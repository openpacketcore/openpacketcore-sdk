//! The JSON text contract used by stored principals and audit classification.
//!
//! Object keys are always ordinary keys, duplicates keep their last value, and
//! objects sort by key. Serde handles string escapes and scalar syntax through
//! public typed decoders. Numbers retain the original u64/i64/finite-f64 policy
//! independently of serde_json's optional number and raw-value representations.

use std::collections::BTreeMap;

use serde::{de::DeserializeOwned, de::IgnoredAny, Serialize};

mod number;

// This representation is private to the text projection. It intentionally has
// no Deserialize implementation: a dependency's private map tokens cannot
// select a scalar variant. Only audit classification needs canonical JSON.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub(crate) fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.get(key),
            _ => None,
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }
}

pub(crate) fn parse(input: &str) -> Result<Json, ()> {
    let mut parser = Parser::new(input);
    let value = parser.value(0)?;
    parser.end()?;
    Ok(value)
}

pub(crate) struct Parser<'a> {
    remaining: &'a str,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(input: &'a str) -> Self {
        Self { remaining: input }
    }

    fn peek(&mut self) -> Option<u8> {
        self.remaining = self.remaining.trim_start_matches([' ', '\t', '\r', '\n']);
        self.remaining.as_bytes().first().copied()
    }

    fn punctuation(&mut self, expected: u8) -> Result<(), ()> {
        if self.peek() != Some(expected) {
            return Err(());
        }
        self.remaining = &self.remaining[1..];
        Ok(())
    }

    fn take<T: DeserializeOwned>(&mut self) -> Result<T, ()> {
        let mut stream = serde_json::Deserializer::from_str(self.remaining).into_iter::<T>();
        let value = stream.next().ok_or(())?.map_err(|_| ())?;
        self.remaining = &self.remaining[stream.byte_offset()..];
        Ok(value)
    }

    // Unknown metadata fields historically use IgnoredAny: their numbers are
    // syntax-checked without conversion, and their containers are iterative.
    pub(crate) fn skip(&mut self) -> Result<(), ()> {
        self.take::<IgnoredAny>().map(|_| ())
    }

    pub(crate) fn end(&mut self) -> Result<(), ()> {
        if self.peek().is_none() {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(crate) fn object(
        &mut self,
        depth: usize,
        mut field: impl FnMut(&mut Self, String) -> Result<(), ()>,
    ) -> Result<(), ()> {
        if depth >= 127 {
            return Err(());
        }
        self.punctuation(b'{')?;
        if self.peek() == Some(b'}') {
            return self.punctuation(b'}');
        }
        loop {
            let key = self.take::<String>()?;
            self.punctuation(b':')?;
            field(self, key)?;
            if self.peek() == Some(b'}') {
                return self.punctuation(b'}');
            }
            self.punctuation(b',')?;
        }
    }

    pub(crate) fn value(&mut self, depth: usize) -> Result<Json, ()> {
        self.projected_value(depth, true, true)
    }

    // Reserved principal fields need scalars only. Validate rejected containers
    // with the same number/depth/string rules without constructing their trees.
    pub(crate) fn scalar(&mut self, depth: usize) -> Result<Json, ()> {
        self.projected_value(depth, false, true)
    }

    fn projected_value(
        &mut self,
        depth: usize,
        containers: bool,
        strings: bool,
    ) -> Result<Json, ()> {
        match self.peek().ok_or(())? {
            b'"' if strings => self.take().map(Json::String),
            b'"' => self.take::<DiscardText>().map(|_| Json::Null),
            b't' | b'f' => self.take().map(Json::Bool),
            b'n' => self.take::<()>().map(|()| Json::Null),
            b'{' => {
                let mut fields = BTreeMap::new();
                self.object(depth, |parser, key| {
                    // Validate even a value overwritten by a duplicate key.
                    let value = parser.projected_value(depth + 1, containers, containers)?;
                    if containers {
                        fields.insert(key, value);
                    }
                    Ok(())
                })?;
                Ok(Json::Object(fields))
            }
            b'[' => {
                if depth >= 127 {
                    return Err(());
                }
                self.punctuation(b'[')?;
                let mut values = Vec::new();
                if self.peek() != Some(b']') {
                    loop {
                        let value = self.projected_value(depth + 1, containers, containers)?;
                        if containers {
                            values.push(value);
                        }
                        if self.peek() == Some(b']') {
                            break;
                        }
                        self.punctuation(b',')?;
                    }
                }
                self.punctuation(b']')?;
                Ok(Json::Array(values))
            }
            b'-' | b'0'..=b'9' => {
                let original = self.remaining;
                // IgnoredAny verifies the JSON number grammar without the
                // optional arbitrary_precision or float_roundtrip conversions.
                self.skip()?;
                number::parse(&original[..original.len() - self.remaining.len()])
            }
            _ => Err(()),
        }
    }
}

// IgnoredAny has a more permissive string validation path. Use deserialize_str
// so unpaired surrogates and invalid escapes keep the existing fallback.
struct DiscardText;
impl<'de> serde::Deserialize<'de> for DiscardText {
    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        struct TextVisitor;
        impl serde::de::Visitor<'_> for TextVisitor {
            type Value = DiscardText;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON text")
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<DiscardText, E> {
                Ok(DiscardText)
            }
        }
        input.deserialize_str(TextVisitor)
    }
}

pub(crate) fn tenant(input: &str) -> Result<Option<String>, ()> {
    let mut parser = Parser::new(input);
    let mut tenant = None;
    parser.object(0, |parser, key| {
        let value = parser.projected_value(1, false, key == "tenant")?;
        if key == "tenant" {
            tenant = match value {
                Json::String(value) => Some(value),
                _ => None,
            };
        }
        Ok(())
    })?;
    parser.end()?;
    Ok(tenant)
}

#[cfg(test)]
mod tests {
    #[test]
    fn principal_projection_validates_but_does_not_retain_containers() {
        for input in [
            r#"[0,{"secret":[1,2,3]},"text"]"#,
            r#"{"tenant":"t1","nested":{"a":[1,2]}}"#,
        ] {
            let projected = super::Parser::new(input).scalar(0).unwrap();
            match projected {
                super::Json::Array(values) => assert!(values.is_empty()),
                super::Json::Object(values) => assert!(values.is_empty()),
                _ => panic!("container projection"),
            }
        }
        for input in [
            r#"[1e999]"#,
            r#"{"a":1e999,"a":0}"#,
            r#"["\uD800"]"#,
            r#"{"a":"\x"}"#,
            r#"[0,]"#,
        ] {
            assert!(super::parse(input).is_err());
            assert!(super::Parser::new(input).scalar(0).is_err(), "{input}");
        }
        let depth = format!("{}0{}", "[".repeat(127), "]".repeat(127));
        assert!(super::Parser::new(&depth).scalar(0).is_ok());
        let over = format!("[{depth}]");
        assert!(super::Parser::new(&over).scalar(0).is_err());
    }

    #[test]
    fn tenant_projection_preserves_duplicates_and_literal_private_keys() {
        for (input, expected) in [
            (r#"{"tenant":"t1","other":[0,{"a":true}]}"#, Some("t1")),
            (r#"{"tenant":"t1","tenant":null}"#, None),
            (r#"{"tenant":null,"tenant":"t2"}"#, Some("t2")),
            (
                r#"{"$serde_json::private::RawValue":"{\"tenant\":\"t1\"}"}"#,
                None,
            ),
            (r#"{"tenant":{"nested":"t1"}}"#, None),
        ] {
            assert_eq!(super::tenant(input).unwrap().as_deref(), expected);
        }
        assert!(super::tenant(r#"{"tenant":"t1","unused":1e999}"#).is_err());
        assert!(super::tenant(r#"{"tenant":"t1","unused":"\uD800"}"#).is_err());
    }

    #[test]
    fn numbers_keep_the_stored_formats_original_conversion() {
        // Captured with serde_json's default features. In particular the long
        // decimal's original conversion differs from correctly rounded f64.
        for (input, expected) in [
            ("-0", "-0.0"),
            ("9223372036854775807", "9223372036854775807"),
            ("9223372036854775808", "9223372036854775808"),
            ("-9223372036854775808", "-9223372036854775808"),
            ("18446744073709551615", "18446744073709551615"),
            ("1.000000000000000111022302462515654", "1.0000000000000002"),
            ("0.01234567890123456789e-309", "1.2345678901233e-311"),
            ("-1e-999", "-0.0"),
            ("0e999999999999", "0.0"),
            ("1e-999999999999", "0.0"),
        ] {
            let actual = super::parse(input).unwrap();
            assert_eq!(serde_json::to_string(&actual).unwrap(), expected, "{input}");
        }
        for input in [
            "01",
            "1.",
            "1e+",
            "1e309",
            "1e999999999999",
            "1.7976931348623159e308",
        ] {
            assert!(super::parse(input).is_err(), "{input}");
        }
    }

    #[test]
    fn objects_keep_ordinary_keys_sorted_and_last_duplicates() {
        let input = r#"{"z":0,"a":1,"a":2,"$serde_json::private::RawValue":"false","$serde_json::private::Number":"1e999"}"#;
        let expected = r#"{"$serde_json::private::Number":"1e999","$serde_json::private::RawValue":"false","a":2,"z":0}"#;
        assert_eq!(
            serde_json::to_string(&super::parse(input).unwrap()).unwrap(),
            expected
        );
        assert!(super::parse(r#"{"a":1e999,"a":0}"#).is_err());
    }
}
