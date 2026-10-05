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
        match self.peek().ok_or(())? {
            b'"' => self.take().map(Json::String),
            b't' | b'f' => self.take().map(Json::Bool),
            b'n' => self.take::<()>().map(|()| Json::Null),
            b'{' => {
                let mut fields = BTreeMap::new();
                self.object(depth, |parser, key| {
                    // Validate even a value overwritten by a duplicate key.
                    fields.insert(key, parser.value(depth + 1)?);
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
                        values.push(self.value(depth + 1)?);
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

#[cfg(test)]
mod tests {
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
