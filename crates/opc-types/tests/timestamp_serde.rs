use opc_types::Timestamp;
use serde::{Deserialize, Deserializer};
use std::fmt::Write;
use std::str::FromStr;
use time::{format_description::well_known::Rfc3339, Date, Month, UtcOffset};

#[derive(Debug, PartialEq)]
struct OriginalTimestamp(Timestamp);

impl<'de> Deserialize<'de> for OriginalTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Timestamp::from_str(&value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

#[test]
fn timestamp_preserves_original_rfc3339_bytes_at_precision_and_calendar_boundaries() {
    for year in [0, 1, 99, 999, 1900, 1969, 1970, 2000, 2026, 9999] {
        for month in [Month::January, Month::February, Month::December] {
            for day in [1, 28] {
                for (hour, minute, second) in [(0, 0, 0), (23, 59, 59)] {
                    for nanos in [
                        0,
                        1,
                        10,
                        100,
                        1_000,
                        10_000,
                        100_000,
                        1_000_000,
                        10_000_000,
                        100_000_000,
                        123_456_789,
                        999_999_999,
                    ] {
                        let value = Date::from_calendar_date(year, month, day)
                            .unwrap()
                            .with_hms_nano(hour, minute, second, nanos)
                            .unwrap()
                            .assume_utc();
                        let expected = value.format(&Rfc3339).unwrap();
                        let timestamp = Timestamp::from(value);
                        assert_eq!(timestamp.to_string(), expected);
                        let actual = serde_json::to_vec(&timestamp).unwrap();
                        assert_eq!(actual, serde_json::to_vec(&expected).unwrap());
                        assert_eq!(
                            serde_json::from_slice::<Timestamp>(&actual).unwrap(),
                            timestamp
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn timestamp_normalizes_offsets_and_preserves_escaped_and_owned_inputs() {
    for input in [
        "0001-01-01T00:00:00+23:59",
        "1970-01-01T00:00:00-00:00",
        "2000-02-29T23:59:59.000000001-06:30",
        "2026-09-11t10:20:30.123456789z",
        "2026-09-11T10:20:30.123456789123Z",
        "2026-09-11T10:20:30.100000000+05:45",
        "2016-12-31T23:59:60Z",
        "9998-12-31T23:59:59-23:59",
    ] {
        let expected = Timestamp::from_str(input).unwrap();
        assert_eq!(expected.as_offset_datetime().offset(), UtcOffset::UTC);
        let json = serde_json::to_vec(input).unwrap();
        assert_eq!(
            serde_json::from_reader::<_, Timestamp>(&json[..]).unwrap(),
            expected
        );
        let escaped = format!("\"{}\"", input.replace('0', "\\u0030"));
        assert_eq!(
            serde_json::from_str::<Timestamp>(&escaped).unwrap(),
            expected
        );
        for actual in
            [
                Timestamp::deserialize(
                    serde::de::value::StrDeserializer::<serde::de::value::Error>::new(input),
                ),
                Timestamp::deserialize(serde::de::value::StringDeserializer::<
                    serde::de::value::Error,
                >::new(input.to_owned())),
                Timestamp::deserialize(serde::de::value::BytesDeserializer::<
                    serde::de::value::Error,
                >::new(input.as_bytes())),
                Timestamp::deserialize(serde::de::value::BorrowedBytesDeserializer::<
                    serde::de::value::Error,
                >::new(input.as_bytes())),
            ]
        {
            assert_eq!(actual.unwrap(), expected);
        }
        let original = expected.as_offset_datetime().format(&Rfc3339).unwrap();
        assert_eq!(
            serde_json::to_vec(&expected).unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
    }
}

#[test]
fn timestamp_deserialization_matches_original_acceptance_and_complete_value() {
    fn compare(input: &[u8]) {
        let original = serde_json::from_slice::<OriginalTimestamp>(input);
        let actual = serde_json::from_slice::<Timestamp>(input);
        assert_eq!(actual.is_ok(), original.is_ok());
        if let (Ok(actual), Ok(original)) = (actual, original) {
            assert_eq!(actual, original.0);
        }
    }
    for input in [
        b"\"0000-01-01T00:00:00Z\"".as_slice(),
        b"\"2026-09-11T10:20:30.123456789+06:30\"",
        b"\"9999-12-31T23:59:59.999999999Z\"",
    ] {
        for end in 0..=input.len() {
            compare(&input[..end]);
        }
        let mut changed = input.to_vec();
        for index in 0..changed.len() {
            for replacement in 0..=u8::MAX {
                changed[index] = replacement;
                compare(&changed);
            }
            changed[index] = input[index];
        }
    }
    for input in [
        b"null".as_slice(),
        b"true",
        b"1",
        b"[]",
        b"{}",
        b"\"\"",
        b"\"bad\"",
    ] {
        compare(input);
    }
    assert!(Timestamp::deserialize(
        serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(&[0xff])
    )
    .is_err());
}

#[test]
fn timestamp_outside_rfc3339_range_returns_a_serialization_error() {
    let timestamp = Timestamp::from(
        Date::from_calendar_date(-1, Month::January, 1)
            .unwrap()
            .midnight()
            .assume_utc(),
    );
    assert!(timestamp.as_offset_datetime().format(&Rfc3339).is_err());
    assert!(write!(&mut String::new(), "{timestamp}").is_err());
    assert!(serde_json::to_vec(&timestamp).is_err());
}
