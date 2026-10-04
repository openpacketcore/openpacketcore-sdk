//! Sort objects without converting typed JSON numbers to floating point.
//!
//! Serde validates the bounded input and supplies each complete value's byte
//! offset. Scalar number tokens stay in that input; no alternate JSON number
//! parser or workspace-wide serde_json feature change is needed.

use std::collections::BTreeMap;

use serde::de::IgnoredAny;

use super::{BoundedWriter, ConfigConsumerError, Write};

pub(super) fn write(input: &[u8], writer: &mut BoundedWriter) -> Result<(), ConfigConsumerError> {
    serde_json::from_slice::<IgnoredAny>(input).map_err(|_| ConfigConsumerError::InvalidState)?;
    write_value(input, writer, 0)
}

fn write_value(
    input: &[u8],
    writer: &mut BoundedWriter,
    depth: usize,
) -> Result<(), ConfigConsumerError> {
    if tokio::time::Instant::now() >= writer.deadline {
        return Err(ConfigConsumerError::Limit);
    }
    let input = input.trim_ascii();
    // IgnoredAny scans containers iteratively. Keep the same nesting ceiling
    // as serde_json::Value's default parser before recursing through them.
    if depth >= 127 && matches!(input.first(), Some(b'{' | b'[')) {
        return Err(ConfigConsumerError::InvalidState);
    }
    match input.first() {
        Some(b'{') => {
            let mut fields = contents(input, b'{', b'}')?;
            let mut sorted = BTreeMap::new();
            while !fields.is_empty() {
                let key: String = serde_json::from_slice(take_value(&mut fields)?)
                    .map_err(|_| ConfigConsumerError::InvalidState)?;
                separator(&mut fields, b':')?;
                sorted.insert(key, take_value(&mut fields)?);
                if !fields.is_empty() {
                    separator(&mut fields, b',')?;
                }
                if tokio::time::Instant::now() >= writer.deadline {
                    return Err(ConfigConsumerError::Limit);
                }
            }
            bytes(writer, b"{")?;
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index != 0 {
                    bytes(writer, b",")?;
                }
                serde_json::to_writer(&mut *writer, &key)
                    .map_err(|_| ConfigConsumerError::Limit)?;
                bytes(writer, b":")?;
                write_value(value, writer, depth + 1)?;
            }
            bytes(writer, b"}")
        }
        Some(b'[') => {
            let mut elements = contents(input, b'[', b']')?;
            bytes(writer, b"[")?;
            while !elements.is_empty() {
                write_value(take_value(&mut elements)?, writer, depth + 1)?;
                if !elements.is_empty() {
                    separator(&mut elements, b',')?;
                    bytes(writer, b",")?;
                }
            }
            bytes(writer, b"]")
        }
        Some(b'"') => {
            let value: String =
                serde_json::from_slice(input).map_err(|_| ConfigConsumerError::InvalidState)?;
            serde_json::to_writer(writer, &value).map_err(|_| ConfigConsumerError::Limit)
        }
        // The complete input has already passed Serde's JSON syntax check.
        // Copy numbers, booleans and null without changing their representation.
        Some(_) => bytes(writer, input),
        None => Err(ConfigConsumerError::InvalidState),
    }
}

fn contents(input: &[u8], open: u8, close: u8) -> Result<&[u8], ConfigConsumerError> {
    input
        .strip_prefix(&[open])
        .and_then(|value| value.strip_suffix(&[close]))
        .map(<[u8]>::trim_ascii)
        .ok_or(ConfigConsumerError::InvalidState)
}

fn take_value<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], ConfigConsumerError> {
    let mut stream = serde_json::Deserializer::from_slice(input).into_iter::<IgnoredAny>();
    stream
        .next()
        .ok_or(ConfigConsumerError::InvalidState)?
        .map_err(|_| ConfigConsumerError::InvalidState)?;
    let (value, remaining) = input.split_at(stream.byte_offset());
    *input = remaining.trim_ascii_start();
    Ok(value)
}

fn separator(input: &mut &[u8], expected: u8) -> Result<(), ConfigConsumerError> {
    *input = input
        .strip_prefix(&[expected])
        .ok_or(ConfigConsumerError::InvalidState)?
        .trim_ascii_start();
    Ok(())
}

fn bytes(writer: &mut BoundedWriter, value: &[u8]) -> Result<(), ConfigConsumerError> {
    writer
        .write_all(value)
        .map_err(|_| ConfigConsumerError::Limit)
}
