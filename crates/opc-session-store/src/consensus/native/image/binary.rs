//! A postcard row is already enclosed by a bounded length frame. Limit nested
//! work before serde visits it too: postcard itself has no recursion limit and
//! its collection sizes must not become trusted allocation hints.

use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::io::{self, Write};

const MAX_DEPTH: usize = 128;

enum Destination<'a> {
    Count,
    Writer(&'a mut dyn Write),
    Compare(&'a [u8]),
}

struct CanonicalSink<'a, 'error> {
    destination: Destination<'a>,
    position: usize,
    maximum: usize,
    error: &'error mut Option<io::Error>,
    buffer: [u8; 256],
    used: usize,
}

// Postcard emits scalar fields and byte-sequence elements separately. Pass
// bounded chunks to the generation's counting/hash writer without retaining
// another encoded row. The final partial chunk must succeed before this
// serializer can report success; the enclosing row and generation admission
// still precede publication.
fn write_fragment(
    writer: &mut dyn Write,
    buffer: &mut [u8; 256],
    used: &mut usize,
    mut bytes: &[u8],
) -> io::Result<()> {
    if *used != 0 {
        let count = bytes.len().min(buffer.len() - *used);
        buffer[*used..*used + count].copy_from_slice(&bytes[..count]);
        *used += count;
        bytes = &bytes[count..];
        if *used != buffer.len() {
            return Ok(());
        }
        writer.write_all(buffer)?;
        *used = 0;
    }
    if bytes.len() >= buffer.len() {
        writer.write_all(bytes)?;
    } else {
        buffer[..bytes.len()].copy_from_slice(bytes);
        *used = bytes.len();
    }
    Ok(())
}

impl postcard::ser_flavors::Flavor for CanonicalSink<'_, '_> {
    type Output = usize;

    fn try_push(&mut self, byte: u8) -> postcard::Result<()> {
        self.try_extend(&[byte])
    }

    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        let end = self
            .position
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        match &mut self.destination {
            Destination::Count => {}
            Destination::Writer(writer) => {
                if let Err(error) = write_fragment(*writer, &mut self.buffer, &mut self.used, bytes)
                {
                    *self.error = Some(error);
                    return Err(postcard::Error::SerializeBufferFull);
                }
            }
            Destination::Compare(expected) => {
                if expected.get(self.position..end) != Some(bytes) {
                    return Err(postcard::Error::SerializeBufferFull);
                }
            }
        }
        self.position = end;
        Ok(())
    }

    fn finalize(mut self) -> postcard::Result<usize> {
        let written = match &mut self.destination {
            Destination::Writer(writer) if self.used != 0 => {
                writer.write_all(&self.buffer[..self.used])
            }
            _ => Ok(()),
        };
        if let Err(error) = written {
            *self.error = Some(error);
            return Err(postcard::Error::SerializeBufferFull);
        }
        if matches!(self.destination,Destination::Compare(bytes) if bytes.len() != self.position) {
            return Err(postcard::Error::SerializeBufferFull);
        }
        Ok(self.position)
    }
}

fn serialize(
    value: &(impl Serialize + ?Sized),
    destination: Destination<'_>,
    maximum: usize,
) -> io::Result<usize> {
    let mut error = None;
    let result = postcard::serialize_with_flavor(
        value,
        CanonicalSink {
            destination,
            position: 0,
            maximum,
            error: &mut error,
            buffer: [0; 256],
            used: 0,
        },
    );
    if let Some(error) = error {
        return Err(error);
    }
    result.map_err(|_| super::invalid("native binary canonical encoding differs or exceeds bound"))
}

// The same postcard serializer now counts, writes and compares without a
// second complete encoded allocation. No schema, depth, work, collection or
// canonical acceptance rule changes. All callers still own their allocation
// reservations and must keep decoded values inside the appropriate lifetime.
pub(in crate::consensus::native) fn encoded_len(
    value: &(impl Serialize + ?Sized),
    maximum: usize,
) -> io::Result<usize> {
    serialize(value, Destination::Count, maximum)
}

pub(in crate::consensus::native) fn write_to(
    value: &(impl Serialize + ?Sized),
    writer: &mut dyn Write,
    maximum: usize,
) -> io::Result<usize> {
    serialize(value, Destination::Writer(writer), maximum)
}

pub(in crate::consensus::native) fn compare(
    value: &(impl Serialize + ?Sized),
    bytes: &[u8],
) -> io::Result<()> {
    serialize(value, Destination::Compare(bytes), bytes.len()).map(|_| ())
}

struct Budget {
    values: Cell<usize>,
    collection: usize,
}

impl Budget {
    fn enter<E: de::Error>(&self, depth: usize) -> Result<(), E> {
        if depth > MAX_DEPTH {
            return Err(E::custom("native binary nesting exceeds bound"));
        }
        let remaining = self
            .values
            .get()
            .checked_sub(1)
            .ok_or_else(|| E::custom("native binary work exceeds frame bound"))?;
        self.values.set(remaining);
        Ok(())
    }

    fn collection<E: de::Error>(&self, length: Option<usize>) -> Result<(), E> {
        if length.is_some_and(|length| length > self.collection) {
            return Err(E::custom("native binary collection exceeds frame bound"));
        }
        Ok(())
    }
}

pub(in crate::consensus::native) fn decode<T: de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> std::io::Result<T> {
    let budget = Budget {
        values: Cell::new(bytes.len().saturating_mul(8).saturating_add(128)),
        collection: bytes.len(),
    };
    let mut decoder = postcard::Deserializer::from_bytes(bytes);
    let value = <T as Deserialize>::deserialize(Bounded {
        inner: &mut decoder,
        budget: &budget,
        depth: 0,
    })
    .map_err(|_| super::invalid("native binary row invalid"))?;
    if !decoder
        .finalize()
        .map_err(|_| super::invalid("native binary row decoder failed"))?
        .is_empty()
    {
        return Err(super::invalid("native binary row contains trailing bytes"));
    }
    // Exact canonical bytes bind the current schema, including varints and
    // custom scalar constructors which could otherwise normalize input.
    compare(&value, bytes)?;
    Ok(value)
}

struct Bounded<'a, D> {
    inner: D,
    budget: &'a Budget,
    depth: usize,
}
struct CheckedVisitor<'a, V> {
    inner: V,
    budget: &'a Budget,
    depth: usize,
}
struct Seed<'a, S> {
    inner: S,
    budget: &'a Budget,
    depth: usize,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Bounded {
            inner: decoder,
            budget: self.budget,
            depth: self.depth,
        })
    }
}

macro_rules! forward {
    ($($method:ident),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.budget.enter(self.depth)?;
            self.inner.$method(CheckedVisitor { inner:visitor, budget:self.budget, depth:self.depth })
        }
    )*};
}

impl<'de, D: de::Deserializer<'de>> de::Deserializer<'de> for Bounded<'_, D> {
    type Error = D::Error;
    forward!(
        deserialize_any,
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_option,
        deserialize_unit,
        deserialize_seq,
        deserialize_map,
        deserialize_identifier,
        deserialize_ignored_any
    );

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.budget.enter(self.depth)?;
        self.inner.deserialize_unit_struct(
            name,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.budget.enter(self.depth)?;
        self.inner.deserialize_newtype_struct(
            name,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.budget.enter(self.depth)?;
        self.inner.deserialize_tuple(
            length,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.budget.enter(self.depth)?;
        self.inner.deserialize_tuple_struct(
            name,
            length,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.budget.enter(self.depth)?;
        self.inner.deserialize_struct(
            name,
            fields,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.budget.enter(self.depth)?;
        self.inner.deserialize_enum(
            name,
            variants,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

macro_rules! scalar {
    ($($method:ident : $ty:ty),* $(,)?) => {$(
        fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> { self.inner.$method(value) }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for CheckedVisitor<'_, V> {
    type Value = V::Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.expecting(formatter)
    }
    scalar!(visit_bool:bool, visit_i8:i8, visit_i16:i16, visit_i32:i32, visit_i64:i64, visit_i128:i128,
        visit_u8:u8, visit_u16:u16, visit_u32:u32, visit_u64:u64, visit_u128:u128,
        visit_f32:f32, visit_f64:f64, visit_char:char, visit_str:&str, visit_borrowed_str:&'de str,
        visit_string:String, visit_bytes:&[u8], visit_borrowed_bytes:&'de [u8], visit_byte_buf:Vec<u8>);
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_some<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Bounded {
            inner: decoder,
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
    fn visit_newtype_struct<D: de::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Bounded {
            inner: decoder,
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.budget.collection(access.size_hint())?;
        self.inner.visit_seq(Bounded {
            inner: access,
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.budget.collection(access.size_hint())?;
        self.inner.visit_map(Bounded {
            inner: access,
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
    fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Bounded {
            inner: access,
            budget: self.budget,
            depth: self.depth + 1,
        })
    }
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Bounded<'_, A> {
    type Error = A::Error;
    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, Self::Error> {
        self.inner.next_element_seed(Seed {
            inner: seed,
            budget: self.budget,
            depth: self.depth,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        None
    }
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Bounded<'_, A> {
    type Error = A::Error;
    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, Self::Error> {
        self.inner.next_key_seed(Seed {
            inner: seed,
            budget: self.budget,
            depth: self.depth,
        })
    }
    fn next_value_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<S::Value, Self::Error> {
        self.inner.next_value_seed(Seed {
            inner: seed,
            budget: self.budget,
            depth: self.depth,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        None
    }
}

impl<'a, 'de, A: EnumAccess<'de>> EnumAccess<'de> for Bounded<'a, A> {
    type Error = A::Error;
    type Variant = Bounded<'a, A::Variant>;
    fn variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Self::Variant), Self::Error> {
        let (value, variant) = self.inner.variant_seed(Seed {
            inner: seed,
            budget: self.budget,
            depth: self.depth,
        })?;
        Ok((
            value,
            Bounded {
                inner: variant,
                budget: self.budget,
                depth: self.depth,
            },
        ))
    }
}

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Bounded<'_, A> {
    type Error = A::Error;
    fn unit_variant(self) -> Result<(), Self::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<S: DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<S::Value, Self::Error> {
        self.inner.newtype_variant_seed(Seed {
            inner: seed,
            budget: self.budget,
            depth: self.depth,
        })
    }
    fn tuple_variant<V: Visitor<'de>>(
        self,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.tuple_variant(
            length,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.struct_variant(
            fields,
            CheckedVisitor {
                inner: visitor,
                budget: self.budget,
                depth: self.depth,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    enum Tree {
        Leaf,
        Branch(Box<Tree>),
    }

    #[test]
    fn native_binary_key_row_coalesces_output_without_an_encoded_allocation() {
        let (storage, request, _) = crate::consensus::native::changes::tests::fixture();
        let key = &request.mutation().record().unwrap().key;
        let row = storage.business.keys.get(key).unwrap();
        let value = (key, Some(row));
        let expected = postcard::to_allocvec(&value).unwrap();
        struct ObservedOutput<'a> {
            remaining: &'a [u8],
            calls: usize,
        }
        impl Write for ObservedOutput<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(!bytes.is_empty());
                assert!(self.remaining.starts_with(bytes));
                self.remaining = &self.remaining[bytes.len()..];
                self.calls += 1;
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut output = ObservedOutput {
            remaining: &expected,
            calls: 0,
        };
        let allocation = allocation_counter::measure(|| {
            assert_eq!(
                write_to(&value, &mut output, expected.len()).unwrap(),
                expected.len()
            );
        });
        assert!(output.remaining.is_empty());
        eprintln!(
            "native_binary_key_row_output encoded_bytes={} writer_calls={} allocations={} allocated_bytes={}",
            expected.len(), output.calls, allocation.count_total, allocation.bytes_total
        );
        assert_eq!(allocation.count_total, 0);
        assert_eq!(allocation.bytes_current, 0);
        assert!(
            output.calls <= expected.len().div_ceil(64) + 1,
            "one native row must amortize tiny field writes before generation hashing"
        );
    }

    #[test]
    fn native_binary_streaming_encoding_matches_postcard_and_preserves_writer_errors() {
        let value = (
            vec![0u8, 1, 127, 128, 255],
            "full string with \"quotes\" and λ",
            Some(65_537u64),
            Tree::Branch(Box::new(Tree::Leaf)),
        );
        let expected = postcard::to_allocvec(&value).unwrap();
        assert_eq!(encoded_len(&value, expected.len()).unwrap(), expected.len());
        assert!(encoded_len(&value, expected.len() - 1).is_err());
        let mut actual = Vec::new();
        assert_eq!(
            write_to(&value, &mut actual, expected.len()).unwrap(),
            expected.len()
        );
        assert_eq!(actual, expected);
        compare(&value, &expected).unwrap();
        for index in 0..expected.len() {
            let mut changed = expected.clone();
            changed[index] ^= 1;
            assert!(compare(&value, &changed).is_err());
        }
        let mut extended = expected.clone();
        extended.push(0);
        assert!(compare(&value, &extended).is_err());
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "writer fixture",
                ))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let error = write_to(&value, &mut FailedWriter, expected.len()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "writer fixture");
    }

    #[test]
    fn native_binary_output_preserves_short_writes_interruptions_and_tail_errors() {
        let value = (
            (0..1_025)
                .map(|index| (index % 256) as u8)
                .collect::<Vec<_>>(),
            "complete final field",
        );
        let expected = postcard::to_allocvec(&value).unwrap();
        struct Output<'a> {
            expected: &'a [u8],
            position: usize,
            step: usize,
            fail_at: usize,
            interrupted: bool,
        }
        impl Write for Output<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.interrupted = !self.interrupted;
                if self.interrupted {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if self.position == self.fail_at {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "exact output fault",
                    ));
                }
                let count = bytes.len().min(self.step).min(self.fail_at - self.position);
                assert_eq!(
                    self.expected
                        .get(self.position..self.position + count)
                        .unwrap(),
                    &bytes[..count]
                );
                self.position += count;
                Ok(count)
            }

            fn flush(&mut self) -> io::Result<()> {
                panic!("row encoding must not flush its caller's output")
            }
        }
        for step in [1, 7, 255, 256, 257, expected.len()] {
            for fail_at in [0, 1, 63, 255, 256, 257, expected.len() - 1, expected.len()] {
                let mut output = Output {
                    expected: &expected,
                    position: 0,
                    step,
                    fail_at,
                    interrupted: false,
                };
                let result = write_to(&value, &mut output, expected.len());
                assert_eq!(output.position, fail_at);
                if fail_at == expected.len() {
                    assert_eq!(result.unwrap(), expected.len());
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                    assert_eq!(error.to_string(), "exact output fault");
                }
            }
        }
    }

    #[test]
    fn native_binary_rejects_noncanonical_and_unbounded_frames() {
        assert_eq!(decode::<u64>(&[0]).unwrap(), 0);
        assert!(decode::<u64>(&[0, 0]).is_err(), "trailing field");
        assert!(decode::<u64>(&[0x80, 0]).is_err(), "overlong scalar");
        assert!(decode::<u64>(&[0x80]).is_err(), "truncated scalar");
        assert!(decode::<Tree>(&[2]).is_err(), "unknown variant");
        assert!(
            decode::<Vec<u8>>(&[0xff, 0xff, 0xff, 0xff, 0x0f]).is_err(),
            "count rejected before allocation"
        );
        let mut deep = vec![1; 200];
        deep.push(0);
        assert!(
            decode::<Tree>(&deep).is_err(),
            "nesting rejected before construction"
        );
        let shallow = [1, 1, 0];
        assert!(matches!(decode::<Tree>(&shallow).unwrap(), Tree::Branch(_)));
        let empty_batch =
            postcard::to_allocvec(&crate::backend::ReplicationOp::Batch { ops: Vec::new() })
                .unwrap();
        assert_eq!(empty_batch.len(), 2);
        let mut nested_operation = Vec::new();
        for _ in 0..200 {
            nested_operation.extend_from_slice(&[empty_batch[0], 1]);
        }
        nested_operation.extend_from_slice(&empty_batch);
        assert!(
            decode::<crate::backend::ReplicationOp>(&nested_operation).is_err(),
            "real notification recursion is bounded on the default stack"
        );
        assert!(
            decode::<std::collections::BTreeMap<u8, Tree>>(&[0xff, 0xff, 0xff, 0xff, 0x0f])
                .is_err(),
            "map count rejected before allocation"
        );
    }
}
