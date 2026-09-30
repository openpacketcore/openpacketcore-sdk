//! Count calls to the real Vec deserializer's SeqAccess. This wraps the actual
//! shared wire DTO deserializer; it does not replace the payload with a mirror.

use std::cell::Cell;
use std::fmt;

use serde::de::{DeserializeSeed, EnumAccess, Error, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::super::{SessionConsensusWireRequest, SessionConsensusWireResponse};

thread_local! {
    static ELEMENTS: Cell<Option<usize>> = const { Cell::new(None) };
}

pub(crate) struct Count;

impl Count {
    pub(crate) fn start() -> Self {
        ELEMENTS.with(|slot| assert!(slot.replace(Some(0)).is_none()));
        Self
    }

    pub(crate) fn finish(self) -> usize {
        ELEMENTS.with(|slot| slot.take().expect("armed dispatch counter"))
    }
}

impl Drop for Count {
    fn drop(&mut self) {
        ELEMENTS.with(|slot| slot.set(None));
    }
}

fn record_element() {
    ELEMENTS.with(|slot| {
        if let Some(count) = slot.get() {
            slot.set(Some(count + 1));
        }
    });
}

pub(crate) fn deserialize_request<'de, D>(
    deserializer: D,
) -> Result<SessionConsensusWireRequest, D::Error>
where
    D: Deserializer<'de>,
{
    SessionConsensusWireRequest::deserialize(Decoder(deserializer))
}

pub(crate) fn deserialize_response<'de, D>(
    deserializer: D,
) -> Result<SessionConsensusWireResponse, D::Error>
where
    D: Deserializer<'de>,
{
    SessionConsensusWireResponse::deserialize(Decoder(deserializer))
}

struct Decoder<D>(D);

macro_rules! forward {
    ($($method:ident($($arg:ident: $ty:ty),*));* $(;)?) => {
        $(
            fn $method<V>(self, $($arg: $ty,)* visitor: V) -> Result<V::Value, Self::Error>
            where V: Visitor<'de> {
                self.0.$method($($arg,)* Visit { inner: visitor, sequence: false })
            }
        )*
    };
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Decoder<D> {
    type Error = D::Error;

    forward! {
        deserialize_any();
        deserialize_bool();
        deserialize_i8();
        deserialize_i16();
        deserialize_i32();
        deserialize_i64();
        deserialize_i128();
        deserialize_u8();
        deserialize_u16();
        deserialize_u32();
        deserialize_u64();
        deserialize_u128();
        deserialize_f32();
        deserialize_f64();
        deserialize_char();
        deserialize_str();
        deserialize_string();
        deserialize_bytes();
        deserialize_byte_buf();
        deserialize_option();
        deserialize_unit();
        deserialize_unit_struct(name: &'static str);
        deserialize_newtype_struct(name: &'static str);
        deserialize_tuple(len: usize);
        deserialize_tuple_struct(name: &'static str, len: usize);
        deserialize_map();
        deserialize_struct(name: &'static str, fields: &'static [&'static str]);
        deserialize_enum(name: &'static str, variants: &'static [&'static str]);
        deserialize_identifier();
        deserialize_ignored_any();
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_seq(Visit {
            inner: visitor,
            sequence: true,
        })
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

struct Visit<V> {
    inner: V,
    sequence: bool,
}

macro_rules! scalar_visits {
    ($($method:ident($ty:ty));* $(;)?) => {
        $(
            fn $method<E: Error>(self, value: $ty) -> Result<Self::Value, E> {
                self.inner.$method(value)
            }
        )*
    };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Visit<V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.expecting(formatter)
    }

    scalar_visits! {
        visit_bool(bool);
        visit_i8(i8);
        visit_i16(i16);
        visit_i32(i32);
        visit_i64(i64);
        visit_i128(i128);
        visit_u8(u8);
        visit_u16(u16);
        visit_u32(u32);
        visit_u64(u64);
        visit_u128(u128);
        visit_f32(f32);
        visit_f64(f64);
        visit_char(char);
        visit_str(&str);
        visit_borrowed_str(&'de str);
        visit_string(String);
        visit_bytes(&[u8]);
        visit_borrowed_bytes(&'de [u8]);
        visit_byte_buf(Vec<u8>);
    }

    fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }

    fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Decoder(deserializer))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Decoder(deserializer))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_seq(Sequence {
            inner: seq,
            count: self.sequence,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_map(Map(map))
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
        self.inner.visit_enum(Enum(data))
    }
}

struct Seed<S>(S);

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        self.0.deserialize(Decoder(deserializer))
    }
}

struct Sequence<A> {
    inner: A,
    count: bool,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for Sequence<A> {
    type Error = A::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        let result = self.inner.next_element_seed(Seed(seed))?;
        if self.count && result.is_some() {
            record_element();
        }
        Ok(result)
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

struct Map<A>(A);

impl<'de, A: MapAccess<'de>> MapAccess<'de> for Map<A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        self.0.next_key_seed(Seed(seed))
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        self.0.next_value_seed(Seed(seed))
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

struct Enum<A>(A);

impl<'de, A: EnumAccess<'de>> EnumAccess<'de> for Enum<A> {
    type Error = A::Error;
    type Variant = Variant<A::Variant>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let (value, variant) = self.0.variant_seed(Seed(seed))?;
        Ok((value, Variant(variant)))
    }
}

struct Variant<A>(A);

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for Variant<A> {
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), Self::Error> {
        self.0.unit_variant()
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        self.0.newtype_variant_seed(Seed(seed))
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.tuple_variant(
            len,
            Visit {
                inner: visitor,
                sequence: false,
            },
        )
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.struct_variant(
            fields,
            Visit {
                inner: visitor,
                sequence: false,
            },
        )
    }
}
