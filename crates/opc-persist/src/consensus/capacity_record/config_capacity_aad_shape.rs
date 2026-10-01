//! Structural admission before the general internally tagged AAD decoder.
//!
//! The bounded configuration schema has a fixed number of scalar fields.
//! Reject containers and unknown fields before serde can retain an arbitrary
//! Content tree. This pass owns no field strings; the original decoder still
//! establishes canonical encoding, domain validity and record binding.

use std::fmt;

use opc_crypto::CONFIG_CAPACITY_V1_AAD_BYTES;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

use crate::PersistError;

struct Text<const MAX: usize>;

impl<'de, const MAX: usize> Deserialize<'de> for Text<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for TextVisitor<MAX> {
            type Value = Text<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded scalar configuration metadata")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX {
                    return Err(E::custom("configuration metadata exceeds capacity"));
                }
                Ok(Text)
            }
        }
        deserializer.deserialize_str(TextVisitor::<MAX>)
    }
}

struct ConfigOnly;

impl<'de> Deserialize<'de> for ConfigOnly {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ConfigVisitor;
        impl Visitor<'_> for ConfigVisitor {
            type Value = ConfigOnly;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("configuration metadata")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value != "config" {
                    return Err(E::custom("configuration metadata kind mismatch"));
                }
                Ok(ConfigOnly)
            }
        }
        deserializer.deserialize_str(ConfigVisitor)
    }
}

// Underscored fields are deliberately consumed without retaining their value.
// Text permits the existing scalar representation, including escaped Unicode.
// The original decoder remains responsible for UUID/digest/time semantics.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AadShape {
    #[serde(rename = "tenant")]
    _tenant: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "purpose")]
    _purpose: ConfigOnly,
    #[serde(rename = "version")]
    _version: u64,
    #[serde(rename = "key_id")]
    _key_id: Text<512>,
    #[serde(rename = "metadata")]
    _metadata: MetadataShape,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataShape {
    #[serde(rename = "kind")]
    _kind: ConfigOnly,
    #[serde(rename = "tx_id")]
    _tx_id: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "parent_tx_id")]
    _parent_tx_id: Option<Text<CONFIG_CAPACITY_V1_AAD_BYTES>>,
    #[serde(rename = "committed_at")]
    _committed_at: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "principal")]
    _principal: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "schema_digest")]
    _schema_digest: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
    #[serde(rename = "store_kind")]
    _store_kind: Text<CONFIG_CAPACITY_V1_AAD_BYTES>,
}

pub(super) fn preflight(bytes: &[u8]) -> Result<(), PersistError> {
    if bytes.len() > CONFIG_CAPACITY_V1_AAD_BYTES {
        return Err(PersistError::corrupt_blob());
    }
    serde_json::from_slice::<AadShape>(bytes)
        .map(|_| ())
        .map_err(|_| PersistError::corrupt_blob())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_key::{ConfigAad, EnvelopeAad, KeyId};
    use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};

    fn canonical(principal: &str, store: &str, parent: bool, key: &str) -> Vec<u8> {
        let aad = EnvelopeAad::config(
            TenantId::from_static("test"),
            u64::MAX,
            ConfigAad::new(
                "11111111-1111-4111-8111-111111111111"
                    .parse::<TxId>()
                    .unwrap(),
                parent.then(|| "22222222-2222-4222-8222-222222222222".parse().unwrap()),
                "2026-09-22T00:00:00.123456789Z"
                    .parse::<Timestamp>()
                    .unwrap(),
                principal,
                SchemaDigest::from_bytes([0xC1; 32]),
                store,
            )
            .unwrap(),
        );
        opc_key::serialize_bound_aad(&aad, &KeyId::new(key).unwrap()).unwrap()
    }

    #[test]
    fn config_capacity_aad_shape_preserves_supported_canonical_scalars() {
        for parent in [false, true] {
            for (principal, store, key) in [
                ("synthetic", "running", "key"),
                ("synthetic-\"\\é", "store-\"\\é", "key-AZaz09-_.:/"),
            ] {
                let encoded = canonical(principal, store, parent, key);
                let original = opc_key::decode_bound_aad(&encoded).unwrap();
                preflight(&encoded).expect("existing canonical fields remain supported");
                assert_eq!(opc_key::decode_bound_aad(&encoded).unwrap(), original);
            }
        }
        let key = "k".repeat(512);
        let initial = canonical("synthetic", "s", true, &key);
        let store = "s".repeat(CONFIG_CAPACITY_V1_AAD_BYTES - initial.len() + 1);
        let at = canonical("synthetic", &store, true, &key);
        assert_eq!(at.len(), CONFIG_CAPACITY_V1_AAD_BYTES);
        opc_key::decode_bound_aad(&at).expect("original at-limit canonical representation");
        preflight(&at).expect("at-limit AAD shape");
        let over = canonical("synthetic", &(store + "s"), true, &key);
        assert_eq!(over.len(), CONFIG_CAPACITY_V1_AAD_BYTES + 1);
        opc_key::decode_bound_aad(&over).expect("general decoder has no bounded-profile promise");
        assert!(preflight(&over).is_err());
    }

    #[test]
    fn config_capacity_aad_shape_rejects_nested_values_before_general_decoding() {
        let original = canonical("synthetic", "running", true, "key");
        preflight(&original).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        for field in [
            "kind",
            "tx_id",
            "parent_tx_id",
            "committed_at",
            "principal",
            "schema_digest",
            "store_kind",
        ] {
            let old = value["metadata"][field].take();
            value["metadata"][field] = serde_json::json!({"nested": [0]});
            let encoded = serde_json::to_vec(&value).unwrap();
            assert!(
                preflight(&encoded).is_err(),
                "a scalar field cannot retain a Content tree"
            );
            value["metadata"][field] = old;
        }
        value["metadata"]["principal"] =
            serde_json::Value::Array(vec![serde_json::Value::Null; 10_000]);
        let encoded = serde_json::to_vec(&value).unwrap();
        assert!(encoded.len() < CONFIG_CAPACITY_V1_AAD_BYTES);
        assert!(preflight(&encoded).is_err());
        // This is structural rejection evidence, not a measured heap upper bound.
    }

    #[test]
    fn config_capacity_aad_shape_is_not_a_replacement_for_canonical_binding() {
        let original = canonical("synthetic", "running", false, "key");
        let mut padded = original.clone();
        padded.push(b' ');
        preflight(&padded).expect("shape alone is not canonical authentication");
        assert!(opc_key::decode_bound_aad(&padded).is_err());
        for metadata in [false, true] {
            let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
            let object = if metadata {
                &mut value["metadata"]
            } else {
                &mut value
            };
            object["unexpected"] = serde_json::json!({"nested": [0, 1, 2]});
            assert!(preflight(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut trailing = original.clone();
        trailing.extend_from_slice(b"{}");
        assert!(preflight(&trailing).is_err());
        assert!(preflight(b"{\"metadata\":").is_err());
    }
}
