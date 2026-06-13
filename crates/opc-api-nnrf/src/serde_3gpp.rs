//! TS 29.510 / TS 29.571 object-form serde wrappers for 3GPP identifier types.
//!
//! `opc_types::PlmnId` and `opc_types::Snssai` serialize as compact
//! OpenPacketCore strings, which is convenient internally but is NOT the wire
//! shape a conformant NRF peer expects. TS 29.571 models a PLMN ID as the JSON
//! object `{ "mcc": "...", "mnc": "..." }` and an S-NSSAI as
//! `{ "sst": <int>, "sd": "<6 hex>"? }`. These newtypes carry the same values
//! but (de)serialize in that standard object form, so the generated NNRF types
//! interoperate with real peers. `serde` applies the element serde through
//! `Vec` and `Option`, so the generator only needs to reference these types.

use opc_types::{PlmnId, Snssai};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `PlmnId` that (de)serializes as the TS 29.571 `{ "mcc", "mnc" }` object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NnrfPlmnId(pub PlmnId);

#[derive(Serialize, Deserialize)]
struct PlmnIdRepr {
    mcc: String,
    mnc: String,
}

impl Serialize for NnrfPlmnId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        PlmnIdRepr {
            mcc: self.0.mcc().to_string(),
            mnc: self.0.mnc().to_string(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NnrfPlmnId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = PlmnIdRepr::deserialize(deserializer)?;
        PlmnId::new(repr.mcc, repr.mnc)
            .map(NnrfPlmnId)
            .map_err(serde::de::Error::custom)
    }
}

impl From<PlmnId> for NnrfPlmnId {
    fn from(p: PlmnId) -> Self {
        Self(p)
    }
}

impl From<NnrfPlmnId> for PlmnId {
    fn from(n: NnrfPlmnId) -> Self {
        n.0
    }
}

/// `Snssai` that (de)serializes as the TS 29.571 `{ "sst", "sd"? }` object.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NnrfSnssai(pub Snssai);

#[derive(Serialize, Deserialize)]
struct SnssaiRepr {
    sst: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sd: Option<String>,
}

impl Serialize for NnrfSnssai {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        SnssaiRepr {
            sst: self.0.sst(),
            sd: self.0.sd().map(str::to_string),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NnrfSnssai {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = SnssaiRepr::deserialize(deserializer)?;
        Snssai::new(repr.sst, repr.sd)
            .map(NnrfSnssai)
            .map_err(serde::de::Error::custom)
    }
}

impl From<Snssai> for NnrfSnssai {
    fn from(s: Snssai) -> Self {
        Self(s)
    }
}

impl From<NnrfSnssai> for Snssai {
    fn from(n: NnrfSnssai) -> Self {
        n.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plmn_id_round_trips_ts29571_object_form() {
        let json = r#"{"mcc":"001","mnc":"01"}"#;
        let plmn: NnrfPlmnId = serde_json::from_str(json).unwrap();
        assert_eq!(plmn.0.mcc(), "001");
        assert_eq!(plmn.0.mnc(), "01");
        assert_eq!(serde_json::to_string(&plmn).unwrap(), json);
    }

    #[test]
    fn snssai_round_trips_ts29571_object_form() {
        let json = r#"{"sst":1,"sd":"000001"}"#;
        let snssai: NnrfSnssai = serde_json::from_str(json).unwrap();
        assert_eq!(snssai.0.sst(), 1);
        assert_eq!(snssai.0.sd(), Some("000001"));
        assert_eq!(serde_json::to_string(&snssai).unwrap(), json);
    }

    #[test]
    fn snssai_without_sd_omits_the_field() {
        let json = r#"{"sst":2}"#;
        let snssai: NnrfSnssai = serde_json::from_str(json).unwrap();
        assert_eq!(snssai.0.sst(), 2);
        assert_eq!(snssai.0.sd(), None);
        assert_eq!(serde_json::to_string(&snssai).unwrap(), json);
    }
}
