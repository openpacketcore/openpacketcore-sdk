//! Execute independently authored custody schedules without key-byte access.
use super::{octets, profile, reference, Inputs};
use opc_n3iwf_fixtures::FixtureCatalog;
use opc_proto_ikev2::protocol_key::{
    Ikev2ProtocolKeyAssociation, Ikev2ProtocolKeyAuth, Ikev2ProtocolKeyError,
    Ikev2ProtocolKeyHandle, Ikev2ProtocolKeyOperation, Ikev2ProtocolKeyPurpose,
};
use opc_proto_ikev2::{Ikev2AuthenticationPayload, Ikev2IkeAuthPeer};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::{pending, Future},
    num::NonZeroU64,
    sync::Barrier,
    task::{Context, Poll, Waker},
};
use zeroize::Zeroizing;

fn number(value: &Value, name: &str) -> u64 {
    value[name].as_u64().expect("bounded schedule number")
}
fn id(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).expect("nonzero local test identifier")
}
fn code<T>(result: Result<T, Ikev2ProtocolKeyError>) -> String {
    result.map_or_else(|error| error.to_string(), |_| "ok".to_owned())
}

struct Answers {
    initiator: Inputs,
    responder: Inputs,
    initiator_wire: Vec<u8>,
    responder_wire: Vec<u8>,
}
impl Answers {
    fn new() -> Self {
        let reference = reference();
        let cases = reference["cases"]
            .as_array()
            .expect("independent AUTH cases");
        let find = |name| cases.iter().find(|c| c["name"] == name).expect("AUTH case");
        let left = find("auth-initiator-known-answer");
        let right = find("auth-responder-known-answer");
        Self {
            initiator: Inputs::new(&left["inputs"]),
            responder: Inputs::new(&right["inputs"]),
            initiator_wire: octets(&left["wire_hex"]),
            responder_wire: octets(&right["wire_hex"]),
        }
    }
    fn consume(
        &self,
        key: &Ikev2ProtocolKeyHandle,
        operation: &Ikev2ProtocolKeyOperation,
        step: &Value,
    ) -> Result<(), Ikev2ProtocolKeyError> {
        let mut initiator = self.initiator.signed();
        if step["wrong_direction"] == true {
            initiator.peer = Ikev2IkeAuthPeer::Responder;
        }
        let limit = step["max_input_bytes"].as_u64().unwrap_or(4096);
        assert!(limit <= 4096, "schedule transcript limit");
        let auth = key.consume_ike_auth(
            operation,
            &self.initiator.material,
            initiator,
            self.responder.signed(),
            limit as usize,
        )?;
        self.verify(&auth);
        Ok(())
    }
    fn verify(&self, auth: &Ikev2ProtocolKeyAuth) {
        assert!(format!("{auth:?}") == "Ikev2ProtocolKeyAuth(<redacted>)");
        for (peer, wire) in [
            (Ikev2IkeAuthPeer::Initiator, &self.initiator_wire),
            (Ikev2IkeAuthPeer::Responder, &self.responder_wire),
        ] {
            assert!(
                auth.authentication_data(peer) == &wire[4..],
                "custody output changed from independent AUTH answer"
            );
            let payload = Ikev2AuthenticationPayload::decode_body(wire).expect("AUTH body");
            auth.verify(peer, &payload).expect("independent AUTH match");
        }
    }
}

struct Schedule {
    owners: BTreeMap<u64, Ikev2ProtocolKeyAssociation>,
    operations: BTreeMap<u64, Ikev2ProtocolKeyOperation>,
    keys: BTreeMap<u64, Ikev2ProtocolKeyHandle>,
    answers: Answers,
}
impl Schedule {
    fn new(generation: u64) -> Self {
        Self {
            owners: [(0, Ikev2ProtocolKeyAssociation::new(id(generation)))].into(),
            operations: BTreeMap::new(),
            keys: BTreeMap::new(),
            answers: Answers::new(),
        }
    }
    fn execute(&mut self, step: &Value) -> Result<(), Ikev2ProtocolKeyError> {
        match step["action"].as_str().expect("schedule action") {
            "new-owner" => {
                let owner = Ikev2ProtocolKeyAssociation::new(id(number(step, "generation")));
                assert!(format!("{owner:?}") == "Ikev2ProtocolKeyAssociation(<redacted>)");
                assert!(self.owners.insert(number(step, "owner"), owner).is_none());
            }
            "begin" => {
                let operation = self.owners[&number(step, "owner")].begin_ike_auth(
                    id(number(step, "generation")),
                    id(number(step, "operation")),
                    profile(),
                )?;
                assert!(format!("{operation:?}") == "Ikev2ProtocolKeyOperation(<redacted>)");
                assert!(self
                    .operations
                    .insert(number(step, "slot"), operation)
                    .is_none());
            }
            "import" => {
                let length = number(step, "length");
                assert!(length <= 4096, "synthetic import bound");
                let purpose = match step["purpose"].as_str().expect("purpose") {
                    "n3iwf" => Ikev2ProtocolKeyPurpose::N3iwfMsk,
                    "unsupported" => Ikev2ProtocolKeyPurpose::Unsupported,
                    _ => panic!("unsupported test recipe"),
                };
                let key = self.operations[&number(step, "slot")]
                    .import(purpose, Zeroizing::new(vec![0; length as usize]))?;
                assert!(format!("{key:?}") == "Ikev2ProtocolKeyHandle(<redacted>)");
                assert!(self.keys.insert(number(step, "key"), key).is_none());
            }
            "consume" => self.answers.consume(
                &self.keys[&number(step, "key")],
                &self.operations[&number(step, "slot")],
                step,
            )?,
            "concurrent-consume" => {
                let key = &self.keys[&number(step, "key")];
                let operation = &self.operations[&number(step, "slot")];
                let barrier = Barrier::new(2);
                let answers = &self.answers;
                let mut results = std::thread::scope(|scope| {
                    let run = || {
                        barrier.wait();
                        code(answers.consume(key, operation, step))
                    };
                    let left = scope.spawn(run);
                    let right = scope.spawn(run);
                    vec![
                        left.join().expect("consume worker"),
                        right.join().expect("consume worker"),
                    ]
                });
                results.sort();
                let expected: Vec<_> = step["outcomes"]
                    .as_array()
                    .expect("two outcomes")
                    .iter()
                    .map(|s| s.as_str().expect("bounded result"))
                    .collect();
                assert_eq!(results, expected, "atomic single consumption");
            }
            "replace" => self.owners[&number(step, "owner")]
                .replace_generation(id(number(step, "current")), id(number(step, "replacement")))?,
            "cancel" => self.operations[&number(step, "slot")].cancel(),
            "release" => self.owners[&number(step, "owner")].release(),
            "drop-owner" => drop(self.owners.remove(&number(step, "owner")).expect("owner")),
            "drop-operation" => drop(
                self.operations
                    .remove(&number(step, "slot"))
                    .expect("operation"),
            ),
            "drop-key" => drop(self.keys.remove(&number(step, "key")).expect("key")),
            "cancel-future" => {
                let operation = self
                    .operations
                    .remove(&number(step, "slot"))
                    .expect("operation");
                let mut future = Box::pin(async move {
                    let _owned_operation = operation;
                    pending::<()>().await;
                });
                let mut context = Context::from_waker(Waker::noop());
                assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
                drop(future);
            }
            _ => panic!("unknown custody schedule action"),
        }
        Ok(())
    }
}

#[test]
fn every_custody_schedule_executes_the_public_sdk_and_independent_auth_answers() {
    let catalog = FixtureCatalog::load_subset_from(&FixtureCatalog::fixture_root(), "protocol-key")
        .expect("custody catalog");
    let mut seen = BTreeSet::new();
    for (manifest, wire) in catalog
        .manifests()
        .filter(|(m, _)| m.validation_scope == "protocol-key-lifecycle")
    {
        let case: Value = serde_json::from_slice(wire).expect("bounded schedule record");
        assert!(
            case["name"] == manifest.context["source_vector"]["case"],
            "scenario identity"
        );
        assert!(seen.insert(manifest.sdk_fixture_id.clone()));
        let steps = case["steps"].as_array().expect("schedule steps");
        assert!(
            !steps.is_empty() && steps.len() <= 16,
            "schedule action bound"
        );
        let mut schedule = Schedule::new(number(&case, "initial_generation"));
        for step in steps {
            let expected = step["expect"].as_str().expect("bounded expected result");
            let result = code(schedule.execute(step));
            assert_eq!(result, expected, "custody schedule result");
        }
    }
    assert_eq!(
        seen.len(),
        25,
        "complete independently authored schedule inventory"
    );
}
