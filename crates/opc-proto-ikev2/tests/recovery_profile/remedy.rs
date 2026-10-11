//! Consumer decisions from typed refusals. No refusal is itself effect authority;
//! the selected operation still passes ordinary admission and complete-row CAS.

use super::{
    authority::{EpochOwners, Owner, Transport},
    driver::{self, Cut, Runtime},
    envelope::{Error as KeyError, Provider},
    store::{self, CasStore, Command, CurrentCut, Mutation},
    sync_driver::Start,
};
use opc_proto_ikev2::{
    canonical::Ikev2CanonicalError as Canonical,
    recovery::{
        Ikev2SyncClock as Clock, Ikev2SyncRecoveryPolicy as Policy, Ikev2WindowError as Window,
    },
    Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncMode as Mode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    Drop,
    Wait,
    EvaluateWithinBudget,
    RepairId,
    Delete,
    RefuseEpoch,
    Capacity,
    Resolve,
}

pub fn canonical_failure(error: Canonical) -> Remedy {
    match error {
        Canonical::Unavailable
        | Canonical::LifecycleBlocked
        | Canonical::CapabilityActive
        | Canonical::NotCommitted => Remedy::Wait,
        Canonical::AlreadyReleased | Canonical::AttemptsExhausted => Remedy::RepairId,
        Canonical::InvalidRequest => Remedy::Drop,
        Canonical::InvalidOutput => Remedy::EvaluateWithinBudget,
        Canonical::RegistryFull => Remedy::Capacity,
        Canonical::Invalidated
        | Canonical::BindingMismatch
        | Canonical::FormatUnavailable
        | Canonical::QualificationFailed
        | Canonical::ValidationOptInRequired
        | Canonical::IntegrationReviewRequired => Remedy::RefuseEpoch,
        _ => Remedy::RefuseEpoch,
    }
}
fn window_failure(error: Window) -> Remedy {
    match error {
        Window::Drop => Remedy::Drop,
        Window::UnsupportedShape => Remedy::Delete,
        Window::Canonical(error) => canonical_failure(error),
        Window::RequestOutstanding | Window::SyncBackoff | Window::ReconcileUnavailable => {
            Remedy::Wait
        }
        Window::CommitUncertain => Remedy::Resolve,
        _ => Remedy::RefuseEpoch,
    }
}

impl Runtime {
    pub fn classify_empty(
        &mut self,
        packet: &[u8],
        transport: &mut Transport,
    ) -> Result<Remedy, driver::Error> {
        match self.reply_empty(packet, transport) {
            Ok(_) => Ok(Remedy::Drop),
            Err(driver::Error::Window(error)) => Ok(window_failure(error)),
            Err(error) => Err(error),
        }
    }

    pub fn repair_id(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        policy: Policy,
        clock: Clock,
        cut: Cut,
        transport: &mut Transport,
    ) -> Result<bool, driver::Error> {
        if self.row.mode == Mode::Negotiated {
            self.sync_request(
                provider,
                store,
                Start::New(policy),
                clock,
                clock,
                cut,
                transport,
            )
        } else {
            self.send_scoped_delete(
                provider,
                store,
                policy.operation(),
                clock.unix_ms(),
                cut,
                transport,
            )
        }
    }
    pub fn send_scoped_delete(
        &mut self,
        provider: &Provider,
        store: &mut CasStore,
        operation: u64,
        now: u64,
        cut: Cut,
        transport: &mut Transport,
    ) -> Result<bool, driver::Error> {
        // Check the independent send slot before spending storage or an IV.
        if self
            .row
            .window
            .outbound
            .as_ref()
            .is_some_and(|entry| entry.response().is_none())
        {
            return Err(Window::RequestOutstanding.into());
        }
        self.reserve_control(
            provider,
            store,
            operation,
            1,
            now,
            Cut::Complete,
            Cut::Complete,
        )?;
        if !self.publish_control_request(
            provider,
            store,
            Exchange::Informational,
            crate::canonical_fixtures::delete(),
            |_| {},
            cut,
        )? {
            return Ok(false);
        }
        self.dispatch_replay(transport)
    }
}

/// Positive envelope/history failure without a usable runtime. The owner lock
/// excludes a concurrent executor; exact birth/generation CAS scopes erasure.
pub struct Cleanup {
    owner: Owner,
    cut: CurrentCut,
    pending: Option<Command>,
}
pub enum Recovery {
    Runtime(Box<Runtime>),
    Terminal(Cleanup),
}

pub fn recover(
    provider: &Provider,
    owners: &EpochOwners,
    cut: CurrentCut,
) -> Result<Recovery, driver::Error> {
    let error = match Runtime::restore(provider, owners, &cut, true) {
        Ok(runtime) => return Ok(Recovery::Runtime(Box::new(runtime))),
        Err(error) => error,
    };
    let terminal = matches!(
        error,
        driver::Error::Key(KeyError::KeyLost | KeyError::Integrity | KeyError::Format)
            | driver::Error::Closed
    ) || matches!(error,driver::Error::Window(Window::Canonical(cause)) if canonical_failure(cause)==Remedy::RefuseEpoch);
    if !terminal {
        return Err(error);
    }
    let owner = owners.acquire(&cut)?;
    Ok(Recovery::Terminal(Cleanup {
        owner,
        cut,
        pending: None,
    }))
}
impl Cleanup {
    pub fn commit(&mut self, store: &mut CasStore, cut: Cut) -> Result<bool, driver::Error> {
        self.owner.permit().check()?;
        let fresh = store.refresh_fenced(&self.cut)?;
        let expected = self.cut.row().ok_or(store::Error::CasConflict)?.version;
        if fresh.row().is_none_or(|row| row.version != expected) {
            return Err(store::Error::CasConflict.into());
        }
        let write = Command::new(
            store.next_request(),
            vec![Mutation {
                key: self.cut.key(),
                expected: Some(expected),
                value: None,
            }],
        )?;
        self.pending = Some(write.clone());
        if !driver::dispatch(store, &write, cut)? {
            return Ok(false);
        }
        self.resolve(store)?;
        Ok(true)
    }
    pub fn command(&self) -> &Command {
        self.pending.as_ref().unwrap()
    }
    pub fn resolve(&mut self, store: &CasStore) -> Result<(), driver::Error> {
        self.owner.permit().check()?;
        let write = self.pending.as_ref().ok_or(driver::Error::Unresolved)?;
        let current = store.fenced_read(write, self.cut.key())?;
        if current.row().is_some() {
            return Err(driver::Error::Unresolved);
        }
        self.owner.revoke();
        Ok(())
    }
}
