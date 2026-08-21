use std::convert::Infallible;

use opc_session_store::fenced_mutation_roster::{
    FencedMutationRosterAdoption, FencedMutationRosterDescriptor, FencedMutationRosterDisposition,
    FencedMutationRosterOrdinal,
};
use opc_session_store::{
    FenceToken, FencedMutationRosterAdmission, FencedMutationRosterFenceIntent,
    FencedMutationRosterMember, FencedMutationRosterMemberExecutionContext,
    FencedMutationRosterMemberExecutor, FencedMutationRosterMemberProvider,
    FencedMutationRosterMembers, FencedMutationRosterOperationId,
    FencedMutationRosterProtectedPlan, FencedMutationRosterProtectedResult,
    FencedMutationRosterProviderOutcome, FencedMutationRosterScope, FencedMutationRosterTerminal,
    Generation, OwnerId,
};

struct ExternalProvider;

impl FencedMutationRosterMemberProvider for ExternalProvider {
    type Error = Infallible;

    fn execute_member(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterProviderOutcome, Self::Error> {
        assert_eq!(context.ordinal().get(), 0);
        assert_eq!(context.current_fence(), FenceToken::new(8));
        assert_eq!(context.member().expected_version(), 3);
        Ok(FencedMutationRosterProviderOutcome::AppliedExecuted)
    }

    fn member_status(
        &self,
        _context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterProviderOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderOutcome::AppliedAdopted)
    }

    fn adopt_member(
        &self,
        _context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterProviderOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderOutcome::NotAppliedReconciled)
    }
}

fn admission() -> FencedMutationRosterAdmission {
    let member = FencedMutationRosterMember::new(
        FencedMutationRosterOrdinal::new(0).expect("member ordinal"),
        [0x11; 16],
        FencedMutationRosterDescriptor::new(vec![0x22]).expect("member descriptor"),
        2,
        3,
        FencedMutationRosterDisposition::Pending,
        FencedMutationRosterAdoption::Unreconciled,
    )
    .expect("member");
    FencedMutationRosterAdmission::new(
        7,
        FencedMutationRosterOperationId::new([0x33; 16]).expect("operation ID"),
        FencedMutationRosterScope::from_digest([0x44; 32]),
        FencedMutationRosterFenceIntent::new(
            OwnerId::new("proof-issuer-test-owner").expect("owner"),
            FenceToken::new(8),
        ),
        Generation::new(9),
        FencedMutationRosterMembers::new([member]).expect("members"),
        FencedMutationRosterProtectedPlan::new(vec![0x55].into_boxed_slice())
            .expect("protected plan"),
    )
    .expect("admission")
    .with_terminal_result(
        FencedMutationRosterProtectedResult::new(vec![0x66].into_boxed_slice())
            .expect("terminal result"),
    )
    .expect("admission terminal result")
}

#[test]
fn external_provider_receives_sdk_validated_context_and_gets_an_opaque_bound_proof() {
    let admission = admission();
    let proof = FencedMutationRosterMemberExecutor::new()
        .execute_member(
            &ExternalProvider,
            &admission,
            FencedMutationRosterOrdinal::new(0).expect("member ordinal"),
            FenceToken::new(8),
        )
        .expect("SDK-issued proof");
    let terminal = FencedMutationRosterTerminal::from_member_proofs(
        &admission,
        &[proof],
        FenceToken::new(8),
        vec![0x77],
        admission.terminal_result().as_bytes().to_vec(),
    )
    .expect("proof-derived terminal");

    assert_eq!(
        terminal.protected_result(),
        admission.terminal_result().as_bytes(),
        "the terminal result remains frozen by the admitted request"
    );
    terminal
        .validate_for_admission(&admission)
        .expect("terminal retains exact admission binding");
}
