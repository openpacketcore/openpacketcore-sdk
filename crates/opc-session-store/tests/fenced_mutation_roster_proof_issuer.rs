use std::convert::Infallible;

use opc_session_store::{
    FencedMutationRosterMemberExecutionContext, FencedMutationRosterMemberProvider,
    FencedMutationRosterProviderOutcome,
};

struct ExternalProvider;

#[async_trait::async_trait]
impl FencedMutationRosterMemberProvider for ExternalProvider {
    type Error = Infallible;

    async fn execute_member(
        &self,
        context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterProviderOutcome, Self::Error> {
        assert_eq!(context.member().expected_generation(), 2);
        assert_eq!(context.member().expected_version(), 3);
        Ok(FencedMutationRosterProviderOutcome::AppliedExecuted)
    }

    async fn member_status(
        &self,
        _context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterProviderOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderOutcome::AppliedAdopted)
    }

    async fn adopt_member(
        &self,
        _context: &FencedMutationRosterMemberExecutionContext<'_>,
    ) -> Result<FencedMutationRosterProviderOutcome, Self::Error> {
        Ok(FencedMutationRosterProviderOutcome::NotAppliedReconciled)
    }
}

#[test]
fn external_provider_contract_is_object_safe_without_a_general_proof_issuer() {
    fn accepts_dynamic_provider(
        _provider: &dyn FencedMutationRosterMemberProvider<Error = Infallible>,
    ) {
    }

    accepts_dynamic_provider(&ExternalProvider);
}
