//! Shared SBI testkit for mock NRF, mock producers, and token fixtures.
//!
//! Downstream NF crates can use these types to write deterministic SBI
//! integration tests without standing up a real NRF.

pub mod fixtures;
pub mod mock_server;
pub mod nrf;

pub use fixtures::{
    generate_test_token, generate_test_token_with_nbf_offset, test_private_key_pem,
    FailureFixtures, MockJwksResolver, TokenFixtures, TEST_EXPONENT_E, TEST_KID, TEST_MODULUS_N,
};
pub use mock_server::{MockConsumer, MockProducer, RecordedRequest};
pub use nrf::{MockNrf, MockNrfError, TokenFixture};
