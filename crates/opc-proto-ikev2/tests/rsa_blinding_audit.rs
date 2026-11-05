//! Guard the private-operation boundary: PSS salt randomness alone is not blinding.

const SIGNATURE_SOURCE: &str = include_str!("../src/ike_auth_signature.rs");
const PROVIDER_SOURCE: &str = include_str!("../src/software_crypto.rs");

fn compact_function(name: &str) -> String {
    let start = SIGNATURE_SOURCE.find(&format!("fn {name}(")).unwrap();
    let body = &SIGNATURE_SOURCE[start..];
    let end = body.find("\n}").unwrap();
    body[..end].split_whitespace().collect()
}

#[test]
fn pkcs1_private_operation_uses_os_randomness_for_blinding() {
    let body = compact_function("rsa_pkcs1v15_sha256_sign");
    assert!(
        !body.contains(".sign("),
        "RSA sign() passes no blinding RNG"
    );
    assert!(body.contains(".sign_with_rng(&mutrsa::rand_core::OsRng,"));
}

#[test]
fn every_pss_hash_enables_private_operation_blinding_and_os_randomness() {
    let parameters = compact_function("rsa_pss_parameters");
    for (hash, salt) in [("Sha256", 32), ("Sha384", 48), ("Sha512", 64)] {
        assert!(
            parameters.contains(&format!("Pss::new_blinded_with_salt::<{hash}>({salt})")),
            "{hash} must blind the RSA operation as well as randomize the salt"
        );
    }
    let body = compact_function("rsa_pss_sign");
    assert!(!body.contains(".sign("));
    assert!(body.contains(".sign_with_rng(&mutrsa::rand_core::OsRng,padding,&digest)"));
    assert!(!body.contains("blinded=false"));
}

#[test]
fn rsa_provider_routes_both_schemes_through_the_audited_helpers() {
    let provider: String = PROVIDER_SOURCE.split_whitespace().collect();
    assert!(provider.contains("rsa_pkcs1v15_sha256_sign(private,message)"));
    assert!(provider.contains("rsa_pss_sign(private,self.algorithm,message)"));
    assert!(!provider.contains("rsa::pss::SigningKey"));
}
