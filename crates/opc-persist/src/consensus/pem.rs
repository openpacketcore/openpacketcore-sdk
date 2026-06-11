use rustls_pki_types::CertificateDer;

pub fn load_certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, std::io::Error> {
    use rustls_pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}
