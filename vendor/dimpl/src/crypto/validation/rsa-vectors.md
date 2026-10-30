The RSA certificate is the public SDK test fixture from
`crates/opc-proto-ikev2/tests/data/rsa2048_cert.der`. It is not a trust anchor
or production identity. Its corresponding synthetic test key is already
published at `rsa2048_pkcs8.der` in that directory.

OpenSSL 3.6.5 independently signed the existing `test_data.bin` with that key:

```
openssl dgst -sha256 -sign rsa2048_pkcs8.der -keyform DER \
  -out rsa_sha256.sig test_data.bin
openssl dgst -sha384 -sign rsa2048_pkcs8.der -keyform DER \
  -out rsa_sha384.sig test_data.bin
openssl dgst -sha256 -sign rsa2048_pkcs8.der -keyform DER \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
  -out rsa_pss_sha256.sig test_data.bin
openssl dgst -sha384 -sign rsa2048_pkcs8.der -keyform DER \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
  -out rsa_pss_sha384.sig test_data.bin
```

PSS salts are randomized; regeneration yields different valid signatures.
Provider admission checks both PKCS#1 and PSS. Unit tests reject changed
transcripts, corrupted signatures, wrong hashes/padding, EC certificates,
and PSS-constrained SPKI keys. Reverse-direction signing is checked with
OpenSSL, including its digest-length PSS salt requirement.
