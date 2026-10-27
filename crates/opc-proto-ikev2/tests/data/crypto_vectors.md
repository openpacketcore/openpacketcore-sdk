# IKE cryptographic reference vectors

All private keys here are public test material, never deployment credentials.

- `rfc8032_ed25519_*` and `ed25519_rfc8032.sig`: RFC 8032 section 7.1, test 2 (message byte `72`). The seed and
  public key use the RFC 8410 PKCS#8/SPKI encodings with absent parameters.
- `rfc4754_p{256,384,521}_*`: RFC 4754 sections 8.1–8.3, public point
  `04 || gwx || gwy` and fixed-width signature `r || s` over `abc`.
- `p521_{pkcs8,spki}.der`: synthetic P-521 key pair retained from the existing test fixtures; key-to-public-key
  correspondence is checked independently by OpenSSL.
- `rsa_pss_*.sig`: generated with OpenSSL 3 using the existing synthetic
  `rsa2048_pkcs8.der` and `rsa_pss_message.bin`. SHA-256/384/512 cases use
  MGF1 with the same digest and salt lengths 32/48/64. The negative fixtures
  deliberately use a 20-byte salt or SHA-384 MGF1 with SHA-256.

PSS generation command (replace the digest, salt length and MGF digest per
the case above):

```sh
openssl dgst -sha256 -sign rsa2048_pkcs8.der -keyform DER \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 rsa_pss_message.bin > rsa_pss_sha256.sig
```

PSS signatures contain random salt. Reproduction checks verification with
the recorded parameters, not equality to a newly generated signature.
`python3 scripts/check-ike-signature-vectors.py` verifies every signature
independently with OpenSSL, including the expected negative cases. Set
`OPENSSL` to an OpenSSL 3 executable where the platform default is LibreSSL.
Run this checker alongside the crate tests.

MODP 15–18 fixed-exponent vectors remain in `src/sa_init_crypto.rs`.
The primes were compared byte-for-byte with RFC 3526 sections 4–7, then
`SHA256(A || B || shared)` was independently reproduced with both Python
integer arithmetic and Node.js BigInt, preserving each group's exact width.
The exponents are synthetic known constants, not runtime generation policy.

Sources: [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526.html),
[RFC 4754](https://www.rfc-editor.org/rfc/rfc4754.html),
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html),
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html).
