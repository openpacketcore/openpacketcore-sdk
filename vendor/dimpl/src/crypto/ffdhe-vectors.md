# FFDHE parameters and independent witnesses

`ffdhe2048.bin` and `ffdhe4096.bin` contain the unsigned, big-endian primes
from [RFC 7919 Appendix A.1/A.3](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A).
Both use generator 2. They match rustls 0.23.46's published parameters and
the independently exported OpenSSL 3.6.5 named groups:

```sh
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe4096
```

The PEM outputs are `tests/ossl/ffdhe2048.pem` and `ffdhe4096.pem`; these are
public parameters, not keys. OpenSSL interoperability tests compare the
reassembled wire prime and generator with the binary parameters.

| File | SHA-256 |
| --- | --- |
| ffdhe2048.bin | 9cd3b7f336872f46c09428d1bbc19877a4d440512cda8d1c1cf0cd6e33698966 |
| ffdhe4096.bin | 4648414224ac881b3d0dc59b466f96d06a558278776807797ecf1f66ff397b3e |
| ffdhe2048.pem | 9ba6429597aeed2d8617a7705b56e96d044f64b07971659382e426675105654b |
| ffdhe4096.pem | 64852d6890ff9e62eecd1ee89c72af9af244dfef5b853bcedea3dfd7aade22b3 |

`ffdhe-vectors.txt` preserves the two independent fixtures in
`crates/opc-tls/tests/data/ffdhe.json` at commit `e3a6da95f` without a JSON
parser dependency. Columns are bit length, fixed test exponent, public
value, peer public value, and shared secret, with integers in hexadecimal.
Python integer `pow` and LibreSSL 3.3.6 `pkeyutl -derive` independently
agreed on these outputs. Tests compare both public and shared values,
reject invalid peer values, and check TLS 1.2's leading-zero removal.
The fixed exponents are exclusively test data; production exchanges draw
a new 512-bit exponent from the OS CSPRNG.
