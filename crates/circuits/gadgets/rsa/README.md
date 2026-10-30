# passport-gadget-rsa

RSA signature verification for xark zero-knowledge circuits.

- `modexp_65537`: `s^65537 mod n` over `xark-bignum` limbs, with the signature
  range-checked below the modulus and the modulus range-checked and odd.
- `pkcs1v15_sha256_verify_1024`: RSASSA-PKCS1-v1_5 with SHA-256 for a
  1024-bit modulus (Document Signer Certificates and passport Security Objects).
- `iso9796_2_s1_sha1_verify_1024`: ISO/IEC 9796-2 scheme 1 with SHA-1 and
  partial message recovery for a 1024-bit modulus, the format ICAO passport
  chips use for Active Authentication (Doc 9303 part 11).

An [xark](https://github.com/blueshift-gg/xark) gadget: ordinary `no_std` Rust that the xark compiler lowers to R1CS. Written for the passport project; a candidate for upstreaming.
