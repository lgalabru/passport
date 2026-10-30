# passport-gadget-sha1

SHA-1 gadget for xark zero-knowledge circuits.

SHA-1 is broken for collision resistance and should not be chosen for new
designs. It is here because deployed systems still sign with it: ICAO
electronic passports use SHA-1 inside ISO/IEC 9796-2 Active Authentication
and in many Document Signer Certificates. Verifying those signatures in a
circuit needs the exact function.

An [xark](https://github.com/blueshift-gg/xark) gadget: ordinary `no_std` Rust that the xark compiler lowers to R1CS. Written for the passport project; a candidate for upstreaming.
