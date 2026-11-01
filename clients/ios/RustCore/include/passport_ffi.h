// C ABI of crates/ffi (passport-ffi). Keep in step with crates/ffi/src/lib.rs.
//
// Every function returning `char *` hands back a JSON string that the caller
// frees with `passport_string_free`.

#ifndef PASSPORT_FFI_H
#define PASSPORT_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Largest APDU response the host may write into `rx`.
#define PASSPORT_RX_CAPACITY 1024

/// Platform callbacks for one read; each receives `ctx` unchanged.
///
/// `transceive` returns 0 and writes the response (status word included) to
/// `rx`, or a transport error: 1 timeout, 2 protocol, 3 card not present,
/// 4 unsupported, anything else I/O. Sink callbacks return 0 on success.
typedef struct PassportHost {
    void *ctx;
    /// 0 = ISO 14443-4A, 1 = ISO 14443-4B.
    uint8_t protocol;
    int32_t (*transceive)(void *ctx, const uint8_t *tx, size_t tx_len,
                          uint8_t *rx, size_t rx_capacity, size_t *rx_len);
    void (*event)(void *ctx, const char *json);
    void (*log)(void *ctx, uint8_t level, const char *line);
    int32_t (*sink_open)(void *ctx, const char *name);
    int32_t (*sink_write)(void *ctx, const uint8_t *data, size_t len);
    int32_t (*sink_close)(void *ctx);
} PassportHost;

/// Read `target` (0 = EF.COM, 1...15 = DGn) with BAC. Blocks: call off the main thread.
char *passport_read(const PassportHost *host, const char *document_number,
                    const char *date_of_birth, const char *date_of_expiry,
                    uint8_t target);

/// Same read against the built-in ICAO specimen chip; `delay_ms` per APDU.
char *passport_demo_read(const PassportHost *host, const char *document_number,
                         const char *date_of_birth, const char *date_of_expiry,
                         uint8_t target, uint32_t delay_ms);

/// Normalised key, its check digits and the 24-byte BAC key material.
char *passport_key_info(const char *document_number, const char *date_of_birth,
                        const char *date_of_expiry);

/// Parse an 88 (TD3) or 90 (TD1) character MRZ and verify its check digits.
char *passport_parse_mrz(const char *mrz);

// Attestation (crates/ffi/src/attest.rs): OpenID4VP requests in, claim proofs out.

/// Parse the link that opened the app: {"kind":"inline","request":{..}} or
/// {"kind":"fetch","request_uri","client_id","post"}.
char *passport_request_parse(const char *url);

/// Parse a request object fetched from a request_uri (JWT or JSON).
char *passport_request_object(const char *body, const char *client_id);

/// Load circuit.xbc, matrices.bin and pk.bin from `dir`. Returns the kid.
char *passport_prover_load(const char *dir);

/// Commitment and development-registry root for a document and secret.
char *passport_enroll(const char *dg1_hex, const char *secret_hex);

/// Each requested claim with the value the proof would carry.
char *passport_preview(const char *request_json, const char *dg1_hex, int64_t now);

/// The claim proof and the direct_post body. Blocks; call off the main thread.
char *passport_prove(const char *request_json, const char *dg1_hex,
                     const char *secret_hex, int64_t now);

/// The direct_post body declining the request.
char *passport_decline_body(const char *request_json);

void passport_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif
