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

/// Read `target` (0 = EF.COM, 1...15 = DGn, 0x1D = EF.SOD) with BAC. Blocks: call off the main thread.
char *passport_read(const PassportHost *host, const char *document_number,
                    const char *date_of_birth, const char *date_of_expiry,
                    uint8_t target);

/// Same read against the built-in ICAO specimen chip; `delay_ms` per APDU.
char *passport_demo_read(const PassportHost *host, const char *document_number,
                         const char *date_of_birth, const char *date_of_expiry,
                         uint8_t target, uint32_t delay_ms);

/// Active Authentication: BAC, then INTERNAL AUTHENTICATE with 16 hex digits.
/// {"ok":true,"signature":"<hex>"}. Blocks: call off the main thread.
char *passport_active_authenticate(const PassportHost *host, const char *document_number,
                                   const char *date_of_birth, const char *date_of_expiry,
                                   const char *challenge_hex);

/// The same against the built-in specimen chip.
char *passport_demo_active_authenticate(const PassportHost *host, const char *document_number,
                                        const char *date_of_birth, const char *date_of_expiry,
                                        const char *challenge_hex, uint32_t delay_ms);

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

/// Commitment and root of a development tree holding only this document.
char *passport_enroll(const char *dg1_hex, const char *secret_hex);

/// Each requested claim with the value the proof would carry.
char *passport_preview(const char *request_json, const char *dg1_hex, int64_t now);

/// The claim proof and the direct_post body. Blocks; call off the main thread.
char *passport_prove(const char *request_json, const char *dg1_hex,
                     const char *secret_hex, int64_t now);

/// The claim proof against the on-chain registry: `registry_json` is
/// {"program_id","leaves":[..],"recent_roots":[..]}. Blocks.
char *passport_prove_enrolled(const char *request_json, const char *dg1_hex,
                              const char *dg15_hex, const char *sod_hex,
                              const char *secret_hex, const char *registry_json,
                              int64_t now);

/// The direct_post body declining the request.
char *passport_decline_body(const char *request_json);

// Enrollment (crates/ffi/src/enroll.rs): compatibility, the enrollment proof
// and its transaction, the registry sync. Fields are base64url, Solana bytes
// base64, addresses and blockhashes base58.

/// The commitment, nullifier and the Active Authentication challenge.
char *passport_enroll_prepare(const char *dg1_hex, const char *dg15_hex,
                              const char *sod_hex, const char *secret_hex);

/// Whether the passport can enroll, check by check. Empty strings for a
/// missing DG15 or Active Authentication answer.
char *passport_enroll_check(const char *dg1_hex, const char *dg15_hex,
                            const char *sod_hex, const char *secret_hex,
                            const char *challenge_hex, const char *aa_hex);

/// Load the enrollment circuit (circuit.xbc, matrices.bin, pk.bin) from `dir`.
char *passport_enroll_prover_load(const char *dir);

/// Free the enrollment prover.
void passport_enroll_prover_unload(void);

/// The enrollment proof as ENROLL instruction data. `dsc_json` is
/// {"leaves":[..],"trusted_roots":[..]}. Blocks for seconds, about 2 GB.
char *passport_enroll_prove(const char *dg1_hex, const char *dg15_hex,
                            const char *sod_hex, const char *secret_hex,
                            const char *aa_hex, const char *dsc_json);

/// The unsigned transaction for the relayer (`fee_payer`) to sign and send.
char *passport_enroll_transaction(const char *program_id, const char *fee_payer,
                                  const char *blockhash, const char *instruction_b64);

/// The registry account's address: {"address":"<base58>"}.
char *passport_registry_address(const char *program_id);

/// The registry account's data (base64): enrolled count, recent and DSC roots.
char *passport_registry_state(const char *account_b64);

/// Enrollments in transactions' logs ([[line, ..], ..]), only the program's own.
char *passport_registry_enrollments(const char *logs_json, const char *program_id);

void passport_string_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif
