#ifndef WALRUS_GO_FFI_H
#define WALRUS_GO_FFI_H

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Store a blob on Walrus (encode → register → upload → certify).
 *
 * config_json  – UTF-8 JSON: {"walrus_config":"/path/to/client_config.yaml",
 *                              "private_key_b64":"<base64url 32-byte key>",
 *                              "epochs":5,
 *                              "encoding":"RS2",
 *                              "deletable":false}
 * data_ptr     – raw blob bytes
 * data_len     – number of bytes
 *
 * Returns a heap-allocated C string with JSON:
 *   success: {"blob_id":"…","already_certified":bool,"tx_digest":"…"}
 *   failure: {"error":"…"}
 *
 * MUST be freed with walrus_free_string().
 */
char* walrus_store_blob(const char* config_json,
                        const uint8_t* data_ptr,
                        size_t data_len);

/** Free a string returned by walrus_store_blob. */
void walrus_free_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif /* WALRUS_GO_FFI_H */