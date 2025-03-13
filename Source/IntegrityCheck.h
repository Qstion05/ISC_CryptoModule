#ifndef INTEGRITY_CHECK_H
#define INTEGRITY_CHECK_H

#include <oqs/oqs.h>

void cleanup_memory(uint8_t *data, size_t len);
void sha3_256(const char *input, unsigned char *output);
void create_integrity_file();


OQS_STATUS generate_dilithium_keys(uint8_t **public_key, uint8_t **secret_key, size_t *pk_len, size_t *sk_len);
OQS_STATUS sign_integrity_file(uint8_t *secret_key, size_t sk_len, uint8_t **signature, size_t *sig_len);
OQS_STATUS verify_integrity(uint8_t *public_key, size_t pk_len, uint8_t *signature, size_t sig_len);
OQS_STATUS test_dilithium_integrity();
OQS_STATUS IntegrityCheck();


#endif // INTEGRITY_CHECK_H
