#include <oqs/oqs.h>
#include <stdio.h>
#include "oqs_kyber_test.h"
#include <string.h>

// Kyber 테스트 함수
OQS_STATUS OQS_Kyber_768_test() {
#ifdef OQS_ENABLE_KEM_kyber_768
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
        cleanup_kyber_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);
        return OQS_ERROR;
    }

    rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
        cleanup_kyber_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);
        return OQS_ERROR;
    }

    rc = OQS_KEM_kyber_768_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
        return OQS_ERROR;
    }

    if (memcmp(shared_secret_e, shared_secret_d, (size_t)OQS_KEM_kyber_768_length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match!\n");
        cleanup_kyber_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
		              shared_secret_e, shared_secret_d,
		              OQS_KEM_kyber_768_length_shared_secret);
        return OQS_ERROR;
    }

    printf("[OQS_Kyber_768_test] Kyber-768 operations completed successfully.\n");
    return OQS_SUCCESS;
#else
    printf("[OQS_Kyber_768_test] Kyber-768 was not enabled at compile-time.\n");
    return OQS_SUCCESS;
#endif
}

void cleanup_kyber_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}

