#include <oqs/oqs.h>
#include <stdio.h>
#include "oqs_dilithium_test.h"

// Cleanup utility
void cleanup_dilithium_stack(uint8_t *secret_key, size_t secret_key_len) {
    OQS_MEM_cleanse(secret_key, secret_key_len);
}

OQS_STATUS OQS_SIG_dilithium_2_test() {
#ifdef OQS_ENABLE_SIG_dilithium_2
    OQS_STATUS rc;

    uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_2_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_2_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

    // Create a random test message to sign
    OQS_randombytes(message, message_len);

    rc = OQS_SIG_dilithium_2_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }

    rc = OQS_SIG_dilithium_2_sign(signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }

    rc = OQS_SIG_dilithium_2_verify(message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }

    printf("[example_stack] OQS_SIG_dilithium_2 operations completed successfully.\n");
    cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
    return OQS_SUCCESS;

#else
    printf("[example_stack] OQS_SIG_dilithium_2 was not enabled at compile-time.\n");
    return OQS_SUCCESS;
#endif
}

