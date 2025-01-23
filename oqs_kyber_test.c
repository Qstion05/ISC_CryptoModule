#include <oqs/oqs.h>
#include <stdio.h>
#include "oqs_kyber_test.h"
#include <string.h>

// Kyber 테스트 함수
OQS_STATUS OQS_Kyber_768_test() {
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

    if(OQS_Kyber_keygen(public_key, secret_key) == OQS_ERROR){
        printf("keygen Error\n");
        return OQS_ERROR;
    }

    if(OQS_Kyber_encaps(ciphertext, shared_secret_e, public_key) == OQS_ERROR){
        printf("Encaps Error\n");
        return OQS_ERROR;
    }
    if(OQS_Kyber_decaps(shared_secret_d, ciphertext, secret_key) == OQS_ERROR){
        printf("Decaps Error\n");
        return OQS_ERROR;
    }

    if (memcmp(shared_secret_e, shared_secret_d, (size_t)OQS_KEM_kyber_768_length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match!\n");
        cleanup_kyber_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);
        return OQS_ERROR;
    }

    printf("\n[OQS_Kyber_768_test] Kyber-768 operations completed successfully.\n");
    cleanup_kyber_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);
    return OQS_SUCCESS;
}



void cleanup_kyber_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
    OQS_MEM_cleanse(secret_key, secret_key_len);
    OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
    OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}


OQS_STATUS OQS_Kyber_keygen(uint8_t *public_key, uint8_t *secret_key){
    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
        return OQS_ERROR;
    }

    printf("Public key:\n");
    for (size_t i = 0; i < OQS_KEM_kyber_768_length_public_key; i++) {
        printf("%02X", public_key[i]);
    }
    printf("\n\n");

    return OQS_SUCCESS;
}

OQS_STATUS OQS_Kyber_encaps(uint8_t *ciphertext, uint8_t *shared_secret_e, const uint8_t *public_key){
    OQS_STATUS rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
        return OQS_ERROR;
    }

    printf("ciphertext:\n");
    for (size_t i = 0; i < OQS_KEM_kyber_768_length_ciphertext; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n\n"); 


    printf("shared_secret_e:\n");
    for (size_t i = 0; i < OQS_KEM_kyber_768_length_shared_secret; i++) {
        printf("%02X", shared_secret_e[i]);
    }
    printf("\n\n");

    return OQS_SUCCESS;
}

OQS_STATUS OQS_Kyber_decaps(uint8_t *shared_secret_d, const uint8_t *ciphertext, const uint8_t *secret_key){
    OQS_STATUS rc = OQS_KEM_kyber_768_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
        return OQS_ERROR;
    }
    
    return OQS_SUCCESS;
}