#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>
#include "oqs_kyber_test.h"
#include "../Source/common.h"

OQS_STATUS OQS_Kyber_keygen(uint8_t *public_key, uint8_t *secret_key){
    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

OQS_STATUS OQS_Kyber_encaps(uint8_t *ciphertext, uint8_t *shared_secret_e, const uint8_t *public_key){
    OQS_STATUS rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
        return OQS_ERROR;
    }
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

void cleanup_kyber_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
    OQS_MEM_cleanse(secret_key, secret_key_len);
    OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
    OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}



// Kyber 테스트 함수
OQS_STATUS ISC_kyber_select() {
    int choice;
    printf("Select Kyber version:\n");
    printf("(1. Kyber-All, 2. Kyber-512, 3. Kyber-768, 4. Kyber-1024): ");

    if (scanf("%d", &choice) != 1) {  // 입력 오류 처리
        printf("Invalid input. Please enter a number.\n");
        while (getchar() != '\n');  // 버퍼 비우기
        return OQS_ERROR;
    }

    switch (choice) {
        case 1:
            return OQS_Kyber_All_test();
        case 2:
            return OQS_Kyber_512_test();
        case 3:
            return OQS_Kyber_768_test();
        case 4:
            return OQS_Kyber_1024_test();
        default:
            printf("Invalid choice. Please enter 1, 2, or 3.\n");
            return OQS_ERROR;
    }
}
OQS_STATUS OQS_Kyber_All_test(){
    if(OQS_Kyber_512_test() == OQS_ERROR)
        return OQS_ERROR;
    if(OQS_Kyber_768_test() == OQS_ERROR)
        return OQS_ERROR;
    if(OQS_Kyber_1024_test() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}
// Kyber-512 Test Function
OQS_STATUS OQS_Kyber_512_test() {
    uint8_t public_key[OQS_KEM_kyber_512_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_512_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_512_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_512_length_shared_secret];

    OQS_STATUS rc = OQS_KEM_kyber_512_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_512_keypair failed!\n");
        return OQS_ERROR;
    }

    rc = OQS_KEM_kyber_512_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_512_encaps failed!\n");
        return OQS_ERROR;
    }

    rc = OQS_KEM_kyber_512_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_512_decaps failed!\n");
        return OQS_ERROR;
    }

    if (memcmp(shared_secret_e, shared_secret_d, (size_t)OQS_KEM_kyber_512_length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match!\n");
        cleanup_kyber_stack(secret_key, OQS_KEM_kyber_512_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_512_length_shared_secret);
        return OQS_ERROR;
    }

    printf("[ISC_Kyber_512] Kyber-512 operations completed successfully.\n");
    cleanup_kyber_stack(secret_key, OQS_KEM_kyber_512_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_512_length_shared_secret);
    return OQS_SUCCESS;
}

// Kyber-768 Test Function
OQS_STATUS OQS_Kyber_768_test() {
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
        return OQS_ERROR;
    }

    rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
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

    printf("[ISC_Kyber_768] Kyber-768 operations completed successfully.\n");
    cleanup_kyber_stack(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);
    return OQS_SUCCESS;
}


// Kyber-1024 Test Function
OQS_STATUS OQS_Kyber_1024_test() {
    uint8_t public_key[OQS_KEM_kyber_1024_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_1024_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_1024_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_1024_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_1024_length_shared_secret];

    OQS_STATUS rc = OQS_KEM_kyber_1024_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_keypair failed!\n");
        return OQS_ERROR;
    }

    rc = OQS_KEM_kyber_1024_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_encaps failed!\n");
        return OQS_ERROR;
    }

    rc = OQS_KEM_kyber_1024_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_decaps failed!\n");
        return OQS_ERROR;
    }

    if (memcmp(shared_secret_e, shared_secret_d, (size_t)OQS_KEM_kyber_1024_length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match!\n");
        cleanup_kyber_stack(secret_key, OQS_KEM_kyber_1024_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_1024_length_shared_secret);
        return OQS_ERROR;
    }

    printf("[ISC_Kyber_1024] Kyber-1024 operations completed successfully.\n");
    cleanup_kyber_stack(secret_key, OQS_KEM_kyber_1024_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_1024_length_shared_secret);
    return OQS_SUCCESS;
}
