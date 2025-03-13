#include <stdio.h>
#include <oqs/oqs.h>

#include "oqs_dilithium_test.h"
#include "../Source/common.h"
// Cleanup utility
void cleanup_dilithium_stack(uint8_t *secret_key, size_t secret_key_len) {
    OQS_MEM_cleanse(secret_key, secret_key_len);
}

OQS_STATUS ISC_dilithium_select() {
    int choice;
    printf("Select Dilithium version");
    printf("(1. Dilithium All, 2. Dilithium-2, 3. Dilithium-3, 4. Dilithium-5): ");
    if (scanf("%d", &choice) != 1) {  // 입력 오류 처리
    printf("Invalid input. Please enter a number.\n");
    while (getchar() != '\n');  // 버퍼 비우기
    return OQS_ERROR;
        }
    switch (choice) {
        case 1:
            return OQS_dilithium_All_test();
        case 2:
            return OQS_dilithium_2_test();
        case 3:
            return OQS_dilithium_3_test();
        case 4:
            return OQS_dilithium_5_test();
        default:
            printf("Invalid choice. Please enter 1, 2, or 3.\n");
            return OQS_ERROR;
    }
}

OQS_STATUS OQS_dilithium_All_test(){
    if(OQS_dilithium_2_test() == OQS_ERROR)
        return OQS_ERROR;
    if(OQS_dilithium_3_test() == OQS_ERROR)
        return OQS_ERROR;
    if(OQS_dilithium_5_test() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}

// Dilithium-2 테스트 함수
OQS_STATUS OQS_dilithium_2_test() {
    OQS_STATUS rc;
    uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_2_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_2_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

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

    printf("[ISC_Dilithium_2] dilithium-2 operations completed successfully.\n");
    cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
    return OQS_SUCCESS;

    printf("[ISC_Dilithium_2] dilithium-2 was not enabled at compile-time.\n");
    cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
    return OQS_ERROR;
}

// Dilithium-3 테스트 함수
OQS_STATUS OQS_dilithium_3_test() {
    OQS_STATUS rc;

    uint8_t public_key[OQS_SIG_dilithium_3_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_3_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_3_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

    OQS_randombytes(message, message_len);

    rc = OQS_SIG_dilithium_3_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_keypair failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
        return OQS_ERROR;
    }

    rc = OQS_SIG_dilithium_3_sign(signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_3n failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
        return OQS_ERROR;
    }

    rc = OQS_SIG_dilithium_3_verify(message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_verify failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
        return OQS_ERROR;
    }

    printf("[ISC_Dilithium_3] dilithium-3 operations completed successfully.\n");
    cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
    return OQS_SUCCESS;

    printf("[ISC_Dilithium_3] dilithium-3 was not enabled at compile-time.\n");
    cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_3_length_secret_key);
    return OQS_ERROR;
}

// Dilithium-5 테스트 함수
OQS_STATUS OQS_dilithium_5_test() {
    OQS_STATUS rc;

    uint8_t public_key[OQS_SIG_dilithium_5_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_5_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_5_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

    OQS_randombytes(message, message_len);

    rc = OQS_SIG_dilithium_5_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_5_keypair failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_5_length_secret_key);
        return OQS_ERROR;
    }

    rc = OQS_SIG_dilithium_5_sign(signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_5n failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_5_length_secret_key);
        return OQS_ERROR;
    }

    rc = OQS_SIG_dilithium_5_verify(message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_5_verify failed!\n");
        cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_5_length_secret_key);
        return OQS_ERROR;
    }

    printf("[ISC_Dilithium_5] dilithium-5 operations completed successfully.\n");
    cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_5_length_secret_key);
    return OQS_SUCCESS;

    printf("[ISC_Dilithium_5] dilithium-5 was not enabled at compile-time.\n");
    cleanup_dilithium_stack(secret_key, OQS_SIG_dilithium_5_length_secret_key);
    return OQS_ERROR;
}
