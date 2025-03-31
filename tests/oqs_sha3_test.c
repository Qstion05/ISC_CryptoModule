#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>
#include "../module.h"
#include "../Source/common.h"
#define MESSAGE_LEN 50

// SHA3-256 테스트
OQS_STATUS ISC_SHA3_256_test() {
    uint8_t message[MESSAGE_LEN];
    uint8_t hash[32];
    int choice;
    DEBUG_PRINT(" ===== SHA3-256 ===== ");
    ISCrandombytes(message, MESSAGE_LEN);

    DEBUG_PRINT(" 랜덤한 메세지를 생성했습니다. 변경하시겠습니까?(1. 변경한다. 2. 변경하지 않는다)");
    scanf("%d", &choice);
    getchar();
    if(choice == 1){
        DEBUG_PRINT("변경을 선택하셨습니다.");
        DEBUG_PRINT("변경할 Msg값을 입력해주세요(50byte 이내)");
        if(DEBUG_HEXIN(message, 1) == false){
            DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다.");
        }
        DEBUG_HEX("변경 후 msg ", message, MESSAGE_LEN);
    } 
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        return OQS_ERROR;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, message, MESSAGE_LEN) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
        perror("SHA3-256 hashing failed");
        EVP_MD_CTX_free(mdctx);
        return OQS_ERROR;
    }

    EVP_MD_CTX_free(mdctx);

    printf("SHA3-256 Hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}

// SHA3-512 테스트
OQS_STATUS ISC_SHA3_512_test() {
    DEBUG_PRINT(" ===== SHA3-512 ===== ");
    uint8_t message[MESSAGE_LEN];
    uint8_t hash[64];
    ISCrandombytes(message, MESSAGE_LEN);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        return OQS_ERROR;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, message, MESSAGE_LEN) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, NULL) != 1) {
        perror("SHA3-512 hashing failed");
        EVP_MD_CTX_free(mdctx);
        return OQS_ERROR;
    }

    EVP_MD_CTX_free(mdctx);

    printf("SHA3-512 Hash: ");
    for (size_t i = 0; i < 64; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}

// SHAKE-128 테스트
OQS_STATUS ISC_SHAKE_128_test() {
    uint8_t message[MESSAGE_LEN];
    uint8_t hash[32];

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        return OQS_ERROR;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, message, MESSAGE_LEN) != 1 ||
        EVP_DigestFinalXOF(mdctx, hash, 32) != 1) {
        perror("SHAKE-128 hashing failed");
        EVP_MD_CTX_free(mdctx);
        return OQS_ERROR;
    }

    EVP_MD_CTX_free(mdctx);

    printf("SHAKE-128 Hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}

// SHAKE-256 테스트
OQS_STATUS ISC_SHAKE_256_test() {
    uint8_t message[MESSAGE_LEN];
    uint8_t hash[64];
    ISCrandombytes(message, MESSAGE_LEN);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        perror("EVP_MD_CTX_new failed");
        return OQS_ERROR;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, message, MESSAGE_LEN) != 1 ||
        EVP_DigestFinalXOF(mdctx, hash, 64) != 1) {
        perror("SHAKE-256 hashing failed");
        EVP_MD_CTX_free(mdctx);
        return OQS_ERROR;
    }

    EVP_MD_CTX_free(mdctx);

    printf("SHAKE-256 Hash: ");
    for (size_t i = 0; i < 64; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}

OQS_STATUS ISC_SHA3_All_test() {
    if (ISC_SHA3_256_test() == OQS_ERROR)
        return OQS_ERROR;
    if (ISC_SHA3_512_test() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}

OQS_STATUS ISC_SHAKE_All_test() {
    if (ISC_SHAKE_128_test() == OQS_ERROR)
        return OQS_ERROR;
    if (ISC_SHAKE_256_test() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}


// SHA3 선택 함수
OQS_STATUS SHA3_select() {
    int choice;
    printf("Select SHA3 function (1. SHA3 All, 2. SHA3-256, 3. SHA3-512): ");

    if (scanf("%d", &choice) != 1) {  
        printf("Invalid input. Please enter a number.\n");
        while (getchar() != '\n');
        return OQS_ERROR;
    }

    switch (choice) {
        case 1:
            return ISC_SHA3_All_test();
        case 2:
            return ISC_SHA3_256_test();
        case 3:
            return ISC_SHA3_512_test();
        default:
            printf("Invalid choice. Please enter 1 or 2.\n");
            return OQS_ERROR;
    }
}

// SHAKE 선택 함수
OQS_STATUS SHAKE_select() {
    int choice;
    printf("Select SHAKE function (1. SHAKE All, 2. SHAKE-128, 3. SHAKE-256): ");
    if (scanf("%d", &choice) != 1) {  
        printf("Invalid input. Please enter a number.\n");
        while (getchar() != '\n');
        return OQS_ERROR;
    }

    switch (choice) {
        case 1:
            return ISC_SHAKE_All_test();
        case 2:
            return ISC_SHAKE_128_test();
        case 3:
            return ISC_SHAKE_256_test();
        default:
            printf("Invalid choice. Please enter 1,2 or 3.\n");
            return OQS_ERROR;
    }
}


