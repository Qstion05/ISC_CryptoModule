#include <stdio.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include "../include/sha3/sha3.h" 
#include "oqs_sha3_test.h"

#define MESSAGE_LEN 50

// SHA3 선택 함수
OQS_STATUS SHA3_select() {
    int choice;
    printf("Select SHA3 function:");
    printf("(1. SHA3 All, 2. SHA3-256, 3. SHA3-512): ");

    if (scanf("%d", &choice) != 1) {  // 입력 오류 처리
        printf("Invalid input. Please enter a number.\n");
        while (getchar() != '\n');  // 입력 버퍼 비우기
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
    printf("Select SHAKE function:");
    printf("(1. SHAKE All, 2. SHAKE-128, 3. SHAKE-256): ");
    if (scanf("%d", &choice) != 1) {  // 입력 오류 처리
        printf("Invalid input. Please enter a number.\n");
        while (getchar() != '\n');  // 입력 버퍼 비우기
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
            printf("Invalid choice. Please enter 1 or 2.\n");
            return OQS_ERROR;
    }
}

OQS_STATUS ISC_SHA3_All_test(){
    if(ISC_SHA3_256_test() == OQS_ERROR)
        return OQS_ERROR;
    if(ISC_SHA3_512_test() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}

OQS_STATUS ISC_SHAKE_All_test(){
    if(ISC_SHAKE_128_test() == OQS_ERROR)
        return OQS_ERROR;
    if(ISC_SHAKE_256_test() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}


OQS_STATUS ISC_SHA3_256_test() {
    uint8_t message[MESSAGE_LEN] = {0};
    uint8_t hash[32];

    // SHA3-256 해시 계산 (SHAKE 사용 안함)
    sha3_hash(hash, 32, message, MESSAGE_LEN, 256, 0);

    printf("SHA3-256 Hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}

OQS_STATUS ISC_SHA3_512_test() {
    uint8_t message[MESSAGE_LEN] = {0};
    uint8_t hash[64];

    // SHA3-512 해시 계산 (SHAKE 사용 안함)
    sha3_hash(hash, 64, message, MESSAGE_LEN, 512, 0);

    printf("SHA3-512 Hash: ");
    for (size_t i = 0; i < 64; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}

OQS_STATUS ISC_SHAKE_128_test() {
    uint8_t message[MESSAGE_LEN] = {0};
    uint8_t hash[32];

    // SHAKE-128 해시 계산 (SHAKE 사용)
    sha3_hash(hash, 32, message, MESSAGE_LEN, 128, 1);

    printf("SHAKE-128 Hash: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}

OQS_STATUS ISC_SHAKE_256_test() {
    uint8_t message[MESSAGE_LEN] = {0};
    uint8_t hash[64];

    // SHAKE-256 해시 계산 (SHAKE 사용)
    sha3_hash(hash, 64, message, MESSAGE_LEN, 256, 1);

    printf("SHAKE-256 Hash: ");
    for (size_t i = 0; i < 64; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
    return OQS_SUCCESS;
}