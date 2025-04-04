#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>
#include "oqs_kyber_test.h"
#include "../module.h"
#include "../Source/common.h"

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
            return ISC_Kyber_All();
        case 2:
            return ISC_Kyber_512();
        case 3:
            return ISC_Kyber_768();
        case 4:
            return ISC_Kyber_1024();
        default:
            printf("Invalid choice. Please enter 1, 2, or 3.\n");
            return OQS_ERROR;
    }
}
OQS_STATUS ISC_Kyber_All(){
    if(ISC_Kyber_512() == OQS_ERROR)
        return OQS_ERROR;
    if(ISC_Kyber_768() == OQS_ERROR)
        return OQS_ERROR;
    if(ISC_Kyber_1024() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}
// Kyber-512 Test Function
OQS_STATUS ISC_Kyber_512() {
    int choice;
    DEBUG_PRINT("=== Kyber-512 ===");
    uint8_t public_key[OQS_KEM_kyber_512_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_512_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_512_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_512_length_shared_secret];

    DEBUG_PRINT(" ===== Kyber-512 Keypair ===== \n");
    if(ISC_Kyber_512_Keypair(public_key, secret_key) != OQS_SUCCESS){
        fprintf(stderr, "ERROR: OQS_KEM_kyber_512_keypair failed!\n");
        return OQS_ERROR;
    }
    if(DEBUG_MODE){
        DEBUG_HEX("pk: ", public_key, OQS_KEM_kyber_512_length_public_key);
        DEBUG_HEX("sk: ", secret_key, OQS_KEM_kyber_512_length_secret_key);
        DEBUG_PRINT("PK, SK가 생성되었습니다. 값을 변경하시겠습니까?(1. 변경한다. 2. 변경하지 않는다)");
        scanf("%d", &choice);
        if(choice == 1){
            DEBUG_PRINT("변수 변경을 선택하셨습니다.");
            DEBUG_PRINT("이후 정상적인 작동이 되지 않을 수 있습니다.");

            DEBUG_PRINT("변경할 Pk값을 입력해주세요");
            if(DEBUG_HEXIN(public_key, OQS_KEM_kyber_512_length_public_key) == false){
                DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다.");
            }

            DEBUG_PRINT("변경할 Sk값을 입력해주세요");
            if(DEBUG_HEXIN(secret_key, OQS_KEM_kyber_512_length_secret_key) == false){
               DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다."); 
            }

            DEBUG_HEX("변경 후 pk ", public_key, OQS_KEM_kyber_512_length_public_key);
            DEBUG_HEX("변경 후 sk ", secret_key, OQS_KEM_kyber_512_length_secret_key);
        }
    }
    DEBUG_PRINT(" ===== Kyber-512 Encapsulation ===== \n");
    if(ISC_Kyber_512_Encaps(ciphertext, shared_secret_e, public_key) != OQS_SUCCESS){
        fprintf(stderr, "ERROR: OQS_KEM_kyber_512_encaps failed!\n");
        return OQS_ERROR;
    }
    
    DEBUG_HEX("ct: ", ciphertext, OQS_KEM_kyber_512_length_ciphertext);
    DEBUG_HEX("ss_e: ", shared_secret_e, OQS_KEM_kyber_512_length_shared_secret);

    DEBUG_PRINT(" ===== Kyber-512 Decapsulation ===== \n");
    if(ISC_Kyber_512_Decaps(shared_secret_d, ciphertext, secret_key) != OQS_SUCCESS){
        fprintf(stderr, "ERROR: OQS_KEM_kyber_512_decaps failed!\n");
        return OQS_ERROR;
    }


    DEBUG_HEX("ss_d: ", shared_secret_d, OQS_KEM_kyber_512_length_shared_secret);
    if (memcmp(shared_secret_e, shared_secret_d, (size_t)OQS_KEM_kyber_512_length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match!\n");
        ISC_Kyber_Cleanup(secret_key, OQS_KEM_kyber_512_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_512_length_shared_secret);
        return OQS_ERROR;
    }
    DEBUG_PRINT(" Shared_Secret이 일치합니다!");
    DEBUG_PRINT(" Kyber-512 알고리즘을 종료합니다!");

    printf("[ISC_Kyber_512] Kyber-512 operations completed successfully.\n");
    ISC_Kyber_Cleanup(secret_key, OQS_KEM_kyber_512_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_512_length_shared_secret);
    return OQS_SUCCESS;
}


OQS_STATUS ISC_Kyber_512_Keypair(uint8_t *public_key, uint8_t* secret_key){
    OQS_STATUS rc = OQS_KEM_kyber_512_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) return OQS_ERROR;
    return OQS_SUCCESS;
}

OQS_STATUS ISC_Kyber_512_Encaps(uint8_t *ciphertext, uint8_t *shared_secret_e, uint8_t *public_key){
    OQS_STATUS rc = OQS_KEM_kyber_512_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) return OQS_ERROR;
    return OQS_SUCCESS;
}

OQS_STATUS ISC_Kyber_512_Decaps(uint8_t *shared_secret_d, uint8_t *ciphertext, uint8_t *secret_key){
    OQS_STATUS rc = OQS_KEM_kyber_512_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) return OQS_ERROR;
    return OQS_SUCCESS;
}

// Kyber-768 Test Function
OQS_STATUS ISC_Kyber_768() {
    int choice;
    DEBUG_PRINT("=== Kyber-768 ===");
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_768_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_768_length_shared_secret];

    DEBUG_PRINT(" ===== Kyber-512 Keypair ===== \n");
    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
        return OQS_ERROR;
    }
    DEBUG_HEX("pk: ", public_key, OQS_KEM_kyber_768_length_public_key);
    DEBUG_HEX("sk: ", secret_key, OQS_KEM_kyber_768_length_secret_key);
    if(DEBUG_MODE){
        DEBUG_PRINT("PK, SK가 생성되었습니다. 값을 변경하시겠습니까?(1. 변경한다. 2. 변경하지 않는다)");
        scanf("%d", &choice);
        getchar();
        if(choice == 1){
            DEBUG_PRINT("변수 변경을 선택하셨습니다.");
            DEBUG_PRINT("이후 정상적인 작동이 되지 않을 수 있습니다.");
            DEBUG_PRINT("변경할 Pk값을 입력해주세요");
            if(DEBUG_HEXIN(public_key, OQS_KEM_kyber_768_length_public_key) == false){
                DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다.");
            }
            DEBUG_PRINT("변경할 Sk값을 입력해주세요");
            if(DEBUG_HEXIN(secret_key, OQS_KEM_kyber_768_length_secret_key) == false){
               DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다."); 
            }
            DEBUG_HEX("변경 후 pk ", public_key, OQS_KEM_kyber_768_length_public_key);
            DEBUG_HEX("변경 후 sk ", secret_key, OQS_KEM_kyber_768_length_secret_key);
        }
    }

    DEBUG_PRINT(" ===== Kyber-768 Encapsulation ===== \n");
    rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
        return OQS_ERROR;
    }

    DEBUG_HEX("ct: ", ciphertext, OQS_KEM_kyber_768_length_ciphertext);
    DEBUG_HEX("ss_e: ", shared_secret_e, OQS_KEM_kyber_768_length_shared_secret);

    DEBUG_PRINT(" ===== Kyber-768 Decapsulation ===== ");
    rc = OQS_KEM_kyber_768_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
        return OQS_ERROR;
    }

    DEBUG_HEX("ss_d: ", shared_secret_d, OQS_KEM_kyber_768_length_shared_secret);
    if (memcmp(shared_secret_e, shared_secret_d, (size_t)OQS_KEM_kyber_768_length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match!\n");
        ISC_Kyber_Cleanup(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);
        return OQS_ERROR;
    }
    DEBUG_PRINT(" Shared_Secret이 일치합니다!");
    DEBUG_PRINT(" Kyber-768 알고리즘을 종료합니다!");

    printf("[ISC_Kyber_768] Kyber-768 operations completed successfully.\n");
    ISC_Kyber_Cleanup(secret_key, OQS_KEM_kyber_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_768_length_shared_secret);
    return OQS_SUCCESS;
}


// Kyber-1024 Test Function
OQS_STATUS ISC_Kyber_1024() {
    int choice;
    DEBUG_PRINT("=== Kyber-1024 ===");
    uint8_t public_key[OQS_KEM_kyber_1024_length_public_key];
    uint8_t secret_key[OQS_KEM_kyber_1024_length_secret_key];
    uint8_t ciphertext[OQS_KEM_kyber_1024_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_kyber_1024_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_kyber_1024_length_shared_secret];

    DEBUG_PRINT(" ===== Kyber-1024 Keypair ===== \n");
    OQS_STATUS rc = OQS_KEM_kyber_1024_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_keypair failed!\n");
        return OQS_ERROR;
    }
    
    DEBUG_HEX("pk: ", public_key, OQS_KEM_kyber_1024_length_public_key);
    DEBUG_HEX("sk: ", secret_key, OQS_KEM_kyber_1024_length_secret_key);
    if(DEBUG_MODE){
        DEBUG_PRINT("PK, SK가 생성되었습니다. 값을 변경하시겠습니까?(1. 변경한다. 2. 변경하지 않는다)");
        scanf("%d", &choice);
        getchar();
        if(choice == 1){
            DEBUG_PRINT("변수 변경을 선택하셨습니다.");
            DEBUG_PRINT("이후 정상적인 작동이 되지 않을 수 있습니다.");
            DEBUG_PRINT("변경할 Pk값을 입력해주세요");
            if(DEBUG_HEXIN(public_key, OQS_KEM_kyber_1024_length_public_key) == false){
                DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다.");
            }
            DEBUG_PRINT("변경할 Sk값을 입력해주세요");
            if(DEBUG_HEXIN(secret_key, OQS_KEM_kyber_1024_length_secret_key) == false){
               DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다."); 
            }
            DEBUG_HEX("변경 후 pk ", public_key, OQS_KEM_kyber_1024_length_public_key);
            DEBUG_HEX("변경 후 sk ", secret_key, OQS_KEM_kyber_1024_length_secret_key);
        }
    }

    rc = OQS_KEM_kyber_1024_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_encaps failed!\n");
        return OQS_ERROR;
    }

    DEBUG_PRINT(" ===== Kyber-1024 Encapsulation ===== \n");
    DEBUG_HEX("ct: ", ciphertext, OQS_KEM_kyber_1024_length_ciphertext);
    DEBUG_HEX("ss_e: ", shared_secret_e, OQS_KEM_kyber_1024_length_shared_secret);
    rc = OQS_KEM_kyber_1024_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_decaps failed!\n");
        return OQS_ERROR;
    }

    DEBUG_PRINT(" ===== Kyber-1024 Decapsulation ===== ");
    DEBUG_HEX("ss_d: ", shared_secret_d, OQS_KEM_kyber_1024_length_shared_secret);
    if (memcmp(shared_secret_e, shared_secret_d, (size_t)OQS_KEM_kyber_1024_length_shared_secret) != 0) {
        fprintf(stderr, "ERROR: Shared secrets do not match!\n");
        ISC_Kyber_Cleanup(secret_key, OQS_KEM_kyber_1024_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_1024_length_shared_secret);
        return OQS_ERROR;
    }
    DEBUG_PRINT(" Shared_Secret이 일치합니다!");
    DEBUG_PRINT(" Kyber 알고리즘을 종료합니다!");
    printf("[ISC_Kyber_1024] Kyber-1024 operations completed successfully.\n");
    ISC_Kyber_Cleanup(secret_key, OQS_KEM_kyber_1024_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_kyber_1024_length_shared_secret);
    return OQS_SUCCESS;
}



void ISC_Kyber_Cleanup(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
    OQS_MEM_cleanse(secret_key, secret_key_len);
    OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
    OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}
