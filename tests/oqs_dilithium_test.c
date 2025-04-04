#include <stdio.h>
#include <oqs/oqs.h>

#include "oqs_dilithium_test.h"
#include "../Source/common.h"
#include "../module.h"
// Cleanup utility
void ISC_Dilithium_Cleanup(uint8_t *secret_key, size_t secret_key_len) {
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
            return ISC_Dilithium_All();
        case 2:
            return ISC_Dilithium_2();
        case 3:
            return ISC_Dilithium_3();
        case 4:
            return ISC_Dilithium_5();
        default:
            printf("Invalid choice. Please enter 1, 2, or 3.\n");
            return OQS_ERROR;
    }
}

OQS_STATUS ISC_Dilithium_All(){
    if(ISC_Dilithium_2() == OQS_ERROR)
        return OQS_ERROR;
    if(ISC_Dilithium_3() == OQS_ERROR)
        return OQS_ERROR;
    if(ISC_Dilithium_5() == OQS_ERROR)
        return OQS_ERROR;
    return OQS_SUCCESS;
}

OQS_STATUS ISC_Dilithium_2_Keypair(uint8_t *public_key, uint8_t* secret_key){
  rc = OQS_SIG_dilithium_2_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }

OQS_STATUS ISC_Dilithium_2_sign(uint8_t *ciphertext, uint8_t *shared_secret_e, uint8_t *public_key){
    rc = OQS_SIG_dilithium_2_sign(signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }
}

OQS_STATUS ISC_Dilithium_2_verify(uint8_t *ciphertext, uint8_t *shared_secret_e, uint8_t *public_key){
    rc = OQS_SIG_dilithium_2_verify(message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }
}


// Dilithium-2 테스트 함수
OQS_STATUS ISC_Dilithium_2() {
    int choice;
    DEBUG_PRINT("=== Dilithium-2 ===");
    OQS_STATUS rc;
    uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_2_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_2_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

    OQS_randombytes(message, message_len);
    DEBUG_PRINT(" ===== Dilithium-2 Keypair ===== \n");
    rc = OQS_SIG_dilithium_2_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }
    if(DEBUG_MODE){
        DEBUG_PRINT("PK, SK가 생성되었습니다. 값을 변경하시겠습니까?(1. 변경한다. 2. 변경하지 않는다)");
        scanf("%d", &choice);
        getchar();
        if(choice == 1){
            DEBUG_PRINT("변수 변경을 선택하셨습니다.");
            DEBUG_PRINT("이후 정상적인 작동이 되지 않을 수 있습니다.");
            DEBUG_PRINT("변경할 Pk값을 입력해주세요");
            if(DEBUG_HEXIN(public_key, OQS_SIG_dilithium_2_length_public_key) == false){
                DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다.");
            }
            DEBUG_PRINT("변경할 Sk값을 입력해주세요");
            if(DEBUG_HEXIN(secret_key, OQS_SIG_dilithium_2_length_secret_key) == false){
               DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다."); 
            }
            DEBUG_HEX("변경 후 pk ", public_key, OQS_SIG_dilithium_2_length_public_key);
            DEBUG_HEX("변경 후 sk ", secret_key, OQS_SIG_dilithium_2_length_secret_key);
        }
    }

    DEBUG_PRINT(" ===== Dilithium_2 Signature ===== \n");
    rc = OQS_SIG_dilithium_2_sign(signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }
    
    DEBUG_HEX("Signature: ", signature, OQS_SIG_dilithium_2_length_signature);
    DEBUG_HEX("Message: ", message, message_len);

    DEBUG_PRINT(" ===== Dilithium_2 Verify ===== \n");
    rc = OQS_SIG_dilithium_2_verify(message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        return OQS_ERROR;
    }
    
    DEBUG_HEX("Signature: ", signature, OQS_SIG_dilithium_2_length_signature);
    DEBUG_HEX("Message: ", message, message_len);

    printf("[ISC_Dilithium_2] dilithium-2 operations completed successfully.\n");
    ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_2_length_secret_key);
    return OQS_SUCCESS;
}

// Dilithium-2 테스트 함수
OQS_STATUS ISC_Dilithium_3() {
    int choice;
    DEBUG_PRINT("=== Dilithium-3 ===");
    OQS_STATUS rc;
    uint8_t public_key[OQS_SIG_dilithium_3_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_3_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_3_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

    OQS_randombytes(message, message_len);
    DEBUG_PRINT(" ===== Dilithium-3 Keypair ===== \n");
    rc = OQS_SIG_dilithium_3_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_keypair failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_3_length_secret_key);
        return OQS_ERROR;
    }
    if(DEBUG_MODE){
        DEBUG_PRINT("PK, SK가 생성되었습니다. 값을 변경하시겠습니까?(1. 변경한다. 2. 변경하지 않는다)");
        scanf("%d", &choice);
        getchar();
        if(choice == 1){
            DEBUG_PRINT("변수 변경을 선택하셨습니다.");
            DEBUG_PRINT("이후 정상적인 작동이 되지 않을 수 있습니다.");
            DEBUG_PRINT("변경할 Pk값을 입력해주세요");
            if(DEBUG_HEXIN(public_key, OQS_SIG_dilithium_3_length_public_key) == false){
                DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다.");
            }
            DEBUG_PRINT("변경할 Sk값을 입력해주세요");
            if(DEBUG_HEXIN(secret_key, OQS_SIG_dilithium_3_length_secret_key) == false){
               DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다."); 
            }
            DEBUG_HEX("변경 후 pk ", public_key, OQS_SIG_dilithium_3_length_public_key);
            DEBUG_HEX("변경 후 sk ", secret_key, OQS_SIG_dilithium_3_length_secret_key);
        }
    }
    DEBUG_PRINT(" ===== Dilithium_3 Signature ===== \n");
    rc = OQS_SIG_dilithium_3_sign(signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_sign failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_3_length_secret_key);
        return OQS_ERROR;
    }
   
    DEBUG_HEX("Signature: ", signature, OQS_SIG_dilithium_3_length_signature);
    DEBUG_HEX("Message: ", message, message_len);

    rc = OQS_SIG_dilithium_3_verify(message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_verify failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_3_length_secret_key);
        return OQS_ERROR;
    }
    DEBUG_PRINT(" ===== Dilithium_3 Verify ===== \n");
    DEBUG_HEX("Signature: ", signature, OQS_SIG_dilithium_3_length_signature);
    DEBUG_HEX("Message: ", message, message_len);

    printf("[ISC_Dilithium_3] dilithium-2 operations completed successfully.\n");
    ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_3_length_secret_key);
    return OQS_SUCCESS;

}


OQS_STATUS ISC_Dilithium_5() {
    int choice;
    DEBUG_PRINT("=== Dilithium-5 ===");
    OQS_STATUS rc;
    uint8_t public_key[OQS_SIG_dilithium_5_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_5_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_5_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

    OQS_randombytes(message, message_len);
    DEBUG_PRINT(" ===== Dilithium-5 Keypair ===== \n");
    rc = OQS_SIG_dilithium_5_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_5_keypair failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_5_length_secret_key);
        return OQS_ERROR;
    }
    if(DEBUG_MODE){
        DEBUG_PRINT("PK, SK가 생성되었습니다. 값을 변경하시겠습니까?(1. 변경한다. 2. 변경하지 않는다)");
        scanf("%d", &choice);
        getchar();
        if(choice == 1){
            DEBUG_PRINT("변수 변경을 선택하셨습니다.");
            DEBUG_PRINT("이후 정상적인 작동이 되지 않을 수 있습니다.");
            DEBUG_PRINT("변경할 Pk값을 입력해주세요");
            if(DEBUG_HEXIN(public_key, OQS_SIG_dilithium_5_length_public_key) == false){
                DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다.");
            }
            DEBUG_PRINT("변경할 Sk값을 입력해주세요");
            if(DEBUG_HEXIN(secret_key, OQS_SIG_dilithium_5_length_secret_key) == false){
               DEBUG_PRINT("입력값에 오류가 발생했습니다. 변경하지 않습니다."); 
            }
            DEBUG_HEX("변경 후 pk ", public_key, OQS_SIG_dilithium_5_length_public_key);
            DEBUG_HEX("변경 후 sk ", secret_key, OQS_SIG_dilithium_5_length_secret_key);
        }
    }
    DEBUG_PRINT(" ===== Dilithium_5 Signature ===== \n");
    rc = OQS_SIG_dilithium_5_sign(signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_5_sign failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_5_length_secret_key);
        return OQS_ERROR;
    }
    
    DEBUG_HEX("Signature: ", signature, OQS_SIG_dilithium_5_length_signature);
    DEBUG_HEX("Message: ", message, message_len);

    DEBUG_PRINT(" ===== Dilithium_5 Verify ===== \n");
    rc = OQS_SIG_dilithium_5_verify(message, message_len, signature, signature_len, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_dilithium_5_verify failed!\n");
        ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_5_length_secret_key);
        return OQS_ERROR;
    }
    
    DEBUG_HEX("Signature: ", signature, OQS_SIG_dilithium_5_length_signature);
    DEBUG_HEX("Message: ", message, message_len);

    printf("[ISC_Dilithium_5] dilithium-2 operations completed successfully.\n");
    ISC_Dilithium_Cleanup(secret_key, OQS_SIG_dilithium_5_length_secret_key);
    return OQS_SUCCESS;

}
