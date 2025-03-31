#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <oqs/oqs.h>
#include <stdlib.h>
#include "tests/oqs_dilithium_test.h"
#include "tests/oqs_kyber_test.h"
#include "tests/oqs_sha3_test.h"
#include "Source/IntegrityCheck.h"
#include "Source/SelfTest.h"
#include "module.h"
#include "./Source/common.h"

// 디버그 플래그 정의
bool DEBUG_MODE = false;

// 터미널 클리어 함수
void sclear() {
    printf("\033[H\033[J");
    fflush(stdout);
}

int errorCode;
State current_state = POWER_ON;

State ISC_Poweron() {
    printf("\nState: POWER_ON\n");
    DEBUG_PRINT("전원 상태 진입");
    printf("Power On...!\n");
    return current_state = INITIALIZATION;
}

State ISC_Initialization() {
    printf("\nState: INITIALIZATION\n");
    DEBUG_PRINT("초기화 시작");

    OQS_init();

    // 메모리 초기화
    uint8_t *public_key = NULL, *secret_key = NULL;
    size_t pk_len = 0, sk_len = 0;

    uint8_t *kyber_public_key = NULL, *kyber_secret_key = NULL;
    uint8_t *kyber_ciphertext = NULL, *kyber_shared_secret = NULL;

    uint8_t sha3_hash[32] = {0};

    DEBUG_PRINT("메모리 정리 시작");

    if (public_key) OQS_MEM_cleanse(public_key, pk_len);
    if (secret_key) OQS_MEM_cleanse(secret_key, sk_len);

    if (kyber_public_key) OQS_MEM_cleanse(kyber_public_key, OQS_KEM_kyber_768_length_public_key);
    if (kyber_secret_key) OQS_MEM_cleanse(kyber_secret_key, OQS_KEM_kyber_768_length_secret_key);
    if (kyber_ciphertext) OQS_MEM_cleanse(kyber_ciphertext, OQS_KEM_kyber_768_length_ciphertext);
    if (kyber_shared_secret) OQS_MEM_cleanse(kyber_shared_secret, OQS_KEM_kyber_768_length_shared_secret);

    // 메모리 할당
    public_key = malloc(OQS_SIG_dilithium_3_length_public_key);
    secret_key = malloc(OQS_SIG_dilithium_3_length_secret_key);
    kyber_public_key = malloc(OQS_KEM_kyber_768_length_public_key);
    kyber_secret_key = malloc(OQS_KEM_kyber_768_length_secret_key);
    kyber_ciphertext = malloc(OQS_KEM_kyber_768_length_ciphertext);
    kyber_shared_secret = malloc(OQS_KEM_kyber_768_length_shared_secret);

    if (!public_key || !secret_key || !kyber_public_key || !kyber_secret_key || !kyber_ciphertext || !kyber_shared_secret) {
        fprintf(stderr, "Memory allocation failed during initialization.\n");
        return ERROR_STATE;
    }

    DEBUG_PRINT("메모리 할당 완료");

    memset(public_key, 0, OQS_SIG_dilithium_3_length_public_key);
    memset(secret_key, 0, OQS_SIG_dilithium_3_length_secret_key);
    memset(kyber_public_key, 0, OQS_KEM_kyber_768_length_public_key);
    memset(kyber_secret_key, 0, OQS_KEM_kyber_768_length_secret_key);
    memset(kyber_ciphertext, 0, OQS_KEM_kyber_768_length_ciphertext);
    memset(kyber_shared_secret, 0, OQS_KEM_kyber_768_length_shared_secret);
    memset(sha3_hash, 0, sizeof(sha3_hash));

    DEBUG_PRINT("초기화 완료");
    printf("Memory initialization complete.\n");
    return current_state = INTEGRITY_CHECK;
}

State ISC_Integrity() {
    printf("\nState: INTEGRITY_CHECK\n");
    DEBUG_PRINT("무결성 검사 진입");
    DEBUG_PRINT("무결성 검사 미구현!");

    return current_state = SELF_TEST;
}

State ISC_Selftest() {
    printf("\nState: SELF_TEST\n");
    DEBUG_PRINT("자가시험 시작");

    if (KyberKatTest() != OQS_SUCCESS) {
        printf("Kyber Self-test failed.\n");
        return current_state = ERROR_STATE;
    }
    DEBUG_PRINT("Kyber KAT 성공");

    if (DilithiumKatTest() != OQS_SUCCESS) {
        printf("Dilithium Self-test failed.\n");
        return current_state = ERROR_STATE;
    }
    DEBUG_PRINT("Dilithium KAT 성공");

    if (SHA3KatTest() != OQS_SUCCESS) {
        printf("SHA3 Self-test failed.\n");
        return current_state = ERROR_STATE;
    }
    DEBUG_PRINT("SHA3 KAT 성공");

    if (SHAKEKatTest() != OQS_SUCCESS) {
        printf("SHAKE Self-test failed.\n");
        return current_state = ERROR_STATE;
    }
    DEBUG_PRINT("SHAKE KAT 성공");

    printf("ALL Kat Test Success!\n");
    return current_state = OPERATIONAL_MODE;
}

State ISC_Operation() {
    printf("\nState: OPERATIONAL_MODE\n");
    int input;
    printf("Enter a number (1. ALL, 2. Kyber, 3. Dilithium, 4. SHA3, 5. SHAKE): ");
    if (scanf("%d", &input) != 1) {
        printf("Invalid number input.\n");
        while (getchar() != '\n');
        return ERROR_STATE;
    }

    DEBUG_PRINT("사용자 선택: %d", input);

    switch (input) {
        case 1:
            return (OQS_Kyber_All_test() == OQS_SUCCESS &&
                    OQS_dilithium_All_test() == OQS_SUCCESS &&
                    ISC_SHA3_All_test() == OQS_SUCCESS &&
                    ISC_SHAKE_All_test() == OQS_SUCCESS)
                   ? OPERATIONAL_MODE : ERROR_STATE;
        case 2:
            return ISC_kyber_select() == OQS_SUCCESS ? OPERATIONAL_MODE : ERROR_STATE;
        case 3:
            return ISC_dilithium_select() == OQS_SUCCESS ? OPERATIONAL_MODE : ERROR_STATE;
        case 4:
            return SHA3_select() == OQS_SUCCESS ? OPERATIONAL_MODE : ERROR_STATE;
        case 5:
            return SHAKE_select() == OQS_SUCCESS ? OPERATIONAL_MODE : ERROR_STATE;
        default:
            printf("Invalid selection.\n");
            return ERROR_STATE;
    }
}

State ISC_Error() {
    printf("\nState: ERROR_STATE\n");
    DEBUG_PRINT("에러 발생, 상태 종료 또는 재시작 필요");
    return INITIALIZATION;
}

State run_fsm(){
    while (1) {
        switch (current_state) {
            case POWER_ON:
                current_state = ISC_Poweron();
                break;
            case INITIALIZATION:
                current_state = ISC_Initialization();
                break;
            case INTEGRITY_CHECK:
                current_state = ISC_Integrity();
                break;
            case SELF_TEST:
                current_state = ISC_Selftest();
                break;
            case OPERATIONAL_MODE:
                current_state = ISC_Operation();
                break;
            case ERROR_STATE:
                current_state = ISC_Error();
                break;
            default:
                printf("Unknown state. Resetting to POWER_ON.\n");
                current_state = POWER_ON;
                break;
        }
    }
}
int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        DEBUG_MODE = true;
        printf("디버그 모드 활성화됨\n");
    }
    run_fsm();
    return 0;
}