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

    // 라이브러리 초기화
    OQS_init();
    // 키 길이 정의
    size_t pk_len = OQS_SIG_dilithium_3_length_public_key;
    size_t sk_len = OQS_SIG_dilithium_3_length_secret_key;

    uint8_t *public_key = malloc(pk_len);
    uint8_t *secret_key = malloc(sk_len);

    uint8_t *kyber_public_key = malloc(OQS_KEM_kyber_768_length_public_key);
    uint8_t *kyber_secret_key = malloc(OQS_KEM_kyber_768_length_secret_key);
    uint8_t *kyber_ciphertext = malloc(OQS_KEM_kyber_768_length_ciphertext);
    uint8_t *kyber_shared_secret = malloc(OQS_KEM_kyber_768_length_shared_secret);

    uint8_t sha3_hash[32] = {0};

    if (!public_key || !secret_key || !kyber_public_key || !kyber_secret_key ||
        !kyber_ciphertext || !kyber_shared_secret) {
        fprintf(stderr, "Memory allocation failed during initialization.\n");

        if (!public_key) fprintf(stderr,"[!] public_key 할당 실패\n");
        if (!secret_key) fprintf(stderr,"[!] secret_key 할당 실패\n");
        if (!kyber_public_key) fprintf(stderr,"[!] kyber_public_key 할당 실패\n");
        if (!kyber_secret_key) fprintf(stderr,"[!] kyber_secret_key 할당 실패\n");
        if (!kyber_ciphertext) fprintf(stderr,"[!] kyber_ciphertext 할당 실패\n");
        if (!kyber_shared_secret) fprintf(stderr,"[!] kyber_shared_secret 할당 실패\n");

        // 정리
        if (public_key) OQS_MEM_cleanse(public_key, pk_len), free(public_key);
        if (secret_key) OQS_MEM_cleanse(secret_key, sk_len), free(secret_key);
        if (kyber_public_key) OQS_MEM_cleanse(kyber_public_key, OQS_KEM_kyber_768_length_public_key), free(kyber_public_key);
        if (kyber_secret_key) OQS_MEM_cleanse(kyber_secret_key, OQS_KEM_kyber_768_length_secret_key), free(kyber_secret_key);
        if (kyber_ciphertext) OQS_MEM_cleanse(kyber_ciphertext, OQS_KEM_kyber_768_length_ciphertext), free(kyber_ciphertext);
        if (kyber_shared_secret) OQS_MEM_cleanse(kyber_shared_secret, OQS_KEM_kyber_768_length_shared_secret), free(kyber_shared_secret);

        return ERROR_STATE;
    }

    DEBUG_PRINT("메모리 할당 완료");
    // 실제 사용은 여기서 수행 (키 생성 등)

    // 정리: 보안 메모리 삭제
    OQS_MEM_cleanse(public_key, pk_len); free(public_key);
    OQS_MEM_cleanse(secret_key, sk_len); free(secret_key);
    OQS_MEM_cleanse(kyber_public_key, OQS_KEM_kyber_768_length_public_key); free(kyber_public_key);
    OQS_MEM_cleanse(kyber_secret_key, OQS_KEM_kyber_768_length_secret_key); free(kyber_secret_key);
    OQS_MEM_cleanse(kyber_ciphertext, OQS_KEM_kyber_768_length_ciphertext); free(kyber_ciphertext);
    OQS_MEM_cleanse(kyber_shared_secret, OQS_KEM_kyber_768_length_shared_secret); free(kyber_shared_secret);

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
            return (ISC_Kyber_All() == OQS_SUCCESS &&
                    ISC_Dilithium_All() == OQS_SUCCESS &&
                    ISC_SHA3_All() == OQS_SUCCESS &&
                    ISC_SHAKE_All() == OQS_SUCCESS)
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

State run_test(){
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
    run_test();
    return 0;
}