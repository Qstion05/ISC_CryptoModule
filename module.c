#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <oqs/oqs.h>
#include "tests/oqs_dilithium_test.h"
#include "tests/oqs_kyber_test.h"
#include "tests/oqs_sha3_test.h"
#include "Source/IntegrityCheck.h"
#include "Source/SelfTest.h"
#include "module.h"

int errorCode;
State current_state = POWER_ON;

// 상태 전이 함수들
State ISC_Poweron() {
    printf("\nState: POWER_ON\n");
    printf("Power On...!\n");
    return current_state = INITIALIZATION;
}

State ISC_Initialization() {
    printf("\nState: INITIALIZATION\n");

    // OQS 라이브러리 초기화 (필요한 경우)
    OQS_init();

    // 메모리 초기화 (모듈에서 사용하는 모든 변수)
    uint8_t *public_key = NULL, *secret_key = NULL;
    size_t pk_len = 0, sk_len = 0;

    // Kyber 관련 메모리 초기화
    uint8_t *kyber_public_key = NULL, *kyber_secret_key = NULL;
    uint8_t *kyber_ciphertext = NULL, *kyber_shared_secret = NULL;
    
    // SHA3 관련 메모리 초기화
    uint8_t sha3_hash[32] = {0};

    // 기존 할당된 메모리 정리
    if (public_key) OQS_MEM_cleanse(public_key, pk_len);
    if (secret_key) OQS_MEM_cleanse(secret_key, sk_len);
    if (kyber_public_key) OQS_MEM_cleanse(kyber_public_key, OQS_KEM_kyber_768_length_public_key);
    if (kyber_secret_key) OQS_MEM_cleanse(kyber_secret_key, OQS_KEM_kyber_768_length_secret_key);
    if (kyber_ciphertext) OQS_MEM_cleanse(kyber_ciphertext, OQS_KEM_kyber_768_length_ciphertext);
    if (kyber_shared_secret) OQS_MEM_cleanse(kyber_shared_secret, OQS_KEM_kyber_768_length_shared_secret);
        
    // 메모리 재할당 및 초기화
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
    
    memset(public_key, 0, OQS_SIG_dilithium_3_length_public_key);
    memset(secret_key, 0, OQS_SIG_dilithium_3_length_secret_key);
    memset(kyber_public_key, 0, OQS_KEM_kyber_768_length_public_key);
    memset(kyber_secret_key, 0, OQS_KEM_kyber_768_length_secret_key);
    memset(kyber_ciphertext, 0, OQS_KEM_kyber_768_length_ciphertext);
    memset(kyber_shared_secret, 0, OQS_KEM_kyber_768_length_shared_secret);
    
    memset(sha3_hash, 0, sizeof(sha3_hash));

    // 초기화 완료 메시지
    printf("Memory initialization complete.\n");

    return current_state = INTEGRITY_CHECK;
}

State ISC_Integrity() {
    printf("\nState: INTEGRITY_CHECK\n");
    // 무결성 검증 결과 (예제에서 무조건 성공으로 처리)
    return current_state = SELF_TEST;
}

State ISC_Selftest() {
    printf("\nState: SELF_TEST\n");
    /*
    generate_dilithium_req_file("vector/Dilithium_Test_Vector_2.req", 100);
    generate_dilithium_req_file("vector/Dilithium_Test_Vector_3.req", 100);
    generate_dilithium_req_file("vector/Dilithium_Test_Vector_5.req", 100);
    
    generate_smt_file("./vector/SHA3/SHA3_256_SMT.req");
    generate_lmt_file("./vector/SHA3/SHA3_256_LMT.req");
    generate_sha3_mct_file("./vector/SHA3/SHA3_256_MCT.req", 32);

    generate_smt_file("./vector/SHA3/SHA3_512_SMT.req");
    generate_lmt_file("./vector/SHA3/SHA3_512_LMT.req");
    generate_sha3_mct_file("./vector/SHA3/SHA3_512_MCT.req", 64);

    generate_smt_file("./vector/SHAKE/SHAKE_128_SMT.req");
    generate_lmt_file("./vector/SHAKE/SHAKE_128_LMT.req");
    generate_shake_mct_file("./vector/SHAKE/SHAKE_128_MCT.req", 16);

    generate_smt_file("./vector/SHAKE/SHAKE_256_SMT.req");
    generate_lmt_file("./vector/SHAKE/SHAKE_256_LMT.req");
    generate_shake_mct_file("./vector/SHAKE/SHAKE_256_MCT.req", 32);
    */

    if (KyberKatTest() != OQS_SUCCESS) {
        printf("Kyber Self-test failed.\n");
        sclear();
        return current_state = ERROR_STATE;
    } 
    printf("Kyber Kat Test Success!\n");

    if (DilithiumKatTest() != OQS_SUCCESS) {
        printf("Dilithium Self-test failed.\n");
        sclear();
        return current_state = ERROR_STATE;
    }
    printf("Dilithium Kat Test Success!\n");

    if (SHA3KatTest() != OQS_SUCCESS) {
        printf("SHA3 Self-test failed.\n");
        sclear();
        return current_state = ERROR_STATE;
    }
    printf("SHA3 Kat Test Success!\n");

    if (SHAKEKatTest() != OQS_SUCCESS) {
        printf("SHAKE Self-test failed.\n");
        sclear();
        return current_state = ERROR_STATE;
    }
    printf("SHAKE Kat Test Success!\n\n");
    printf("=======================\nALL Kat Test Success!\n=======================\n\n");
    return current_state = OPERATIONAL_MODE;
}



State ISC_operation() {
    printf("\nState: OPERATIONAL_MODE\n");
    int input;
    printf("Enter a integer(1. ALL, 2. Kyber 3. Dilithium 4. SHA3 5. SHAKE )) ");
    if (scanf("%d", &input) != 1) {
        printf("Invalid number input.\n");
        while (getchar() != '\n');  // 버퍼 비우기
        return ERROR_STATE;
    }

    switch (input){
        case 1:
            if(OQS_Kyber_All_test() == OQS_SUCCESS && OQS_dilithium_All_test() == OQS_SUCCESS && ISC_SHA3_All_test() == OQS_SUCCESS && ISC_SHAKE_All_test() == OQS_SUCCESS)
                return current_state = OPERATIONAL_MODE;
            else{
                return current_state = ERROR_STATE;
            }

        case 2:
            if (ISC_kyber_select() == OQS_SUCCESS){
                printf("Kyber Test Result Success\n");
                return current_state = OPERATIONAL_MODE;
            }
            
            else{ 
                printf("Kyber Test Result Failed\n");
    
                sclear();
                return current_state = ERROR_STATE;
            }
        case 3:
            if (ISC_dilithium_select() == OQS_SUCCESS){
                printf("Dilithium Test Result Success\n");
    
                return current_state = OPERATIONAL_MODE;
            }
            
            else{
                printf("Dilithium Test Result Failed\n");
    
                sclear();
                return current_state = ERROR_STATE;
            }
        case 4:
            if (SHA3_select() == OQS_SUCCESS) {
                printf("SHA3 Test Result Success\n");
    
                return current_state = OPERATIONAL_MODE;
            } else {
                printf("SHA3 Test Result Failed\n");
    
                sclear();
                return current_state = ERROR_STATE;
            }
            break;

        case 5:
            if (SHAKE_select() == OQS_SUCCESS) {
                printf("SHAKE Test Result Success\n");
    
                return current_state = OPERATIONAL_MODE;
            } else {
                printf("SHAKE Test Result Failed\n");
                sclear();
                return current_state = ERROR_STATE;
            }
            break;
        default:
            printf("OPERATIONAL_ERROR\n");

            sclear();
            return current_state = ERROR_STATE;
        }
    }

State ISC_error() {
    printf("\nState: ERROR_STATE\n");
    switch (errorCode){
        case 1100: //"Initialization Error, Memory Not Initialize"
            printf("errorCode: %d\n\n", errorCode);
            printf("Memory not Initialize\n");
            break; 

        case 3100: //"Kyber Error, Kyber's Keygen Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Kyber's Selftest Failed\n");
            break; 

        case 3101: //"Kyber Error, Kyber's encaps Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Kyber's encaps Failed\n");
            break;

        case 3102: //"Kyber Error, Kyber's decaps Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Kyber's decaps Failed\n");
            break;

        case 3103: //"Kyber Error, Kyber's Selftest Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Kyber's Selftest Failed\n");
            break; 

        case 3104: //"Dilithium Error, Dilithium's Keygen Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Dilithium's Selftest Failed\n");
            break; 

        case 3105: //"Dilithium Error, Dilithium's sign Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Dilithium's sign Failed\n");
            break;

        case 3106: //"Dilithium Error, Dilithium's verify Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Dilithium's verify Failed\n");
            break;

        case 3107: //"Dilithium Error, Dilithium's Selftest Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Dilithium's Selftest Failed\n");
            break; 

        case 3108: //"Sha3 Error, Sha3's Selftest Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Sha3's Selftest Failed\n");
            break; 

        case 3109: //"SHAKE Error, SHAKE's Selftest Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("SHAKE Selftest Failed\n");
            break;

        case 4100: //"Operation Error, 'Wrong Input"
            printf("errorCode: %d\n\n", errorCode);
            printf("Wrong Input\n");
            break; 

        case 4101: //"Operation Error, Kyber's Operation Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Kyber's Operation Failed\n");
            break; 

        case 4102: //"Operation Error, Dilithium's Operation Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("Dilithium's Operation Failed\n");
            break; 

        case 4103: //"Operation Error, SHA3's Operation Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("SHA3's Operation Failed\n");
            break; 

        case 4104: //"Operation Error, SHAKE's Operation Failed"
            printf("errorCode: %d\n\n", errorCode);
            printf("SHAKE's Operation Failed\n");
            break; 
        case 5100: //"urandom not open"
            printf("errorCode: %d\n\n", errorCode);
            printf("/dev/urandom could not open\n");
            break; 
        case 5101: //"File not open"
            printf("errorCode: %d\n\n", errorCode);
            printf("File could not open\n");
            break; 
        default:
            printf("Unknown Error\n\n");    
    }
    return current_state = INITIALIZATION;
}

// FSM 실행 함수
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
                current_state = ISC_operation();
                break;
            case ERROR_STATE:
                current_state = ISC_error();
                break;
            default:
                printf("Unknown state. Resetting to POWER_ON.\n");
                current_state = POWER_ON;
                break;
        }
    }
}

// 메인 함수
int main() {
    run_fsm();
    return 0;
}

