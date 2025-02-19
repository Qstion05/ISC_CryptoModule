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



// 현재 상태를 저장하는 변수
State current_state = POWER_ON;
int errorCode = 0; // 0 = 정상 상태

// 상태 전이 함수들
State ISC_Poweron() {
    printf("\nState: POWER_ON\n");
    printf("Initializing system...\n");
    return current_state = INITIALIZATION;
}

State ISC_Initialization() {
    printf("\nState: INITIALIZATION\n");
    // 초기화 성공 여부 (예제에서 무조건 성공으로 처리)
    bool init_success = true;
    char input[100];
    printf("Enter a string (type 'error' to error_mode: ) ");
    scanf("%99s", input);
    if (strcmp(input, "error") == 0) {
        init_success = false;  // "error"인 경우 false 반환
    } else {
        init_success = true;  // 그 외의 경우 true 반환
    }

    if (init_success) {
        printf("Initialization complete.\n");
        return current_state = INTEGRITY_CHECK;
    } else {
        printf("Initialization failed.\n");
        errorCode = 100;
        sclear();
        return current_state = ERROR_STATE;
    }
}

State ISC_Integrity() {
    printf("\nState: INTEGRITY_CHECK\n");
    // 무결성 검증 결과 (예제에서 무조건 성공으로 처리)
    char input[100];
    printf("Enter a string (type 'error' to error_mode: ) ");
    scanf("%99s", input);
    if (IntegrityCheck() == OQS_SUCCESS) { 
        printf("Integrity check passed.\n");
        return current_state = SELF_TEST;
    } else {
        printf("Integrity check failed.\n");
        errorCode = 101;
        sclear();
        return current_state = ERROR_STATE;
    }
}

State ISC_Selftest() {
    printf("\nState: SELF_TEST\n");
    // 자가 시험 결과 (예제에서 무조건 성공으로 처리)
    bool test_success = true;
    char input[100];
    printf("Enter a string (type 'error' to error_mode: ) ");
    scanf("%99s", input);
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
    bool operation_success;
    printf("Enter a integer(1. ALL, 2. Kyber 3. Dilithium 4. SHA3 5. SHAKE )) ");
    scanf("%d", &input);

    switch (input){
        case 1:
            if(OQS_Kyber_All_test() == OQS_SUCCESS && OQS_dilithium_All_test() == OQS_SUCCESS && ISC_SHA3_All_test() == OQS_SUCCESS && ISC_SHAKE_All_test() == OQS_SUCCESS)
    
                return current_state = OPERATIONAL_MODE;
            else{
                printf("All Test Result Failed\n");
    
                sclear();
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
        case 100: //errorCode = 100
            printf("errorCode: %d\n\n", errorCode);
            break;      
        case 101: //errorCode = 100
            printf("errorCode: %d\n\n", errorCode);  
            break;   
        case 102: //errorCode = 100
            printf("errorCode: %d\n\n", errorCode);
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

