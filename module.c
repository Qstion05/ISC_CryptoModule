#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <oqs/oqs.h>

#include "oqs_dilithium_test.h"
#include "oqs_kyber_test.h"
// 상태 정의
typedef enum {
    POWER_ON,            // 전원 켜짐
    INITIALIZATION,      // 초기화
    INTEGRITY_CHECK,     // 무결성 검사
    SELF_TEST,           // 자가시험
    OPERATIONAL_MODE,    // 동작모드(정상동작 상태)
    ERROR_STATE          // 에러 발생
} State;
#define MESSAGE_LEN 50




// 현재 상태를 저장하는 변수
State current_state = POWER_ON;
int errorCode = 0; // 0 = 정상 상태

// 상태 전이 함수들
State ISC_Poweron() {
    printf("State: POWER_ON\n");
    printf("Initializing system...\n");
    return current_state = INITIALIZATION;
}

State ISC_Initialization() {
    printf("State: INITIALIZATION\n");
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
        return current_state = ERROR_STATE;
    }
}

State ISC_Integrity() {
    printf("State: INTEGRITY_CHECK\n");
    // 무결성 검증 결과 (예제에서 무조건 성공으로 처리)
    bool check_success = true;
    char input[100];
    printf("Enter a string (type 'error' to error_mode: ) ");
    scanf("%99s", input);
    if (strcmp(input, "error") == 0) {
        check_success = false;  // "error"인 경우 false 반환
    } else {
        check_success = true;  // 그 외의 경우 true 반환
    }

    if (check_success) {
        printf("Integrity check passed.\n");
        return current_state = SELF_TEST;
    } else {
        printf("Integrity check failed.\n");
        errorCode = 101;
        return current_state = ERROR_STATE;
    }
}

State ISC_Selftest() {
    printf("State: SELF_TEST\n");
    // 자가 시험 결과 (예제에서 무조건 성공으로 처리)
    bool test_success = true;
    char input[100];
    printf("Enter a string (type 'error' to error_mode: ) ");
    scanf("%99s", input);
    if (strcmp(input, "error") == 0) {
        test_success = false;  // "error"인 경우 false 반환
    } else {
        test_success = true;  // 그 외의 경우 true 반환
    }

    if (test_success) {
        printf("Self-test passed.\n");
        return current_state = OPERATIONAL_MODE;
    } else {
        printf("Self-test failed.\n");
        errorCode = 102;
        return current_state = ERROR_STATE;
    }
}

State ISC_operation() {
    printf("State: OPERATIONAL_MODE\n");
    char input[100];
    bool operation_success;
    printf("Enter a string (type 'error' to error_mode: ) ");
    scanf("%99s", input);
    
    if (strcmp(input, "error") == 0) {
        operation_success = false;  // "error"인 경우 false 반환
    } else {
        operation_success = true;  // 그 외의 경우 true 반환
    }

    if (operation_success){   
        if (OQS_Kyber_768_test() == OQS_SUCCESS){
            printf("Kyber test succeeded.\n");
        } else {
            printf("Kyber test failed.\n");
        }
        return OPERATIONAL_MODE;
    } else {
        printf("Operation failed.\n");
        return current_state = ERROR_STATE;
    }
}

State ISC_error() {
    printf("State: ERROR_STATE\n");
    switch (errorCode){
        case 100: //errorCode = 100
            printf("errorCode: %d\n", errorCode);
            break;      
        case 101: //errorCode = 100
            printf("errorCode: %d\n", errorCode);  
            break;   
        case 102: //errorCode = 100
            printf("errorCode: %d\n", errorCode);
            break;
        default:
            printf("Unknown Error\n");    
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

