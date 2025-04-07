#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <oqs/oqs.h>
#include "tests/oqs_dilithium_test.h"
#include "tests/oqs_kyber_test.h"
#include "tests/oqs_sha3_test.h"
#include "Source/IntegrityCheck.h"
#include "Source/SelfTest.h"

void sclear();  // 터미널 청소 함수

typedef enum {
    POWER_ON,
    INITIALIZATION,
    INTEGRITY_CHECK,
    SELF_TEST,
    OPERATIONAL_MODE,
    ERROR_STATE
} State;

#define MESSAGE_LEN 50

// 디버그 모드 전역 플래그
extern bool DEBUG_MODE;

// 디버그 출력 매크로
#define DEBUG_PRINT(fmt, ...) \
    do { if (DEBUG_MODE) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while (0)

State ISC_Poweron();
State ISC_Initialization();
State ISC_Integrity();
State ISC_Selftest();
State ISC_Operation();
State ISC_Error();
State run_fsm();
