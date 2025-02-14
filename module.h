#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <oqs/oqs.h>
#include "tests/oqs_dilithium_test.h"
#include "tests/oqs_kyber_test.h"
#include "tests/oqs_sha3_test.h"
#include "include/IntegrityCheck.h"
#include "include/SelfTest.h"

typedef enum {
    POWER_ON,
    INITIALIZATION,
    INTEGRITY_CHECK,
    SELF_TEST,
    OPERATIONAL_MODE,
    ERROR_STATE
} State;

#define MESSAGE_LEN 50

State ISC_Poweron();

State ISC_Initialization();

State ISC_Integrity();

State ISC_Selftest();

State ISC_Operation();

State ISC_Error();

State run_fsm();
