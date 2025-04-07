#ifndef OQS_DILITHIUM_TEST_H
#define OQS_DILITHIUM_TEST_H

#include <oqs/oqs.h>

#define MESSAGE_LEN 50

void ISC_Dilithium_Cleanup(uint8_t *secret_key, size_t secret_key_len);
OQS_STATUS ISC_Dilithium_All();
OQS_STATUS ISC_Dilithium_2();
OQS_STATUS ISC_Dilithium_3();
OQS_STATUS ISC_Dilithium_5();
OQS_STATUS ISC_dilithium_select();

#endif // OQS_DILITHIUM_TEST_H
