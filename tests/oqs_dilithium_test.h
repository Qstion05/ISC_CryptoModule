#ifndef OQS_DILITHIUM_TEST_H
#define OQS_DILITHIUM_TEST_H

#include <oqs/oqs.h>

#define MESSAGE_LEN 50

void cleanup_dilithium_stack(uint8_t *secret_key, size_t secret_key_len);
OQS_STATUS OQS_dilithium_All_test();
OQS_STATUS OQS_dilithium_2_test();
OQS_STATUS OQS_dilithium_3_test();
OQS_STATUS OQS_dilithium_5_test();
OQS_STATUS ISC_dilithium_select();

#endif // OQS_DILITHIUM_TEST_H
