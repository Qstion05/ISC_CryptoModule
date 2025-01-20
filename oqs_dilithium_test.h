#ifndef OQS_DILITHIUM_TEST_H
#define OQS_DILITHIUM_TEST_H

#include <oqs/oqs.h>

#define MESSAGE_LEN 50

void cleanup_dilithium_stack(uint8_t *secret_key, size_t secret_key_len);

OQS_STATUS OQS_SIG_dilithium_2_test();

#endif // OQS_DILITHIUM_TEST_H
