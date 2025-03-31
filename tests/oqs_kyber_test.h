#ifndef OQS_KYBER_TEST_H
#define OQS_KYBER_TEST_H

#include <oqs/oqs.h>

// Kyber 테스트 함수 선언
OQS_STATUS ISC_kyber_select();

OQS_STATUS OQS_Kyber_All_test();
OQS_STATUS OQS_Kyber_512_test();
OQS_STATUS OQS_Kyber_768_test();
OQS_STATUS OQS_Kyber_1024_test();

void cleanup_kyber_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

#endif // OQS_KYBER_TEST_H
