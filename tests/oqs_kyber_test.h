#ifndef OQS_KYBER_TEST_H
#define OQS_KYBER_TEST_H

#include <oqs/oqs.h>

// Kyber 테스트 함수 선언
OQS_STATUS ISC_kyber_select();

OQS_STATUS ISC_Kyber_All();
OQS_STATUS ISC_Kyber_512();
OQS_STATUS ISC_Kyber_768();
OQS_STATUS ISC_Kyber_1024();

OQS_STATUS ISC_Kyber_512_Keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_STATUS ISC_Kyber_512_Encaps(uint8_t *ciphertext, uint8_t *shared_secret_e, uint8_t *public_key);
OQS_STATUS ISC_Kyber_512_Decaps(uint8_t *shared_secret_d, uint8_t *ciphertext, uint8_t *secret_key);


void ISC_Kyber_Cleanup(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

#endif // OQS_KYBER_TEST_H
