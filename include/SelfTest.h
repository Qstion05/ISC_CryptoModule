#ifndef SELF_TEST_H
#define SELF_TEST_H

#include <oqs/oqs.h>

static void kat_randombytes(uint8_t *random_array, size_t bytes_to_read);

OQS_STATUS kyber_512_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS kyber_768_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS kyber_1024_selftest(const char *req_filename, const char *rsp_filename);

OQS_STATUS KyberKatTest();


#endif // SELF_TEST_H