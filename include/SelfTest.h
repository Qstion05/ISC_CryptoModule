#ifndef SELF_TEST_H
#define SELF_TEST_H

#include <oqs/oqs.h>

static void kat_randombytes(uint8_t *random_array, size_t bytes_to_read);

OQS_STATUS kyber_512_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS kyber_768_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS kyber_1024_selftest(const char *req_filename, const char *rsp_filename);

OQS_STATUS dilithium_2_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS dilithium_3_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS dilithium_5_selftest(const char *req_filename, const char *rsp_filename);

OQS_STATUS sha3_256_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS sha3_512_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS shake_128_selftest(const char *req_filename, const char *rsp_filename);

OQS_STATUS DilithiumKatTest();
OQS_STATUS KyberKatTest();

void generate_dilithium_req_file(const char *filename, int count);
void generate_sha3_req_file(const char *filename, int seedbyte);
void generate_shake_req_file(const char *filename, int seedbyte);
#endif // SELF_TEST_H