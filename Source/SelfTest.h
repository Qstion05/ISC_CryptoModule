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

OQS_STATUS sha3_256_smt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS sha3_256_lmt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS sha3_256_mct_selftest(const char *req_filename, const char *rsp_filename);

OQS_STATUS sha3_512_smt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS sha3_512_lmt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS sha3_512_mct_selftest(const char *req_filename, const char *rsp_filename);

OQS_STATUS shake_128_smt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS shake_128_lmt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS shake_128_mct_selftest(const char *req_filename, const char *rsp_filename);

OQS_STATUS shake_256_smt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS shake_256_lmt_selftest(const char *req_filename, const char *rsp_filename);
OQS_STATUS shake_256_mct_selftest(const char *req_filename, const char *rsp_filename);

void generate_lmt_file(const char *filename);
void generate_smt_file(const char *filename);

void generate_sha3_mct_file(const char *filename, int seedbyte);
void generate_shake_mct_file(const char *filename, int seedbyte);

OQS_STATUS DilithiumKatTest();
OQS_STATUS KyberKatTest();
OQS_STATUS SHA3KatTest();
OQS_STATUS SHAKEKatTest();

void generate_dilithium_req_file(const char *filename, int count);
void generate_shake_req_file(const char *filename, int seedbyte);
#endif // SELF_TEST_H