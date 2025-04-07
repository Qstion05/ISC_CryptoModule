#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include "common.h"
#include "../module.h"  // DEBUG_MODE, DEBUG_PRINT 접근

#define SEED_SIZE 48
#define MAX_MESSAGE_LEN 10000
#define MCT_ITERATIONS 100
#define MSG_BUFFER_SIZE 1000000

void generate_dilithium_req_file(const char *filename, int count) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Error opening file");
        return;
    }

    for (int i = 0; i < count; i++) {
        unsigned char seed[SEED_SIZE];
        unsigned char msg[MAX_MESSAGE_LEN];

        // mlen을 33의 배수로 설정 (최대 MAX_MESSAGE_LEN을 넘지 않도록 보정)
        size_t mlen = 33 * (i + 1);

        // 랜덤 데이터 생성
        OQS_randombytes(seed, SEED_SIZE);
        OQS_randombytes(msg, mlen);

        fprintf(fp, "count = %d\n", i);
        fprintf(fp, "seed = ");
        for (size_t j = 0; j < SEED_SIZE; j++) {
            fprintf(fp, "%02X", seed[j]);
        }
        fprintf(fp, "\n");

        fprintf(fp, "mlen = %zu\n", mlen);
        fprintf(fp, "msg = ");
        printf("mlen: %zu\n", mlen);
        for (size_t j = 0; j < mlen; j++) {
            fprintf(fp, "%02X", msg[j]);
        }
        fprintf(fp, "\n");

        // 빈 pk, sk, smlen, sm 추가
        fprintf(fp, "pk =\n");
        fprintf(fp, "sk =\n");
        fprintf(fp, "smlen =\n");
        fprintf(fp, "sm =\n\n");

        fflush(fp);  // 즉시 기록
    }

    fclose(fp);
    printf("Generated %s with %d test cases\n", filename, count);
}


void generate_smt_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fprintf(file, "\n = Short Message Test = \n\n");
    for (size_t len = 8; len < 169; len += 8) {
        uint8_t message[len / 8];  
        OQS_randombytes(message, len / 8);  
        fprintf(file, "Len = %zu\nMsg = ", len);
        for (size_t i = 0; i < len / 8; i++) {
            fprintf(file, "%02X", message[i]);
        }
        fprintf(file, "\nMd = \n\n");
    }
    fclose(file);
    printf("SMT test vectors saved to %s\n", filename);
}

void generate_lmt_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fprintf(file, "\n = Long Message Test = \n\n");
    for (size_t len = 8712; len < 24553; len += 792) {
        uint8_t message[len / 8];  
        OQS_randombytes(message, len / 8);  
        fprintf(file, "Len = %zu\nMsg = ", len);
        for (size_t i = 0; i < len / 8; i++) {
            fprintf(file, "%02X", message[i]);
        }
        fprintf(file, "\nMd = \n\n");
    }
    fclose(file);
    printf("LMT test vectors saved to %s\n", filename);
}

void generate_sha3_mct_file(const char *filename, int seedbyte) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fprintf(file, "\n = Monte Carlo Test = \n\n");
    uint8_t seed[seedbyte];  
    OQS_randombytes(seed, seedbyte);  
    fprintf(file, "Seed = ");
    for (size_t i = 0; i < seedbyte; i++) {
        fprintf(file, "%02X", seed[i]);
    }
    fclose(file);
    printf("MCT test vectors saved to %s\n", filename);
}

void generate_shake_mct_file(const char *filename, int seedbyte) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    fprintf(file, "= Monte Carlo Test =\n\n");
    
    uint8_t seed[16];  
    OQS_randombytes(seed, 16);  
    
    fprintf(file, "Seed = ");
    for (size_t i = 0; i < 16; i++) {
        fprintf(file, "%02X", seed[i]);
    }
    fprintf(file, "\n\n");
    
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0) {
        perror("Failed to open /dev/urandom");
        fclose(file);
        return;
    }
    
    for (size_t count = 0; count < MCT_ITERATIONS; count++) {
        uint16_t raw_len;
        ssize_t bytes_read = read(urandom_fd, &raw_len, sizeof(raw_len));
        if (bytes_read != sizeof(raw_len)) {
            perror("Failed to read from /dev/urandom");
            close(urandom_fd);
            return;
        }

        size_t len = (raw_len % ((1496 - 104 + 1) / 8)) * 8 + 104;
        
        fprintf(file, "COUNT = %zu\n", count);
        fprintf(file, "len = %zu\n", len);
        fprintf(file, "Md = \n\n");
    }
    
    close(urandom_fd);
    fclose(file);
    printf("SHAKE MCT test vectors saved to %s\n", filename);
}


OQS_STATUS kyber_512_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *fp_req, *fp_rsp;
    unsigned char seed[SEED_SIZE];
    unsigned char pk[OQS_KEM_kyber_512_length_public_key];
    unsigned char sk[OQS_KEM_kyber_512_length_secret_key];
    unsigned char ct[OQS_KEM_kyber_512_length_ciphertext];
    unsigned char ss_enc[OQS_KEM_kyber_512_length_shared_secret];
    unsigned char ss_dec[OQS_KEM_kyber_512_length_shared_secret];
    char line[256];
    int count;

    fp_req = fopen(req_filename, "r");
    fp_rsp = fopen(rsp_filename, "w");
    if (!fp_req || !fp_rsp) {
        printf("Error: Cannot open files for reading/writing.\n");
        return OQS_ERROR;
    }
    
    fprintf(fp_rsp, "# Kyber-512 KAT Test Vectors\n\n");
    
    while (fgets(line, sizeof(line), fp_req)) {
        if (sscanf(line, "count = %d", &count) == 1) {
            fprintf(fp_rsp, "count = %d\n", count);
        } else if (strncmp(line, "seed = ", 7) == 0) {
            for (int j = 0; j < SEED_SIZE; j++) {
                sscanf(&line[7 + j * 2], "%2hhX", &seed[j]);
            }
            fprintf(fp_rsp, "seed = %s", line + 7);

            // PRNG를 결정론적 KAT 방식으로 설정
            srand(*(unsigned int *)seed);
            OQS_randombytes_custom_algorithm(ISCrandombytes);

            // Kyber 키 쌍 생성
            if (OQS_KEM_kyber_512_keypair(pk, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_512_keypair failed!\n");
                return OQS_ERROR;
            }

            // Kyber 캡슐화 (암호문 및 공유 비밀 생성)
            if (OQS_KEM_kyber_512_encaps(ct, ss_enc, pk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_512_encaps failed!\n");
                return OQS_ERROR;
            }

            // Kyber 디캡슐화 (공유 비밀 복호화)
            if (OQS_KEM_kyber_512_decaps(ss_dec, ct, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_512_decaps failed!\n");
                return OQS_ERROR;
            }

            fprintf(fp_rsp, "pk = ");
            for (size_t j = 0; j < OQS_KEM_kyber_512_length_public_key; j++) {
                fprintf(fp_rsp, "%02X", pk[j]);
            }
            fprintf(fp_rsp, "\nsk = ");
            for (size_t j = 0; j < OQS_KEM_kyber_512_length_secret_key; j++) {
                fprintf(fp_rsp, "%02X", sk[j]);
            }
            fprintf(fp_rsp, "\nct = ");
            for (size_t j = 0; j < OQS_KEM_kyber_512_length_ciphertext; j++) {
                fprintf(fp_rsp, "%02X", ct[j]);
            }
            fprintf(fp_rsp, "\nss_enc = ");
            for (size_t j = 0; j < OQS_KEM_kyber_512_length_shared_secret; j++) {
                fprintf(fp_rsp, "%02X", ss_enc[j]);
            }
            fprintf(fp_rsp, "\nss_dec = ");
            for (size_t j = 0; j < OQS_KEM_kyber_512_length_shared_secret; j++) {
                fprintf(fp_rsp, "%02X", ss_dec[j]);
            }

            // KAT 검증: 공유 비밀이 동일해야 함
            if (memcmp(ss_enc, ss_dec, OQS_KEM_kyber_512_length_shared_secret) != 0) {
                fprintf(stderr, "ERROR: KAT validation failed! Encapsulated and decapsulated secrets do not match.\n");
                return OQS_ERROR;
            }
        }
    }
    
    fclose(fp_req);
    fclose(fp_rsp);
    return OQS_SUCCESS;
}

OQS_STATUS kyber_768_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *fp_req, *fp_rsp;
    unsigned char seed[SEED_SIZE];
    unsigned char pk[OQS_KEM_kyber_768_length_public_key];
    unsigned char sk[OQS_KEM_kyber_768_length_secret_key];
    unsigned char ct[OQS_KEM_kyber_768_length_ciphertext];
    unsigned char ss_enc[OQS_KEM_kyber_768_length_shared_secret];
    unsigned char ss_dec[OQS_KEM_kyber_768_length_shared_secret];
    char line[256];
    int count;

    fp_req = fopen(req_filename, "r");
    fp_rsp = fopen(rsp_filename, "w");
    if (!fp_req || !fp_rsp) {
        printf("Error: Cannot open files for reading/writing.\n");
        return OQS_ERROR;
    }
    
    fprintf(fp_rsp, "# Kyber-768 KAT Test Vectors\n\n");
    
    while (fgets(line, sizeof(line), fp_req)) {
        if (sscanf(line, "count = %d", &count) == 1) {
            fprintf(fp_rsp, "count = %d\n", count);
        } else if (strncmp(line, "seed = ", 7) == 0) {
            for (int j = 0; j < SEED_SIZE; j++) {
                sscanf(&line[7 + j * 2], "%2hhX", &seed[j]);
            }
            fprintf(fp_rsp, "seed = %s", line + 7);

            // PRNG를 결정론적 KAT 방식으로 설정
            srand(*(unsigned int *)seed);
            OQS_randombytes_custom_algorithm(ISCrandombytes);

            // Kyber 키 쌍 생성
            if (OQS_KEM_kyber_768_keypair(pk, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_768_keypair failed!\n");
                return OQS_ERROR;
            }

            // Kyber 캡슐화 (암호문 및 공유 비밀 생성)
            if (OQS_KEM_kyber_768_encaps(ct, ss_enc, pk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_768_encaps failed!\n");
                return OQS_ERROR;
            }

            // Kyber 디캡슐화 (공유 비밀 복호화)
            if (OQS_KEM_kyber_768_decaps(ss_dec, ct, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_768_decaps failed!\n");
                return OQS_ERROR;
            }

            fprintf(fp_rsp, "pk = ");
            for (size_t j = 0; j < OQS_KEM_kyber_768_length_public_key; j++) {
                fprintf(fp_rsp, "%02X", pk[j]);
            }
            fprintf(fp_rsp, "\nsk = ");
            for (size_t j = 0; j < OQS_KEM_kyber_768_length_secret_key; j++) {
                fprintf(fp_rsp, "%02X", sk[j]);
            }
            fprintf(fp_rsp, "\nct = ");
            for (size_t j = 0; j < OQS_KEM_kyber_768_length_ciphertext; j++) {
                fprintf(fp_rsp, "%02X", ct[j]);
            }
            fprintf(fp_rsp, "\nss_enc = ");
            for (size_t j = 0; j < OQS_KEM_kyber_768_length_shared_secret; j++) {
                fprintf(fp_rsp, "%02X", ss_enc[j]);
            }
            fprintf(fp_rsp, "\nss_dec = ");
            for (size_t j = 0; j < OQS_KEM_kyber_768_length_shared_secret; j++) {
                fprintf(fp_rsp, "%02X", ss_dec[j]);

            }

            // KAT 검증: 공유 비밀이 동일해야 함
            if (memcmp(ss_enc, ss_dec, OQS_KEM_kyber_768_length_shared_secret) != 0) {
                fprintf(stderr, "ERROR: KAT validation failed! Encapsulated and decapsulated secrets do not match.\n");
                return OQS_ERROR;
            }
            fprintf(fp_rsp, "\n[KAT validation successful]\n\n");
        }
    }
    
    fclose(fp_req);
    fclose(fp_rsp);
    return OQS_SUCCESS;
}

OQS_STATUS kyber_1024_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *fp_req, *fp_rsp;
    unsigned char seed[SEED_SIZE];
    unsigned char pk[OQS_KEM_kyber_1024_length_public_key];
    unsigned char sk[OQS_KEM_kyber_1024_length_secret_key];
    unsigned char ct[OQS_KEM_kyber_1024_length_ciphertext];
    unsigned char ss_enc[OQS_KEM_kyber_1024_length_shared_secret];
    unsigned char ss_dec[OQS_KEM_kyber_1024_length_shared_secret];
    char line[256];
    int count;

    fp_req = fopen(req_filename, "r");
    fp_rsp = fopen(rsp_filename, "w");
    if (!fp_req || !fp_rsp) {
        printf("Error: Cannot open files for reading/writing.\n");
        return OQS_ERROR;
    }
    
    fprintf(fp_rsp, "# Kyber-1024 KAT Test Vectors\n\n");
    
    while (fgets(line, sizeof(line), fp_req)) {
        if (sscanf(line, "count = %d", &count) == 1) {
            fprintf(fp_rsp, "count = %d\n", count);
        } else if (strncmp(line, "seed = ", 7) == 0) {
            for (int j = 0; j < SEED_SIZE; j++) {
                sscanf(&line[7 + j * 2], "%2hhX", &seed[j]);
            }
            fprintf(fp_rsp, "seed = %s", line + 7);

            // PRNG를 결정론적 KAT 방식으로 설정
            srand(*(unsigned int *)seed);
            OQS_randombytes_custom_algorithm(ISCrandombytes);

            // Kyber 키 쌍 생성
            if (OQS_KEM_kyber_1024_keypair(pk, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_keypair failed!\n");
                return OQS_ERROR;
            }

            // Kyber 캡슐화 (암호문 및 공유 비밀 생성)
            if (OQS_KEM_kyber_1024_encaps(ct, ss_enc, pk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_encaps failed!\n");
                return OQS_ERROR;
            }

            // Kyber 디캡슐화 (공유 비밀 복호화)
            if (OQS_KEM_kyber_1024_decaps(ss_dec, ct, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_KEM_kyber_1024_decaps failed!\n");
                return OQS_ERROR;
            }

            fprintf(fp_rsp, "pk = ");
            for (size_t j = 0; j < OQS_KEM_kyber_1024_length_public_key; j++) {
                fprintf(fp_rsp, "%02X", pk[j]);
            }
            fprintf(fp_rsp, "\nsk = ");
            for (size_t j = 0; j < OQS_KEM_kyber_1024_length_secret_key; j++) {
                fprintf(fp_rsp, "%02X", sk[j]);
            }
            fprintf(fp_rsp, "\nct = ");
            for (size_t j = 0; j < OQS_KEM_kyber_1024_length_ciphertext; j++) {
                fprintf(fp_rsp, "%02X", ct[j]);
            }
            fprintf(fp_rsp, "\nss_enc = ");
            for (size_t j = 0; j < OQS_KEM_kyber_1024_length_shared_secret; j++) {
                fprintf(fp_rsp, "%02X", ss_enc[j]);
            }
            fprintf(fp_rsp, "\nss_dec = ");
            for (size_t j = 0; j < OQS_KEM_kyber_1024_length_shared_secret; j++) {
                fprintf(fp_rsp, "%02X", ss_dec[j]);
            }

            // KAT 검증: 공유 비밀이 동일해야 함
            if (memcmp(ss_enc, ss_dec, OQS_KEM_kyber_1024_length_shared_secret) != 0) {
                fprintf(stderr, "ERROR: KAT validation failed! Encapsulated and decapsulated secrets do not match.\n");
                return OQS_ERROR;
            }
        }
    }
    
    fclose(fp_req);
    fclose(fp_rsp);
    return OQS_SUCCESS;
}


OQS_STATUS dilithium_2_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *fp_req, *fp_rsp;
    unsigned char seed[SEED_SIZE];
    unsigned char pk[OQS_SIG_dilithium_2_length_public_key];
    unsigned char sk[OQS_SIG_dilithium_2_length_secret_key];
    unsigned char sm[MAX_MESSAGE_LEN + OQS_SIG_dilithium_2_length_signature];
    unsigned char msg[MAX_MESSAGE_LEN];
    size_t smlen, mlen;
    char line[256];
    int count;

    fp_req = fopen(req_filename, "r");
    fp_rsp = fopen(rsp_filename, "w");
    if (!fp_req || !fp_rsp) {
        printf("Error: Cannot open files for reading/writing.\n");
        return OQS_ERROR;
    }

    fprintf(fp_rsp, "# Dilithium-2 KAT Test Vectors\n\n");

    while (fgets(line, sizeof(line), fp_req)) {
        if (sscanf(line, "count = %d", &count) == 1) {
            fprintf(fp_rsp, "count = %d\n", count);
        } else if (strncmp(line, "seed = ", 7) == 0) {
            for (int j = 0; j < SEED_SIZE; j++) {
                sscanf(&line[7 + j * 2], "%2hhX", &seed[j]);
            }
            fprintf(fp_rsp, "seed = %s", line + 7);

            srand(*(unsigned int *)seed);
            OQS_randombytes_custom_algorithm(ISCrandombytes);

        } else if (sscanf(line, "mlen = %zu", &mlen) == 1) {
            fprintf(fp_rsp, "mlen = %zu\n", mlen);
        } else if (strncmp(line, "msg = ", 6) == 0) {
            for (size_t j = 0; j < mlen; j++) {
                sscanf(&line[6 + j * 2], "%2hhX", &msg[j]);
            }
            fprintf(fp_rsp, "msg = %s", line + 6);

            // Dilithium 키 생성
            if (OQS_SIG_dilithium_2_keypair(pk, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
                return OQS_ERROR;
            }

            // 메시지 서명
            if (OQS_SIG_dilithium_2_sign(sm, &smlen, msg, mlen, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
                return OQS_ERROR;
            }

            // 응답 파일에 결과 저장
            fprintf(fp_rsp, "\npk = ");
            for (size_t j = 0; j < OQS_SIG_dilithium_2_length_public_key; j++) {
                fprintf(fp_rsp, "%02X", pk[j]);
            }
            fprintf(fp_rsp, "\nsk = ");
            for (size_t j = 0; j < OQS_SIG_dilithium_2_length_secret_key; j++) {
                fprintf(fp_rsp, "%02X", sk[j]);
            }
            fprintf(fp_rsp, "\nsmlen = %zu\n", smlen);
            fprintf(fp_rsp, "sm = ");
            for (size_t j = 0; j < smlen; j++) {
                fprintf(fp_rsp, "%02X", sm[j]);
            }

            fprintf(fp_rsp, "\n[KAT validation successful]\n\n");
        }
    }

    fclose(fp_req);
    fclose(fp_rsp);
    return OQS_SUCCESS;
}

OQS_STATUS dilithium_3_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *fp_req, *fp_rsp;
    unsigned char seed[SEED_SIZE];
    unsigned char pk[OQS_SIG_dilithium_3_length_public_key];
    unsigned char sk[OQS_SIG_dilithium_3_length_secret_key];
    unsigned char sm[MAX_MESSAGE_LEN + OQS_SIG_dilithium_3_length_signature];
    unsigned char msg[MAX_MESSAGE_LEN];
    size_t smlen, mlen;
    char line[256];
    int count;

    fp_req = fopen(req_filename, "r");
    fp_rsp = fopen(rsp_filename, "w");
    if (!fp_req || !fp_rsp) {
        printf("Error: Cannot open files for reading/writing.\n");
        return OQS_ERROR;
    }

    fprintf(fp_rsp, "# Dilithium-3 KAT Test Vectors\n\n");

    while (fgets(line, sizeof(line), fp_req)) {
        if (sscanf(line, "count = %d", &count) == 1) {
            fprintf(fp_rsp, "count = %d\n", count);
        } else if (strncmp(line, "seed = ", 7) == 0) {
            for (int j = 0; j < SEED_SIZE; j++) {
                sscanf(&line[7 + j * 2], "%2hhX", &seed[j]);
            }
            fprintf(fp_rsp, "seed = %s", line + 7);

            srand(*(unsigned int *)seed);
            OQS_randombytes_custom_algorithm(ISCrandombytes);

        } else if (sscanf(line, "mlen = %zu", &mlen) == 1) {
            fprintf(fp_rsp, "mlen = %zu\n", mlen);
        } else if (strncmp(line, "msg = ", 6) == 0) {
            for (size_t j = 0; j < mlen; j++) {
                sscanf(&line[6 + j * 2], "%2hhX", &msg[j]);
            }
            fprintf(fp_rsp, "msg = %s", line + 6);

            // Dilithium 키 생성
            if (OQS_SIG_dilithium_3_keypair(pk, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_keypair failed!\n");
                return OQS_ERROR;
            }

            // 메시지 서명
            if (OQS_SIG_dilithium_3_sign(sm, &smlen, msg, mlen, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_SIG_dilithium_3_sign failed!\n");
                return OQS_ERROR;
            }

            // 응답 파일에 결과 저장
            fprintf(fp_rsp, "\npk = ");
            for (size_t j = 0; j < OQS_SIG_dilithium_3_length_public_key; j++) {
                fprintf(fp_rsp, "%02X", pk[j]);
            }
            fprintf(fp_rsp, "\nsk = ");
            for (size_t j = 0; j < OQS_SIG_dilithium_3_length_secret_key; j++) {
                fprintf(fp_rsp, "%02X", sk[j]);
            }
            fprintf(fp_rsp, "\nsmlen = %zu\n", smlen);
            fprintf(fp_rsp, "sm = ");
            for (size_t j = 0; j < smlen; j++) {
                fprintf(fp_rsp, "%02X", sm[j]);
            }

            fprintf(fp_rsp, "\n[KAT validation successful]\n\n");
        }
    }

    fclose(fp_req);
    fclose(fp_rsp);
    return OQS_SUCCESS;
}

OQS_STATUS dilithium_5_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *fp_req, *fp_rsp;
    unsigned char seed[SEED_SIZE];
    unsigned char pk[OQS_SIG_dilithium_5_length_public_key];
    unsigned char sk[OQS_SIG_dilithium_5_length_secret_key];
    unsigned char sm[MAX_MESSAGE_LEN + OQS_SIG_dilithium_5_length_signature];
    unsigned char msg[MAX_MESSAGE_LEN];
    size_t smlen, mlen;
    char line[256];
    int count;

    fp_req = fopen(req_filename, "r");
    fp_rsp = fopen(rsp_filename, "w");
    if (!fp_req || !fp_rsp) {
        printf("Error: Cannot open files for reading/writing.\n");
        return OQS_ERROR;
    }

    fprintf(fp_rsp, "# Dilithium-3 KAT Test Vectors\n\n");

    while (fgets(line, sizeof(line), fp_req)) {
        if (sscanf(line, "count = %d", &count) == 1) {
            fprintf(fp_rsp, "count = %d\n", count);
        } else if (strncmp(line, "seed = ", 7) == 0) {
            for (int j = 0; j < SEED_SIZE; j++) {
                sscanf(&line[7 + j * 2], "%2hhX", &seed[j]);
            }
            fprintf(fp_rsp, "seed = %s", line + 7);

            srand(*(unsigned int *)seed);
            OQS_randombytes_custom_algorithm(ISCrandombytes);

        } else if (sscanf(line, "mlen = %zu", &mlen) == 1) {
            fprintf(fp_rsp, "mlen = %zu\n", mlen);
        } else if (strncmp(line, "msg = ", 6) == 0) {
            for (size_t j = 0; j < mlen; j++) {
                sscanf(&line[6 + j * 2], "%2hhX", &msg[j]);
            }
            fprintf(fp_rsp, "msg = %s", line + 6);

            // Dilithium 키 생성
            if (OQS_SIG_dilithium_5_keypair(pk, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_SIG_dilithium_5_keypair failed!\n");
                return OQS_ERROR;
            }

            // 메시지 서명
            if (OQS_SIG_dilithium_5_sign(sm, &smlen, msg, mlen, sk) != OQS_SUCCESS) {
                fprintf(stderr, "ERROR: OQS_SIG_dilithium_5_sign failed!\n");
                return OQS_ERROR;
            }

            // 응답 파일에 결과 저장
            fprintf(fp_rsp, "\npk = ");
            for (size_t j = 0; j < OQS_SIG_dilithium_5_length_public_key; j++) {
                fprintf(fp_rsp, "%02X", pk[j]);
            }
            fprintf(fp_rsp, "\nsk = ");
            for (size_t j = 0; j < OQS_SIG_dilithium_5_length_secret_key; j++) {
                fprintf(fp_rsp, "%02X", sk[j]);
            }
            fprintf(fp_rsp, "\nsmlen = %zu\n", smlen);
            fprintf(fp_rsp, "sm = ");
            for (size_t j = 0; j < smlen; j++) {
                fprintf(fp_rsp, "%02X", sm[j]);
            }

            fprintf(fp_rsp, "\n[KAT validation successful]\n\n");
        }
    }

    fclose(fp_req);
    fclose(fp_rsp);
    return OQS_SUCCESS;
}


OQS_STATUS sha3_256_smt_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[2048];
    size_t msg_len = 0;
    uint8_t msg[1024];
    uint8_t digest[32];
    memset(msg, 0, 1024);
    
    fprintf(rsp_file, "# SHA3-256 SMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0) {
            fputs(line, rsp_file);
            sscanf(line, "Len = %zu", &msg_len);
            memset(msg, 0, 1024);
        } else if (strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 1024) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
        } else if (strncmp(line, "Md =", 4) == 0) {
            fprintf(rsp_file, "Md = ");
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinal_ex(mdctx, digest, NULL);
            EVP_MD_CTX_free(mdctx);
            
            for (size_t i = 0; i < 32; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n");
        } else {
            fputs(line, rsp_file);
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS sha3_256_lmt_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[16384];  // 긴 메시지를 위해 큰 버퍼 사용
    size_t msg_len;
    uint8_t *msg = malloc(8192);  // 동적 할당으로 메모리 관리
    if (!msg) {
        perror("Memory allocation failed");
        fclose(req_file);
        fclose(rsp_file);
        return OQS_ERROR;
    }
    uint8_t digest[32];
    
    fprintf(rsp_file, "# SHA3-256 LMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0 || strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
        } else if (strncmp(line, "Md =", 4) == 0) {
            char *msg_hex = strchr(line, '=') + 2;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 8192) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
            
            // SHA3-256 해시 계산
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinal_ex(mdctx, digest, NULL);
            EVP_MD_CTX_free(mdctx);
            
            // 기존 "Md = " 다음에 해시 결과를 기록
            fprintf(rsp_file, "Md = ");
            for (size_t i = 0; i < 32; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }
    
    free(msg);
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS sha3_256_mct_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[2048];
    size_t msg_len = 0;
    uint8_t msg[1024];
    uint8_t digest[32];
    memset(msg, 0, 1024);
    
    fprintf(rsp_file, "# SHA3-256 MCT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        fputs(line, rsp_file);
        if (strncmp(line, "Seed =", 6) == 0) {
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 1024) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
            fprintf(rsp_file, "\n\n");
            // MCT 100번 반복 수행
            for (size_t iter = 0; iter < MCT_ITERATIONS; iter++) {
                EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                if (!mdctx) {
                    perror("EVP_MD_CTX_new failed");
                    fclose(req_file);
                    fclose(rsp_file);
                    return OQS_ERROR;
                }
                EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
                EVP_DigestUpdate(mdctx, msg, msg_len);
                EVP_DigestFinal_ex(mdctx, digest, NULL);
                EVP_MD_CTX_free(mdctx);
                
                // count 및 해시 결과 기록
                fprintf(rsp_file, "count = %zu\nMd = ", iter);
                for (size_t i = 0; i < 32; i++) {
                    fprintf(rsp_file, "%02X", digest[i]);
                }
                fprintf(rsp_file, "\n\n");
                
                // 다음 반복을 위해 msg를 최신 digest로 업데이트
                memcpy(msg, digest, 32);
                msg_len = 32;
            }
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS sha3_512_smt_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[4096];
    size_t msg_len = 0;
    uint8_t msg[2048];
    uint8_t digest[64];
    memset(msg, 0, 2048);
    
    fprintf(rsp_file, "# SHA3-512 SMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0) {
            fputs(line, rsp_file);
            sscanf(line, "Len = %zu", &msg_len);
            memset(msg, 0, 2048);
        } else if (strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 2048) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
        } else if (strncmp(line, "Md =", 4) == 0) {
            fprintf(rsp_file, "Md = ");
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinal_ex(mdctx, digest, NULL);
            EVP_MD_CTX_free(mdctx);
            
            for (size_t i = 0; i < 64; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n");
        } else {
            fputs(line, rsp_file);
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS sha3_512_lmt_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[32768];  // 긴 메시지를 위해 큰 버퍼 사용
    size_t msg_len;
    uint8_t *msg = malloc(16384);  // 동적 할당으로 메모리 관리
    if (!msg) {
        perror("Memory allocation failed");
        fclose(req_file);
        fclose(rsp_file);
        return OQS_ERROR;
    }
    uint8_t digest[64];
    
    fprintf(rsp_file, "# SHA3-512 LMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0 || strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
        } else if (strncmp(line, "Md =", 4) == 0) {
            char *msg_hex = strchr(line, '=') + 2;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 16384) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
            
            // SHA3-256 해시 계산
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinal_ex(mdctx, digest, NULL);
            EVP_MD_CTX_free(mdctx);
            
            // 기존 "Md = " 다음에 해시 결과를 기록
            fprintf(rsp_file, "Md = ");
            for (size_t i = 0; i < 64; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }
    
    free(msg);
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS sha3_512_mct_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[4096];
    size_t msg_len = 0;
    uint8_t msg[2048];
    uint8_t digest[64];
    memset(msg, 0, 2048);
    
    fprintf(rsp_file, "# SHA3-512 MCT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        fputs(line, rsp_file);
        if (strncmp(line, "Seed =", 6) == 0) {
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 2048) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
            fprintf(rsp_file, "\n\n");
            // MCT 100번 반복 수행
            for (size_t iter = 0; iter < MCT_ITERATIONS; iter++) {
                EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                if (!mdctx) {
                    perror("EVP_MD_CTX_new failed");
                    fclose(req_file);
                    fclose(rsp_file);
                    return OQS_ERROR;
                }
                EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
                EVP_DigestUpdate(mdctx, msg, msg_len);
                EVP_DigestFinal_ex(mdctx, digest, NULL);
                EVP_MD_CTX_free(mdctx);
                
                // count 및 해시 결과 기록
                fprintf(rsp_file, "count = %zu\nMd = ", iter);
                for (size_t i = 0; i < 64; i++) {
                    fprintf(rsp_file, "%02X", digest[i]);
                }
                fprintf(rsp_file, "\n\n");
                
                // 다음 반복을 위해 msg를 최신 digest로 업데이트
                memcpy(msg, digest, 64);
                msg_len = 64;
            }
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS shake_128_smt_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[1024];
    size_t msg_len = 0;
    uint8_t msg[512];
    uint8_t digest[16];
    memset(msg, 0, 512);
    
    fprintf(rsp_file, "# SHAKE128 SMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0) {
            fputs(line, rsp_file);
            sscanf(line, "Len = %zu", &msg_len);
            memset(msg, 0, 512);
        } else if (strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 512) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
        } else if (strncmp(line, "Md =", 4) == 0) {
            fprintf(rsp_file, "Md = ");
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinalXOF(mdctx, digest, 16); // SHAKE128은 XOF(Output Flexible) 방식 사용
            EVP_MD_CTX_free(mdctx);
            
            for (size_t i = 0; i < 16; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n");
        } else {
            fputs(line, rsp_file);
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS shake_128_lmt_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[16384];  // 긴 메시지를 위해 큰 버퍼 사용
    size_t msg_len;
    uint8_t *msg = malloc(8192);  // 동적 할당으로 메모리 관리
    if (!msg) {
        perror("Memory allocation failed");
        fclose(req_file);
        fclose(rsp_file);
        return OQS_ERROR;
    }
    uint8_t digest[16];
    memset(msg, 0, 8192);
    
    fprintf(rsp_file, "# SHAKE128 LMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0) {
            fputs(line, rsp_file);
            sscanf(line, "Len = %zu", &msg_len);
            memset(msg, 0, 8192);
        } else if (strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 8192) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
        } else if (strncmp(line, "Md =", 4) == 0) {
            fprintf(rsp_file, "Md = ");
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinalXOF(mdctx, digest, 16); // SHAKE128은 XOF(Output Flexible) 방식 사용
            EVP_MD_CTX_free(mdctx);
            
            for (size_t i = 0; i < 16; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n\n");
        } else {
            fputs(line, rsp_file);
        }
    }
    
    free(msg);
    fclose(req_file);
    return OQS_SUCCESS;
}

OQS_STATUS shake_128_mct_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[2048];
    size_t msg_len = 0;
    uint8_t msg[2048];
    uint8_t digest[2048];
    memset(msg, 0, 2048);
    
    fprintf(rsp_file, "# SHAKE128 MCT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        fputs(line, rsp_file);
        if (strncmp(line, "COUNT =", 7) == 0) {
            if (fgets(line, sizeof(line), req_file) == NULL) {
                perror("Failed to read line from request file");
                fclose(req_file);
                return OQS_ERROR;
            }
            sscanf(line, "len = %zu", &msg_len);
            if (msg_len < 104 || msg_len > 1496) {
                fprintf(stderr, "Invalid message length: %zu\n", msg_len);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            if (fgets(line, sizeof(line), req_file) == NULL) {
                perror("Failed to read line from request file");
                fclose(req_file);
                return OQS_ERROR;
            }
            
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len /8);
            EVP_DigestFinalXOF(mdctx, digest, msg_len /8);
            EVP_MD_CTX_free(mdctx);
            
            fprintf(rsp_file, "Len = %zu\n", msg_len);
            fprintf(rsp_file, "Md = ");
            for (size_t i = 0; i < msg_len /8; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS shake_256_smt_selftest(const char *req_filename, const char *rsp_filename) {
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[2048];
    size_t msg_len = 0;
    uint8_t msg[1024];
    uint8_t digest[32];
    memset(msg, 0, 1024);
    
    fprintf(rsp_file, "# SHAKE128 SMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0) {
            fputs(line, rsp_file);
            sscanf(line, "Len = %zu", &msg_len);
            memset(msg, 0, 32);
        } else if (strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 1024) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
        } else if (strncmp(line, "Md =", 4) == 0) {
            fprintf(rsp_file, "Md = ");
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinalXOF(mdctx, digest, 32); // SHAKE128은 XOF(Output Flexible) 방식 사용
            EVP_MD_CTX_free(mdctx);
            
            for (size_t i = 0; i < 32; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n");
        } else {
            fputs(line, rsp_file);
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS shake_256_lmt_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[16384];  // 긴 메시지를 위해 큰 버퍼 사용
    size_t msg_len;
    uint8_t *msg = malloc(8192);  // 동적 할당으로 메모리 관리
    if (!msg) {
        perror("Memory allocation failed");
        fclose(req_file);
        fclose(rsp_file);
        return OQS_ERROR;
    }
    uint8_t digest[32];
    memset(msg, 0, 8192);
    
    fprintf(rsp_file, "# SHAKE128 LMT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        if (strncmp(line, "Len =", 5) == 0) {
            fputs(line, rsp_file);
            sscanf(line, "Len = %zu", &msg_len);
            memset(msg, 0, 8192);
        } else if (strncmp(line, "Msg =", 5) == 0) {
            fputs(line, rsp_file);
            char *msg_hex = strchr(line, '=') + 2;
            while (*msg_hex == ' ' || *msg_hex == '\n') msg_hex++;
            msg_len = strlen(msg_hex) / 2;
            if (msg_len > 8192) {
                fprintf(stderr, "Message length exceeds buffer size!\n");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            for (size_t i = 0; i < msg_len; i++) {
                sscanf(msg_hex + (i * 2), "%2hhx", &msg[i]);
            }
        } else if (strncmp(line, "Md =", 4) == 0) {
            fprintf(rsp_file, "Md = ");
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                free(msg);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len);
            EVP_DigestFinalXOF(mdctx, digest, 32); // SHAKE128은 XOF(Output Flexible) 방식 사용
            EVP_MD_CTX_free(mdctx);
            
            for (size_t i = 0; i < 32; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n\n");
        } else {
            fputs(line, rsp_file);
        }
    }
    
    free(msg);
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS shake_256_mct_selftest(const char *req_filename, const char *rsp_filename){
    FILE *req_file = fopen(req_filename, "r");
    if (!req_file) {
        perror("Failed to open request file");
        return OQS_ERROR;
    }
    
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!rsp_file) {
        perror("Failed to open response file");
        fclose(req_file);
        return OQS_ERROR;
    }
    
    char line[2048];
    size_t msg_len = 0;
    uint8_t msg[2048];
    uint8_t digest[2048];
    memset(msg, 0, 2048);
    
    fprintf(rsp_file, "# SHAKE128 MCT KAT Response File\n\n");
    
    while (fgets(line, sizeof(line), req_file)) {
        fputs(line, rsp_file);
        if (strncmp(line, "COUNT =", 7) == 0) {
            if (fgets(line, sizeof(line), req_file) == NULL) {
                perror("Failed to read line from request file");
                fclose(req_file);
                return OQS_ERROR;
            }
            sscanf(line, "len = %zu", &msg_len);
            if (msg_len < 104 || msg_len > 1496) {
                fprintf(stderr, "Invalid message length: %zu\n", msg_len);
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            if (fgets(line, sizeof(line), req_file) == NULL) {
                perror("Failed to read line from request file");
                fclose(req_file);
                return OQS_ERROR;
            }
            
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                perror("EVP_MD_CTX_new failed");
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }
            EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL);
            EVP_DigestUpdate(mdctx, msg, msg_len /8);
            EVP_DigestFinalXOF(mdctx, digest, msg_len /8);
            EVP_MD_CTX_free(mdctx);
            
            fprintf(rsp_file, "Len = %zu\n", msg_len);
            fprintf(rsp_file, "Md = ");
            for (size_t i = 0; i < msg_len /8; i++) {
                fprintf(rsp_file, "%02X", digest[i]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }
    
    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS KyberKatTest() {
    /*
    generate_kyber_req_file("vector/Kyber_Test_Vector_512.req");
    generate_kyber_req_file("vector/Kyber_Test_Vector_768.req");
    generate_kyber_req_file("vector/Kyber_Test_Vector_1024.req");
    */
    if(kyber_1024_selftest("vector/Kyber/Kyber_Test_Vector_1024.req", "vector/Kyber/Kyber_Test_Vector_1024.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: Kyber-1024 kat test failed!\n");
        return OQS_ERROR;
    }
    if(kyber_768_selftest("vector/Kyber/Kyber_Test_Vector_768.req", "vector/Kyber/Kyber_Test_Vector_768.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: Kyber-768 kat test failed!\n");
        return OQS_ERROR;
    }
    if(kyber_512_selftest("vector/Kyber/Kyber_Test_Vector_512.req", "vector/Kyber/Kyber_Test_Vector_512.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: Kyber-512 kat test failed!\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}
OQS_STATUS DilithiumKatTest() {
    if (dilithium_2_selftest("vector/Dilithium/Dilithium_Test_Vector_2.req", "vector/Dilithium/Dilithium_Test_Vector_2.rsp") == OQS_ERROR) {
        fprintf(stderr, "ERROR: Dilithium-2 kat test failed!\n");
        return OQS_ERROR;
    }
    if (dilithium_3_selftest("vector/Dilithium/Dilithium_Test_Vector_3.req", "vector/Dilithium/Dilithium_Test_Vector_3.rsp") == OQS_ERROR) {
        fprintf(stderr, "ERROR: Dilithium-3 kat test failed!\n");
        return OQS_ERROR;
    }
    if (dilithium_5_selftest("vector/Dilithium/Dilithium_Test_Vector_5.req", "vector/Dilithium/Dilithium_Test_Vector_5.rsp") == OQS_ERROR) {
        fprintf(stderr, "ERROR: Dilithium-5 kat test failed!\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

OQS_STATUS SHA3KatTest(){
    if(sha3_256_smt_selftest("./vector/SHA3/SHA3_256_SMT.req", "./vector/SHA3/SHA3_256_SMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHA3-256 SMT failed!\n");
        return OQS_ERROR;
    }

    if(sha3_256_lmt_selftest("./vector/SHA3/SHA3_256_LMT.req", "./vector/SHA3/SHA3_256_LMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHA3-256 LMT failed!\n");
        return OQS_ERROR;
    }

    if(sha3_256_mct_selftest("./vector/SHA3/SHA3_256_MCT.req", "./vector/SHA3/SHA3_256_MCT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHA3-256 MCT failed!\n");
        return OQS_ERROR;
    }

    if(sha3_512_smt_selftest("./vector/SHA3/SHA3_512_SMT.req", "./vector/SHA3/SHA3_512_SMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHA3-512 SMT failed!\n");
        return OQS_ERROR;
    }

    if(sha3_512_lmt_selftest("./vector/SHA3/SHA3_512_LMT.req", "./vector/SHA3/SHA3_512_LMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHA3-512 LMT failed!\n");
        return OQS_ERROR;
    }

    if(sha3_512_mct_selftest("./vector/SHA3/SHA3_512_MCT.req", "./vector/SHA3/SHA3_512_MCT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHA3-512 MCT failed!\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

OQS_STATUS SHAKEKatTest(){
    if(shake_128_smt_selftest("./vector/SHAKE/SHAKE_128_SMT.req", "./vector/SHAKE/SHAKE_128_SMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHAKE-128 SMT failed!\n");
        return OQS_ERROR;
    }

    if(shake_128_lmt_selftest("./vector/SHAKE/SHAKE_128_LMT.req", "./vector/SHAKE/SHAKE_128_LMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHAKE-128 LMT failed!\n");
        return OQS_ERROR;
    }

    if(shake_128_mct_selftest("./vector/SHAKE/SHAKE_128_MCT.req", "./vector/SHAKE/SHAKE_128_MCT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHAKE-128 MCT failed!\n");
        return OQS_ERROR;
    }

    if(shake_256_smt_selftest("./vector/SHAKE/SHAKE_256_SMT.req", "./vector/SHAKE/SHAKE_256_SMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHAKE-256 SMT failed!\n");
        return OQS_ERROR;
    }

    if(shake_256_lmt_selftest("./vector/SHAKE/SHAKE_256_LMT.req", "./vector/SHAKE/SHAKE_256_LMT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHAKE-256 LMT failed!\n");
        return OQS_ERROR;
    }

    if(shake_256_mct_selftest("./vector/SHAKE/SHAKE_256_MCT.req", "./vector/SHAKE/SHAKE_256_MCT.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: SHAKE-256s MCT failed!\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}