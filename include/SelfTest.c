#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>

#define SEED_SIZE 48
#define MAX_MESSAGE_LEN 10000
#define MCT_ITERATIONS 1000
#define MSG_BUFFER_SIZE 1000000

static void kat_randombytes(uint8_t *random_array, size_t bytes_to_read) {
    static unsigned int seed_offset = 0;
    for (size_t i = 0; i < bytes_to_read; i++) {
        random_array[i] = (uint8_t)(rand() % 256);
    }
    seed_offset += bytes_to_read;
}

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

void generate_sha3_req_file(const char *filename, int seedbyte) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    //SMT
    fprintf(file, "\n = Short Message Test = \n\n");
    for (size_t len = 8; len < 169; len += 8) {
        uint8_t message[len / 8];  // 비트 단위이므로 바이트 크기로 변환
        OQS_randombytes(message, len / 8);  // OQS 랜덤 함수 사용
        fprintf(file, "Len = %zu\nMsg = ", len);
        for (size_t i = 0; i < len / 8; i++) {
            fprintf(file, "%02X", message[i]);
            }
        fprintf(file, "\n Md = \n\n");
    }
    
    //LMT
    fprintf(file, "\n = Long Message Test = \n\n");
    for (size_t len = 8712; len < 24553; len += 792) {
        uint8_t message[len / 8];  // 비트 단위이므로 바이트 크기로 변환
        OQS_randombytes(message, len / 8);  // OQS 랜덤 함수 사용
        // 벡터 파일 작성
        fprintf(file, "Len = %zu\nMsg = ", len);
        for (size_t i = 0; i < len / 8; i++) {
                fprintf(file, "%02X", message[i]);
            }
        fprintf(file, "\nMd = \n\n");
    }

    //MCT
    fprintf(file, "\n = Monte Carlo Test = \n\n");
    uint8_t seed[seedbyte];  // seedbyte바이트 크기의 시드 생성
    OQS_randombytes(seed, seedbyte);  // OQS 랜덤 함수 사용
    fprintf(file, "Seed = ");
    for (size_t i = 0; i < seedbyte; i++) {
         fprintf(file, "%02X", seed[i]);
    }

    fclose(file);
    printf("Test vectors saved to %s\n", filename);
}

void generate_shake_req_file(const char *filename, int seedbyte) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    // SMT (Short Message Test)
    fprintf(file, "\n = Short Message Test = \n\n");
    for (size_t len = 8; len < 169; len += 8) {
        uint8_t message[len / 8];  // 비트 단위이므로 바이트 크기로 변환
        OQS_randombytes(message, len / 8);  // OQS 랜덤 함수 사용
        fprintf(file, "Len = %zu\nMsg = ", len);
        for (size_t i = 0; i < len / 8; i++) {
            fprintf(file, "%02X", message[i]);
        }
        fprintf(file, "\nMd = \n\n");
    }
    
    // LMT (Long Message Test)
    fprintf(file, "\n = Long Message Test = \n\n");
    for (size_t len = 8712; len < 24553; len += 792) { //20번 반복
        uint8_t message[len / 8];  // 비트 단위이므로 바이트 크기로 변환
        OQS_randombytes(message, len / 8);
        fprintf(file, "Len = %zu\nMsg = ", len);
        for (size_t i = 0; i < len / 8; i++) {
            fprintf(file, "%02X", message[i]);
        }
        fprintf(file, "\n\n");
    }

    // MCT (Monte Carlo Test)
    fprintf(file, "\n = Monte Carlo Test = \n\n");
    uint8_t seed[seedbyte];
    OQS_randombytes(seed, seedbyte);
    fprintf(file, "Msg = ");
    for (size_t i = 0; i < seedbyte; i++) {
        fprintf(file, "%02X", seed[i]);
    }
    fprintf(file, "\n\n\n");

    for(size_t c = 0; c < 100; c++) {
        fprintf(file, "count = %zu\n", c);
        unsigned int Outputlen = 24;
        do {
            OQS_randombytes((uint8_t *)&Outputlen, sizeof(Outputlen));
            Outputlen = 24 + (Outputlen % (1296 - 24 + 1));
        } while (Outputlen < 24 || Outputlen > 1296);
        fprintf(file, "Outputlen = %d\n", Outputlen);
        fprintf(file, "Md = \n\n");
    }
   

    // VOT (Variable Output Test)
    fprintf(file, "\n = Variable Output Test = \n\n");
    uint8_t vot_message[32];
    unsigned int Outputlen = 20;
    int count = 0;

    for(int r = 0; r < 14; r++) {   
        for (int i = 0; i < 7; i++) {  
            fprintf(file, "count = %d\n", count);
            count += 1; 
            OQS_randombytes(vot_message, 32);
            fprintf(file, "Outputlen = %d\nMsg = ", Outputlen);
            for (size_t j = 0; j < 32; j++) {
                fprintf(file, "%02X", vot_message[j]);
            }
            fprintf(file, "\n\n");
            }
        Outputlen += 9;
    }

    fclose(file);
    printf("SHAKE Test vectors saved to %s\n", filename);
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
            OQS_randombytes_custom_algorithm(kat_randombytes);

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
            fprintf(fp_rsp, "\n[KAT validation successful]\n\n");
        }
    }
    
    fclose(fp_req);
    fclose(fp_rsp);
    printf("KAT test vectors saved to %s\n", rsp_filename);
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
            OQS_randombytes_custom_algorithm(kat_randombytes);

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
    printf("KAT test vectors saved to %s\n", rsp_filename);
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
            OQS_randombytes_custom_algorithm(kat_randombytes);

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
            fprintf(fp_rsp, "\n[KAT validation successful]\n\n");
        }
    }
    
    fclose(fp_req);
    fclose(fp_rsp);
    printf("KAT test vectors saved to %s\n", rsp_filename);
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
            OQS_randombytes_custom_algorithm(kat_randombytes);

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
    printf("KAT test vectors saved to %s\n", rsp_filename);
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
            OQS_randombytes_custom_algorithm(kat_randombytes);

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
    printf("KAT test vectors saved to %s\n", rsp_filename);
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
            OQS_randombytes_custom_algorithm(kat_randombytes);

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
    printf("KAT test vectors saved to %s\n", rsp_filename);
    return OQS_SUCCESS;
}


OQS_STATUS sha3_256_selftest(const char *req_filename, const char *rsp_filename) {
    


    // 입력 및 출력 파일 열기
    FILE *req_file = fopen(req_filename, "r");
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!req_file || !rsp_file) {
        if (req_file) fclose(req_file);
        if (rsp_file) fclose(rsp_file);
        printf("Ｆｉｌｅ Ｎｏｔ ＯＰｅｎ");
        return OQS_ERROR;
    }

    char line[4096];
    char msg_buffer[MSG_BUFFER_SIZE];  // HEX 데이터를 저장할 버퍼
    size_t len = 0;
    uint8_t message[4096];
    uint8_t hash[32];
    uint8_t seed[32];
    int line_number = 0;
    int seed_found = 0;

    fprintf(rsp_file, "SHA3-256 Test Response File\n\n");

    while (fgets(line, sizeof(line), req_file)) {
        line_number++;
        
        if (strlen(line) <= 1 || strspn(line, " \t\n\r") == strlen(line)) continue; // 빈 줄 및 공백 문자만 포함된 줄 건너뛰기

        // Seed 값 읽기
        if (strncmp(line, "Seed =", 6) == 0) {
            char *seed_str = strchr(line, '=') + 2;
            for (size_t i = 0; i < 32; i++) {
                if (sscanf(seed_str + (i * 2), "%2hhX", &seed[i]) != 1) {
                    fclose(req_file);
                    fclose(rsp_file);
                    printf("ＳＥＥＤ ＮＯＴ ＦＯＵＮＤ");
                    return OQS_ERROR;
                }
            }
            seed_found = 1;
        }

        // 메시지 길이(Len) 읽기
        if (sscanf(line, "Len = %zu", &len) == 1) {
            msg_buffer[0] = '\0';
            size_t expected_hex_len = (len / 8) * 2;
            size_t actual_hex_len = 0;

            while (fgets(line, sizeof(line), req_file)) {
                line_number++;
                if (strncmp(line, "Md =", 4) == 0) break;
                if (strlen(line) <= 1) continue;

                char *msg_str = strstr(line, "Msg =");
                if (msg_str) msg_str += 5;
                else msg_str = line;

                while (*msg_str && isspace((unsigned char)*msg_str)) msg_str++;

                size_t msg_str_len = strlen(msg_str);
                while (msg_str_len > 0 && isspace((unsigned char)msg_str[msg_str_len - 1])) {
                    msg_str[msg_str_len - 1] = '\0';
                    msg_str_len--;
                }

                strncat(msg_buffer, msg_str, sizeof(msg_buffer) - strlen(msg_buffer) - 1);
                actual_hex_len = strlen(msg_buffer);
                if (actual_hex_len >= expected_hex_len) break;
            }
            // HEX 데이터 길이 검증
            if (actual_hex_len != expected_hex_len) {
                    fclose(req_file);
                    fclose(rsp_file);
                    printf("LEN ERROR");
                    return OQS_ERROR;
            }

            memset(message, 0, sizeof(message));
            for (size_t i = 0; i < len / 8; i++) {
                if (sscanf(msg_buffer + (i * 2), "%2hhX", &message[i]) != 1) {
                    fclose(req_file);
                    fclose(rsp_file);
                    printf("SIZE ERROR");
                    return OQS_ERROR;
                }
            }

            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                fclose(req_file);
                fclose(rsp_file);
                printf("MD_ERROR");
                return OQS_ERROR;
            }

            EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
            EVP_DigestUpdate(mdctx, message, len / 8);
            EVP_DigestFinal_ex(mdctx, hash, NULL);
            EVP_MD_CTX_free(mdctx);

            fprintf(rsp_file, "Len = %zu\n", len);
            fprintf(rsp_file, "Msg = ");
            for (size_t i = 0; i < len / 8; i++) {
                fprintf(rsp_file, "%02X", message[i]);
            }
            fprintf(rsp_file, "\n");

            fprintf(rsp_file, "Md = ");
            for (size_t i = 0; i < 32; i++) {
                fprintf(rsp_file, "%02X", hash[i]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }

    if (!seed_found) {
        fclose(req_file);
        fclose(rsp_file);
        printf("SEED_ERROR");
        return OQS_ERROR;
    }

    uint8_t mct_hash[32];
    memcpy(mct_hash, seed, 32);

    fprintf(rsp_file, "=== Monte Carlo Test ===\n");
    for (int i = 0; i < MCT_ITERATIONS; i++) {
        fprintf(rsp_file, "COUNT = %d\n", i);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
        EVP_DigestUpdate(mdctx, mct_hash, 32);
        fprintf(rsp_file, "Msg = ");
        for (size_t j = 0; j < 32; j++) {
            fprintf(rsp_file, "%02X", mct_hash[j]);
        }
        EVP_DigestFinal_ex(mdctx, mct_hash, NULL);
        fprintf(rsp_file, "\nMd = ");
        for (size_t j = 0; j < 32; j++) {
            fprintf(rsp_file, "%02X", mct_hash[j]);
        }

        EVP_MD_CTX_free(mdctx);
        fprintf(rsp_file, "\n\n");
    }

    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS sha3_512_selftest(const char *req_filename, const char *rsp_filename) {
    // 입력 및 출력 파일 열기
    FILE *req_file = fopen(req_filename, "r");
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!req_file || !rsp_file) {
        if (req_file) fclose(req_file);
        if (rsp_file) fclose(rsp_file);
        return OQS_ERROR;
    }

    char line[4096];
    char msg_buffer[MSG_BUFFER_SIZE];  // HEX 데이터를 저장할 버퍼
    size_t len = 0;
    uint8_t message[4096];
    uint8_t hash[64];
    uint8_t seed[64];
    int line_number = 0;
    int seed_found = 0;

    fprintf(rsp_file, "SHA3-512 Test Response File\n\n");

    while (fgets(line, sizeof(line), req_file)) {
        line_number++;
        
        // 빈 줄 및 공백 문자만 포함된 줄 건너뛰기
        if (strlen(line) <= 1 || strspn(line, " \t\n\r") == strlen(line)) continue;

        // Seed 값 읽기
        if (strncmp(line, "Seed =", 6) == 0) {
            char *seed_str = strchr(line, '=') + 2;
            for (size_t i = 0; i < 64; i++) {
                if (sscanf(seed_str + (i * 2), "%2hhX", &seed[i]) != 1) {
                    fclose(req_file);
                    fclose(rsp_file);
                    return OQS_ERROR;
                }
            }
            seed_found = 1;
        }

        // 메시지 길이(Len) 읽기
        if (sscanf(line, "Len = %zu", &len) == 1) {
            msg_buffer[0] = '\0';
            size_t expected_hex_len = (len / 8) * 2;
            size_t actual_hex_len = 0;

            // Msg 값 읽기 및 결합 (여러 줄 가능)
            while (fgets(line, sizeof(line), req_file)) {
                line_number++;
                if (strncmp(line, "Md =", 4) == 0) break;
                if (strlen(line) <= 1) continue;

                char *msg_str = strstr(line, "Msg =");
                if (msg_str) msg_str += 5;
                else msg_str = line;

                while (*msg_str && isspace((unsigned char)*msg_str)) msg_str++;

                size_t msg_str_len = strlen(msg_str);
                while (msg_str_len > 0 && isspace((unsigned char)msg_str[msg_str_len - 1])) {
                    msg_str[msg_str_len - 1] = '\0';
                    msg_str_len--;
                }

                strncat(msg_buffer, msg_str, sizeof(msg_buffer) - strlen(msg_buffer) - 1);
                actual_hex_len = strlen(msg_buffer);
                if (actual_hex_len >= expected_hex_len) break;
            }

            // HEX 데이터 길이 검증 및 보정
            if (actual_hex_len < expected_hex_len) {
                if (actual_hex_len + 1 == expected_hex_len) {
                    strcat(msg_buffer, "0");
                    actual_hex_len++;
                } else {
                    fclose(req_file);
                    fclose(rsp_file);
                    return OQS_ERROR;
                }
            }

            // HEX 데이터를 바이트 배열로 변환
            memset(message, 0, sizeof(message));
            for (size_t i = 0; i < len / 8; i++) {
                if (sscanf(msg_buffer + (i * 2), "%2hhX", &message[i]) != 1) {
                    fclose(req_file);
                    fclose(rsp_file);
                    return OQS_ERROR;
                }
            }

            // SHA3-512 해싱 수행
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                fclose(req_file);
                fclose(rsp_file);
                return OQS_ERROR;
            }

            EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
            EVP_DigestUpdate(mdctx, message, len / 8);
            EVP_DigestFinal_ex(mdctx, hash, NULL);
            EVP_MD_CTX_free(mdctx);

            // 결과 저장
            fprintf(rsp_file, "Len = %zu\n", len);
            fprintf(rsp_file, "Msg = ");
            for (size_t i = 0; i < len / 8; i++) {
                fprintf(rsp_file, "%02X", message[i]);
            }
            fprintf(rsp_file, "\n");

            fprintf(rsp_file, "Md = ");
            for (size_t i = 0; i < 64; i++) {
                fprintf(rsp_file, "%02X", hash[i]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }

    if (!seed_found) {
        fclose(req_file);
        fclose(rsp_file);
        printf("SEED NOT FOUND");
        return OQS_ERROR;
    }

    // 몬테 카를로 테스트 수행
    uint8_t mct_hash[64];
    memcpy(mct_hash, seed, 64);

    fprintf(rsp_file, "=== Monte Carlo Test ===\n");
    for (int i = 0; i < MCT_ITERATIONS; i++) {
        fprintf(rsp_file, "COUNT = %d\n", i);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
        EVP_DigestUpdate(mdctx, mct_hash, 64);
        fprintf(rsp_file, "Msg = ");
        for (size_t j = 0; j < 64; j++) {
            fprintf(rsp_file, "%02X", mct_hash[j]);
        }
        EVP_DigestFinal_ex(mdctx, mct_hash, NULL);
        fprintf(rsp_file, "\nMd = ");
        for (size_t j = 0; j < 64; j++) {
            fprintf(rsp_file, "%02X", mct_hash[j]);
        }

        EVP_MD_CTX_free(mdctx);
        fprintf(rsp_file, "\n\n");
    }

    fclose(req_file);
    fclose(rsp_file);
    return OQS_SUCCESS;
}

OQS_STATUS shake_128_selftest(const char *req_filename, const char *rsp_filename) {
FILE *req_file = fopen(req_filename, "r");
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!req_file || !rsp_file) {
        perror("Failed to open file");
        if (req_file) fclose(req_file);
        if (rsp_file) fclose(rsp_file);
        return OQS_ERROR;
    }

    char line[MSG_BUFFER_SIZE];
    size_t len = 0;
    uint8_t message[MSG_BUFFER_SIZE];
    uint8_t hash[16];
    uint8_t seed[32];
    int seed_found = 0;
    int in_mct_section = 0;
    int in_vot_section = 0;

    while (fgets(line, sizeof(line), req_file)) {
        if (strstr(line, "Short Message Test")) {
            fprintf(rsp_file, "\n = Short Message Test = \n\n");
            continue;
        } else if (strstr(line, "Long Message Test")) {
            fprintf(rsp_file, "\n = Long Message Test = \n\n");
            continue;
        } else if (strstr(line, "Monte Carlo Test")) {
            fprintf(rsp_file, "\n = Monte Carlo Test = \n\n");
            in_mct_section = 1;
            continue;
        } else if (strstr(line, "Variable Output Test")) {
            fprintf(rsp_file, "\n = Variable Output Test = \n\n");
            in_mct_section = 0;
            in_vot_section = 1;
            continue;
        }

        if (strncmp(line, "Len =", 5) == 0) {
            sscanf(line, "Len = %zu", &len);
            fgets(line, sizeof(line), req_file);
            if (strncmp(line, "Msg =", 5) == 0) {
                char *msg_str = strchr(line, '=');
                if (!msg_str) continue;
                msg_str += 2;

                size_t msg_len = len / 8;
                for (size_t i = 0; i < msg_len; i++) {
                    sscanf(msg_str + (i * 2), "%2hhX", &message[i]);
                }

                EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL);
                EVP_DigestUpdate(mdctx, message, msg_len);
                EVP_DigestFinalXOF(mdctx, hash, 16);
                EVP_MD_CTX_free(mdctx);

                fprintf(rsp_file, "Len = %zu\n", len);
                fprintf(rsp_file, "Msg = ");
                for (size_t i = 0; i < msg_len; i++) {
                    fprintf(rsp_file, "%02X", message[i]);
                }
                fprintf(rsp_file, "\nMd = ");
                for (size_t i = 0; i < 16; i++) {
                    fprintf(rsp_file, "%02X", hash[i]);
                }
                fprintf(rsp_file, "\n\n");
            }
        } else if (in_mct_section && strncmp(line, "Msg =", 5) == 0 && !seed_found) {
            // Monte Carlo Test 시작 시 seed 설정
            char *seed_str = strchr(line, '=') + 2;
            for (size_t i = 0; i < 32; i++) {
                sscanf(seed_str + (i * 2), "%2hhX", &seed[i]);
            }
            seed_found = 1;
        }
    }

    // Monte Carlo Test (MCT)
    if (seed_found) {
        fprintf(rsp_file, "\n = Monte Carlo Test = \n\n");
        uint8_t mct_hash[16];
        memcpy(mct_hash, seed, 32);

        for (int i = 0; i < MCT_ITERATIONS; i++) {
            int Outputlen;
            do {
                OQS_randombytes((uint8_t *)&Outputlen, sizeof(Outputlen));
                Outputlen = 24 + (Outputlen % (1296 - 24 + 1));
            } while (Outputlen < 24 || Outputlen > 1296);

            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL);
            EVP_DigestUpdate(mdctx, mct_hash, 32);
            EVP_DigestFinalXOF(mdctx, mct_hash, Outputlen);
            EVP_MD_CTX_free(mdctx);

            fprintf(rsp_file, "COUNT = %d\nOutputlen = %d\nSeed = ", i, Outputlen);
            for (size_t j = 0; j < 32; j++) {
                fprintf(rsp_file, "%02X", seed[j]);
            }
            fprintf(rsp_file, "\nMd = ");
            for (size_t j = 0; j < Outputlen; j++) {
                fprintf(rsp_file, "%02X", mct_hash[j]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }

    // Variable Output Test (VOT)
    if (in_vot_section) {
        fprintf(rsp_file, "\n = Variable Output Test = \n\n");
        while (fgets(line, sizeof(line), req_file)) {
            int Outputlen;
            uint8_t vot_msg[32];

            if (sscanf(line, "count = %*d\nOutputlen = %d", &Outputlen) == 1) {
                fgets(line, sizeof(line), req_file);
                if (strncmp(line, "Msg =", 5) == 0) {
                    char *msg_str = strchr(line, '=') + 2;
                    for (size_t i = 0; i < 32; i++) {
                        sscanf(msg_str + (i * 2), "%2hhX", &vot_msg[i]);
                    }

                    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                    EVP_DigestInit_ex(mdctx, EVP_shake128(), NULL);
                    EVP_DigestUpdate(mdctx, vot_msg, 32);
                    EVP_DigestFinalXOF(mdctx, hash, Outputlen);
                    EVP_MD_CTX_free(mdctx);

                    fprintf(rsp_file, "Md = ");
                    for (size_t i = 0; i < Outputlen; i++) {
                        fprintf(rsp_file, "%02X", hash[i]);
                    }
                    fprintf(rsp_file, "\n\n");
                }
            }
        }
    }

    fclose(req_file);
    fclose(rsp_file);
    printf("SHAKE Test vectors saved to %s\n", rsp_filename);
}


OQS_STATUS shake_256_selftest(const char *req_filename, const char *rsp_filename) {
    


    // 입력 및 출력 파일 열기
    FILE *req_file = fopen(req_filename, "r");
    FILE *rsp_file = fopen(rsp_filename, "w");
    if (!req_file || !rsp_file) {
        if (req_file) fclose(req_file);
        if (rsp_file) fclose(rsp_file);
        printf("Ｆｉｌｅ Ｎｏｔ ＯＰｅｎ");
        return OQS_ERROR;
    }

    char line[4096];
    char msg_buffer[MSG_BUFFER_SIZE];  // HEX 데이터를 저장할 버퍼
    size_t len = 0;
    uint8_t message[4096];
    uint8_t hash[32];
    uint8_t seed[32];
    int line_number = 0;
    int seed_found = 0;

    fprintf(rsp_file, "SHA3-256 Test Response File\n\n");

    while (fgets(line, sizeof(line), req_file)) {
        line_number++;
        
        if (strlen(line) <= 1 || strspn(line, " \t\n\r") == strlen(line)) continue; // 빈 줄 및 공백 문자만 포함된 줄 건너뛰기

        // Seed 값 읽기
        if (strncmp(line, "Seed =", 6) == 0) {
            char *seed_str = strchr(line, '=') + 2;
            for (size_t i = 0; i < 32; i++) {
                if (sscanf(seed_str + (i * 2), "%2hhX", &seed[i]) != 1) {
                    fclose(req_file);
                    fclose(rsp_file);
                    printf("ＳＥＥＤ ＮＯＴ ＦＯＵＮＤ");
                    return OQS_ERROR;
                }
            }
            seed_found = 1;
        }

        // 메시지 길이(Len) 읽기
        if (sscanf(line, "Len = %zu", &len) == 1) {
            msg_buffer[0] = '\0';
            size_t expected_hex_len = (len / 8) * 2;
            size_t actual_hex_len = 0;

            while (fgets(line, sizeof(line), req_file)) {
                line_number++;
                if (strncmp(line, "Md =", 4) == 0) break;
                if (strlen(line) <= 1) continue;

                char *msg_str = strstr(line, "Msg =");
                if (msg_str) msg_str += 5;
                else msg_str = line;

                while (*msg_str && isspace((unsigned char)*msg_str)) msg_str++;

                size_t msg_str_len = strlen(msg_str);
                while (msg_str_len > 0 && isspace((unsigned char)msg_str[msg_str_len - 1])) {
                    msg_str[msg_str_len - 1] = '\0';
                    msg_str_len--;
                }

                strncat(msg_buffer, msg_str, sizeof(msg_buffer) - strlen(msg_buffer) - 1);
                actual_hex_len = strlen(msg_buffer);
                if (actual_hex_len >= expected_hex_len) break;
            }
            // HEX 데이터 길이 검증
            if (actual_hex_len != expected_hex_len) {
                    fclose(req_file);
                    fclose(rsp_file);
                    printf("LEN ERROR");
                    return OQS_ERROR;
            }

            memset(message, 0, sizeof(message));
            for (size_t i = 0; i < len / 8; i++) {
                if (sscanf(msg_buffer + (i * 2), "%2hhX", &message[i]) != 1) {
                    fclose(req_file);
                    fclose(rsp_file);
                    printf("SIZE ERROR");
                    return OQS_ERROR;
                }
            }

            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                fclose(req_file);
                fclose(rsp_file);
                printf("MD_ERROR");
                return OQS_ERROR;
            }

            EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
            EVP_DigestUpdate(mdctx, message, len / 8);
            EVP_DigestFinal_ex(mdctx, hash, NULL);
            EVP_MD_CTX_free(mdctx);

            fprintf(rsp_file, "Len = %zu\n", len);
            fprintf(rsp_file, "Msg = ");
            for (size_t i = 0; i < len / 8; i++) {
                fprintf(rsp_file, "%02X", message[i]);
            }
            fprintf(rsp_file, "\n");

            fprintf(rsp_file, "Md = ");
            for (size_t i = 0; i < 32; i++) {
                fprintf(rsp_file, "%02X", hash[i]);
            }
            fprintf(rsp_file, "\n\n");
        }
    }

    if (!seed_found) {
        fclose(req_file);
        fclose(rsp_file);
        printf("SEED_ERROR");
        return OQS_ERROR;
    }

    uint8_t mct_hash[32];
    memcpy(mct_hash, seed, 32);

    fprintf(rsp_file, "=== Monte Carlo Test ===\n");
    for (int i = 0; i < MCT_ITERATIONS; i++) {
        fprintf(rsp_file, "COUNT = %d\n", i);
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL);
        EVP_DigestUpdate(mdctx, mct_hash, 32);
        fprintf(rsp_file, "Msg = ");
        for (size_t j = 0; j < 32; j++) {
            fprintf(rsp_file, "%02X", mct_hash[j]);
        }
        EVP_DigestFinal_ex(mdctx, mct_hash, NULL);
        fprintf(rsp_file, "\nMd = ");
        for (size_t j = 0; j < 32; j++) {
            fprintf(rsp_file, "%02X", mct_hash[j]);
        }

        EVP_MD_CTX_free(mdctx);
        fprintf(rsp_file, "\n\n");
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
    if(kyber_1024_selftest("vector/Kyber_Test_Vector_1024.req", "vector/Kyber_Test_Vector_1024.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: Kyber-1024 kat test failed!\n");
        return OQS_ERROR;
    }
    if(kyber_768_selftest("vector/Kyber_Test_Vector_768.req", "vector/Kyber_Test_Vector_768.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: Kyber-768 kat test failed!\n");
        return OQS_ERROR;
    }
    if(kyber_512_selftest("vector/Kyber_Test_Vector_512.req", "vector/Kyber_Test_Vector_512.rsp") == OQS_ERROR){
        fprintf(stderr, "ERROR: Kyber-512 kat test failed!\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

OQS_STATUS DilithiumKatTest() {
    if (dilithium_2_selftest("vector/Dilithium_Test_Vector_2.req", "vector/Dilithium_Test_Vector_2.rsp") == OQS_ERROR) {
        fprintf(stderr, "ERROR: Dilithium-2 kat test failed!\n");
        return OQS_ERROR;
    }
    if (dilithium_3_selftest("vector/Dilithium_Test_Vector_3.req", "vector/Dilithium_Test_Vector_3.rsp") == OQS_ERROR) {
        fprintf(stderr, "ERROR: Dilithium-3 kat test failed!\n");
        return OQS_ERROR;
    }
    if (dilithium_5_selftest("vector/Dilithium_Test_Vector_5.req", "vector/Dilithium_Test_Vector_5.rsp") == OQS_ERROR) {
        fprintf(stderr, "ERROR: Dilithium-5 kat test failed!\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}