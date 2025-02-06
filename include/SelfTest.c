#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define SEED_SIZE 48

static void kat_randombytes(uint8_t *random_array, size_t bytes_to_read) {
    static unsigned int seed_offset = 0;
    for (size_t i = 0; i < bytes_to_read; i++) {
        random_array[i] = (uint8_t)(rand() % 256);
    }
    seed_offset += bytes_to_read;
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
