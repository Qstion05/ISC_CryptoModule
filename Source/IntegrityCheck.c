#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>

#define MESSAGE_LEN 32  // SHA3-256 해시 크기
#define DILITHIUM_ALG OQS_SIG_alg_dilithium_3  // Dilithium-3 고정

// 🔹 메모리 정리 함수
void cleanup_memory(uint8_t *data, size_t len) {
    if (data) {
        OQS_MEM_cleanse(data, len);
        free(data);
    }
}

// 🔹 SHA3-256 해시 생성 (파일 무결성 확인용)
void sha3_256(const char *input, unsigned char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha3_256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, input, strlen(input));
    EVP_DigestFinal_ex(mdctx, output, NULL);
    EVP_MD_CTX_free(mdctx);
}

// 🔹 Integrity.txt 생성 (ISCLAB 해시 저장)
void create_integrity_file() {
    unsigned char hash[MESSAGE_LEN];
    sha3_256("ISCLAB", hash);

    FILE *file = fopen("Integrity.txt", "wb");
    if (!file) {
        perror("File Generate Failed");
        exit(EXIT_FAILURE);
    }
    fwrite(hash, 1, MESSAGE_LEN, file);
    fclose(file);
    printf("Integrity.txt Generate Success\n");
}

// 🔹 Dilithium-3 키 쌍 생성
OQS_STATUS generate_dilithium_keys(uint8_t **public_key, uint8_t **secret_key, size_t *pk_len, size_t *sk_len) {
    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG);
    if (!sig) {
        fprintf(stderr, "ERROR: Failed to initialize %s.\n", DILITHIUM_ALG);
        return OQS_ERROR;
    }

    *pk_len = sig->length_public_key;
    *sk_len = sig->length_secret_key;
    *public_key = malloc(*pk_len);
    *secret_key = malloc(*sk_len);
    
    if (!*public_key || !*secret_key) {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        OQS_SIG_free(sig);
        return OQS_ERROR;
    }

    if (OQS_SIG_keypair(sig, *public_key, *secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Key pair generation failed.\n");
        cleanup_memory(*public_key, *pk_len);
        cleanup_memory(*secret_key, *sk_len);
        OQS_SIG_free(sig);
        return OQS_ERROR;
    }

    OQS_SIG_free(sig);
    return OQS_SUCCESS;
}

// 🔹 Integrity.txt 서명 생성
OQS_STATUS sign_integrity_file(uint8_t *secret_key, size_t sk_len, uint8_t **signature, size_t *sig_len) {
    FILE *file = fopen("Integrity.txt", "rb");
    if (!file) {
        perror("Integrity.txt Read Failed");
        return OQS_ERROR;
    }

    uint8_t message[MESSAGE_LEN];
    if (fread(message, 1, MESSAGE_LEN, file) != MESSAGE_LEN) {
        perror("Failed to read message from file");
        fclose(file);
        return OQS_ERROR;
    }
    fclose(file);

    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG);
    if (!sig) {
        fprintf(stderr, "ERROR: Failed to initialize %s.\n", DILITHIUM_ALG);
        return OQS_ERROR;
    }

    *signature = malloc(sig->length_signature);
    if (!*signature) {
        fprintf(stderr, "ERROR: Memory allocation failed.\n");
        OQS_SIG_free(sig);
        return OQS_ERROR;
    }

    if (OQS_SIG_sign(sig, *signature, sig_len, message, MESSAGE_LEN, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: Signing failed.\n");
        cleanup_memory(*signature, sig->length_signature);
        OQS_SIG_free(sig);
        return OQS_ERROR;
    }

    FILE *sig_file = fopen("Integrity.sig", "wb");
    fwrite(*signature, 1, *sig_len, sig_file);
    fclose(sig_file);
    printf("[✔] Integrity.txt Signature Success!\n");

    OQS_SIG_free(sig);
    return OQS_SUCCESS;
}

// 🔹 서명 검증 함수
OQS_STATUS verify_integrity(uint8_t *public_key, size_t pk_len, uint8_t *signature, size_t sig_len) {
    FILE *file = fopen("Integrity.txt", "rb");
    if (!file) {
        perror("Integrity.txt Read Failed");
        return OQS_ERROR;
    }

    uint8_t message[MESSAGE_LEN];
    if (fread(message, 1, MESSAGE_LEN, file) != MESSAGE_LEN) {
        perror("Failed to read message from file");
        fclose(file);
        return OQS_ERROR;
    }
    fclose(file);

    OQS_SIG *sig = OQS_SIG_new(DILITHIUM_ALG);
    if (!sig) {
        fprintf(stderr, "ERROR: Failed to initialize %s.\n", DILITHIUM_ALG);
        return OQS_ERROR;
    }

    if (OQS_SIG_verify(sig, message, MESSAGE_LEN, signature, sig_len, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[✘] Integrity Verify Failed!\n");
        OQS_SIG_free(sig);
        return OQS_ERROR;
    }

    printf("[✔] Integrity Verify Success!\n");
    OQS_SIG_free(sig);
    return OQS_SUCCESS;
}

// 🔹 무결성 검증 실행 (Dilithium-3 고정)
OQS_STATUS test_dilithium_integrity() {
    uint8_t *public_key = NULL, *secret_key = NULL, *signature = NULL;
    size_t pk_len, sk_len, sig_len;

    printf("[*] Dilithium-3 Integrity Testing...\n");

    if (generate_dilithium_keys(&public_key, &secret_key, &pk_len, &sk_len) != OQS_SUCCESS)
        return OQS_ERROR;

    if (sign_integrity_file(secret_key, sk_len, &signature, &sig_len) != OQS_SUCCESS) {
        cleanup_memory(public_key, pk_len);
        cleanup_memory(secret_key, sk_len);
        return OQS_ERROR;
    }

    OQS_STATUS result = verify_integrity(public_key, pk_len, signature, sig_len);

    cleanup_memory(public_key, pk_len);
    cleanup_memory(secret_key, sk_len);
    cleanup_memory(signature, sig_len);
    return result;
}

OQS_STATUS IntegrityCheck() {
    create_integrity_file();
    if (test_dilithium_integrity() == OQS_SUCCESS) {
        printf("[✔] Dilithium-3 Integrity Test Success!\n");
    } else {
        printf("[✘] Dilithium-3 Integrity Test Failed!\n");
    }
    return 0;
}
