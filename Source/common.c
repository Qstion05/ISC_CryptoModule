#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include <ctype.h>
#include "../module.h" 

typedef struct{
    int errorCode; //에러코드 값 
    OQS_STATUS OQS_Return; //OQS_SUCCESS / OQS_ERROR
}rv;


void ISCrandombytes(uint8_t *random_array, size_t bytes_to_read) {
    int fd = open("/dev/urandom", O_RDONLY);  // /dev/urandom 파일 열기
    if (fd < 0) {
        // 에러 발생 시 기본적인 Fallback (보안 강도 낮음)
        for (size_t i = 0; i < bytes_to_read; i++) {
            random_array[i] = (uint8_t)(rand() % 256);
        }
    } else {
        ssize_t bytes_read = read(fd, random_array, bytes_to_read);  // /dev/urandom에서 읽기
        if (bytes_read < 0) {  // 읽기 실패 시
        // Fallback: rand() 사용 (비권장, 보안 취약점 가능)
            for (size_t i = 0; i < bytes_to_read; i++) {
                random_array[i] = (uint8_t)(rand() % 256);
            }
        }
    
    close(fd);  // 파일 닫기
    }
}

void DEBUG_HEX(const char *label, const uint8_t *data, size_t len) {
    if (!DEBUG_MODE) return;  // 디버그 모드 아닐 경우 아무것도 출력하지 않음

    fprintf(stderr, "[DEBUG] %s:\n", label);
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02X", data[i]);
        if ((i + 1) % 32 == 0) fprintf(stderr, "\n");
    }
    if (len % 16 != 0) fprintf(stderr, "\n");
}

bool DEBUG_HEXIN(uint8_t *buffer, size_t length) {
    char input[2 * length + 2];  // 개행 포함 고려
    memset(input, 0, sizeof(input));

    printf("%zu바이트(16진수 문자열, 공백 없이 %zu글자) 입력 > ", length, 2 * length);

    if (fgets(input, sizeof(input), stdin) == NULL) {
        fprintf(stderr, "입력 오류\n");
        return false;
    }
    input[strcspn(input, "\n")] = '\0';
    // 입력 길이 확인
    size_t input_len = strlen(input);
    if (input_len < 2 * length) {
        fprintf(stderr, " 입력 길이가 %zu보다 짧습니다.\n", 2 * length);
        fprintf(stderr, "실제 입력 길이: %zu\n",input_len );
        return false;
    } else if (input_len > 2 * length) {
        fprintf(stderr, " 입력 길이가 %zu보다 깁니다.\n", 2 * length);
        fprintf(stderr, "실제 입력 길이: %zu\n",input_len );
        return false;
    }


    // 2글자씩 잘라서 16진수 파싱
    for (size_t i = 0; i < length; i++) {
        char hex_byte[3] = { input[2*i], input[2*i + 1], '\0' };

        // 유효한 16진수인지 검사
        if (!isxdigit(hex_byte[0]) || !isxdigit(hex_byte[1])) {
            fprintf(stderr, " 잘못된 16진수 입력: %s\n", hex_byte);
            return false;
        }

        buffer[i] = (uint8_t)strtoul(hex_byte, NULL, 16);
    }
    return true;
}