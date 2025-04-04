#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include <ctype.h>
#include <sys/random.h>
#include <errno.h>
#include "../module.h" 
typedef struct{
    int errorCode; //에러코드 값 
    OQS_STATUS OQS_Return; //OQS_SUCCESS / OQS_ERROR
}rv;



void ISCrandombytes(uint8_t *random_array, size_t bytes_to_read) {
    ssize_t result = getrandom(random_array, bytes_to_read, 0);
    
    if (result < 0) {
        // Fallback: /dev/urandom 사용 
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            size_t offset = 0;
            while (offset < bytes_to_read) {
                ssize_t read_bytes = read(fd, random_array + offset, bytes_to_read - offset);
                if (read_bytes <= 0) {
                    break;  // 실패 시 그대로 종료
                }
                offset += read_bytes;
            }
            close(fd);
        }
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
    if (!DEBUG_MODE) return false; 
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
