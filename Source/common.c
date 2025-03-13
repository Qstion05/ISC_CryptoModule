#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <oqs/oqs.h>

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
