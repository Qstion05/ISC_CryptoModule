# ISC_CryptoModule
가천대학교 ISC 연구실 암호모듈 프로젝트입니다.

## 디렉토리 구조
ISC_CryptoModule/
  | `module.c` | 암호모듈 유한상태모듈 및 동작 코드|
  ISC_CryptoModule/include
    | `IntegrityCheck.c` | 암호모듈 무결성 검사 소스 코드 |
    | `IntegrityCheck.h` | 무결성 검사 코드에 대한 헤더 파일 |
    | `rng.c`            | 난수 발생기 소스 코드 |
    | `rng.h`            | 난수 발생기에 대한 헤더 파일 |
    | `SelfTest.c`       | 암호모듈 자가시험 소스 코드 |
    | `SelfTest.h`       | 자가시험에 대한 헤더 파일 |
    ISC_CryptoModule/include/sha3
      | `sha3.c` | SHA3 해시 함수 코드       |
      | `sha3.h` | SHA3 코드의 헤더 파일     |
   
  ISC_CryptoModule/tests
    | `oqs_dilithium_test.c` | Dilithium 서명 알고리즘 코드   |
    | `oqs_dilithium_test.h` | Dilithium 코드의 헤더 파일     |
    | `oqs_kyber_test.c`     | Kyber 키 교환 알고리즘 코드    |
    | `oqs_kyber_test.h`     | Kyber 코드의 헤더 파일         |
    | `oqs_sha3_test.c`      | SHA3 해시 함수 코드            |
    | `oqs_sha3_test.h`      | SHA3 코드의 헤더 파일          |



# Compile Option
gcc -Wall -O2 $(pkg-config --cflags --libs liboqs) -I./include/sha3 include/sha3/sha3.c include/SelfTest.c include/IntegrityCheck.c tests/oqs_sha3_test.c tests/oqs_dilithium_test.c tests/oqs_kyber_test.c  module.c -loqs -lcrypto -o out

// 그럼이제 제가 여길 멋대로 써도 된다는 거잖아요
// ㅇㅋ 이해함  
