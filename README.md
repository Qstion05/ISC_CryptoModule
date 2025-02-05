# ISC_CryptoModule
가천대학교 ISC 연구실 암호모듈 프로젝트입니다.


# Compile Option
gcc -Wall -O2 $(pkg-config --cflags --libs liboqs) -I./include/sha3 include/sha3/sha3.c include/SelfTest.c include/IntegrityCheck.c tests/oqs_sha3_test.c tests/oqs_dilithium_test.c tests/oqs_kyber_test.c  module.c -loqs -o o

