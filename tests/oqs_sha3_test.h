#ifndef OQS_SHA3_TEST_H
#define OQS_SHA3_TEST_H

#include <oqs/oqs.h>

OQS_STATUS SHA3_select();
OQS_STATUS SHAKE_select();

OQS_STATUS ISC_SHA3_All_test();
OQS_STATUS ISC_SHAKE_All_test();

OQS_STATUS ISC_SHA3_256_test();
OQS_STATUS ISC_SHA3_512_test();
OQS_STATUS ISC_SHAKE_128_test();
OQS_STATUS ISC_SHAKE_256_test();

#endif // OQS_SHA3_TEST_H
