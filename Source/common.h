

typedef struct {
    int errorCode;
    OQS_STATUS OQS_Return;
} rv;
void ISCrandombytes(uint8_t *random_array, size_t bytes_to_read);

#define DEBUG_PRINT(fmt, ...) \
    do { if (DEBUG_MODE) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while (0)

void DEBUG_HEX(const char *label, const uint8_t *data, size_t len);
bool DEBUG_HEXIN(uint8_t *buffer, size_t length);