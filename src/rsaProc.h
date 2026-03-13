#pragma once    
#include <stdint.h>
int publicEnc(const char *keyPath, const uint8_t *plaintext, int plaintext_len, uint8_t **ciphertext, int *ciphertext_len, int type =1 );
int keyDec(const char *keyPath, const uint8_t *ciphertext, int ciphertext_len, uint8_t **plaintext, int *plaintext_len, int type =1);
int rest_test();