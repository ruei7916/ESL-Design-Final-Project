#ifndef DEFINES_H_
#define DEFINES_H_
//#define NATIVE_SYSTEMC
#include <systemc>

using namespace sc_dt;

typedef struct {
  sc_biguint<128> key;
  sc_biguint<128> plaintext;
} input_t;

typedef sc_biguint<128> output_t;

typedef struct {
  unsigned char arr[4][4];
} StateBlock;

#endif
