//#define NATIVE_SYSTEMC
#include "AES128.h"
#ifndef NATIVE_SYSTEMC
#include "stratus_hls.h"
#endif
#include <cstdint>
#include <iostream>
using namespace sc_dt;
#include <stdio.h>

AES128::AES128(sc_module_name n) : sc_module(n), i_clk( "clk" ), i_rst( "rst" ), 
	key_in("key_in"), plaintext_in("plaintext_in"), dout("dout")
{
  SC_THREAD(encrypt_block);
  sensitive << i_clk.pos();
  reset_signal_is(i_rst, false);
  dont_initialize();

  #ifndef NATIVE_SYSTEMC
  key_in.clk_rst(i_clk, i_rst);
  plaintext_in.clk_rst(i_clk, i_rst);
	dout.clk_rst(i_clk, i_rst);
  #endif
}

void AES128::encrypt_block()
{
  #ifndef NATIVE_SYSTEMC
  {
    HLS_DEFINE_PROTOCOL("main_reset");
    key_in.reset();
    plaintext_in.reset();
    dout.reset();
    wait();
  }
  #endif
    wait();

  while(true){
    #ifndef NATIVE_SYSTEMC
    //HLS_PIPELINE_LOOP(SOFT_STALL, 3, "Loop");
    HLS_CONSTRAIN_LATENCY(0,10,"main_loop");
    #endif
    sc_biguint<128> key_i, plaintext_i;
    #ifndef NATIVE_SYSTEMC
    {
      HLS_DEFINE_PROTOCOL("input");
      key_i = key_in.get();
      plaintext_i = plaintext_in.get();
      wait();
    }
    #else
      key_i = key_in.read();
      plaintext_i = plaintext_in.read();
    #endif
  {
    #ifndef NATIVE_SYSTEMC
    //HLS_DPOPT_REGION();
    #endif
    for(uint8_t i=0;i<16;i++){
      #ifndef NATIVE_SYSTEMC
      HLS_UNROLL_LOOP(ALL, "key_i");
      #endif
      roundkeys[i] = (sc_uint<8>)key_i.range(127-8*i,120-8*i);
    }
    for(sc_uint<3> i=0; i<4; i++){
      #ifndef NATIVE_SYSTEMC
      HLS_UNROLL_LOOP(ALL, "plaintext_i");
      #endif
      for(sc_uint<3> j=0; j<4; j++){
        sc_uint<7> offset = (i*4+j)*8;
        state.arr[j][i] = (sc_uint<8>)(plaintext_i.range(127-offset, 120-offset));
      }
    }
    
    //KeyExpansion(key, roundkeys);
    AddRoundKey(state, roundkeys);

    uint8_t round;
    for(round=1;round<=9;round++){
      SubBytes(state);
      state = ShiftRows(state);
      state = MixColumns(state);
      GenRoundKey(roundkeys + ((round-1)<<4), roundkeys + (round<<4), round);
      AddRoundKey(state, roundkeys + (round<<4));
    }
    
    SubBytes(state);
    state = ShiftRows(state);
    GenRoundKey(roundkeys + 144, roundkeys + 160, 10);
    AddRoundKey(state, roundkeys+ 10 * 4 * 4);
    
    for(uint8_t i=0;i<4;i++){
      #ifndef NATIVE_SYSTEMC
      HLS_UNROLL_LOOP(ALL, "output");
      #endif
      for(uint8_t j=0;j<4;j++){
        output.range(127-8*(4*i+j),120-8*(4*i+j)) = state.arr[j][i];
      }
    }
  }
    #ifndef NATIVE_SYSTEMC
    {
      HLS_DEFINE_PROTOCOL("output");
      dout.put(output);
      wait();
    }
    #else
    dout.write(output);
    #endif
    wait();
  }
}


void AES128::SubBytes(StateBlock &state) {
  #ifndef NATIVE_SYSTEMC
  HLS_DPOPT_REGION("sub_bytes");
  #endif
  sc_uint<3> i, j;
  unsigned char t;
  for (i = 0; i < 4; i++) {
    #ifndef NATIVE_SYSTEMC
    HLS_UNROLL_LOOP(ALL, "sub_bytes");
    #endif
    for (j = 0; j < 4; j++) {
      t = state.arr[i][j];
      state.arr[i][j] = sbox[t>>4][t&0x0f];
    }
  }
}

StateBlock AES128::ShiftRows(StateBlock state) {
  #ifndef NATIVE_SYSTEMC
  HLS_DPOPT_REGION("shiftrows");
  #endif
  StateBlock a;
  for(uint8_t i=0;i<4;i++){
    #ifndef NATIVE_SYSTEMC
    HLS_UNROLL_LOOP(ALL, "SHIFTROWS");
    #endif
    for(uint8_t j=0;j<4;j++){
      a.arr[i][j] = state.arr[i][(j+i)%4];
    }
  }
  return a;
}


StateBlock AES128::MixColumns(StateBlock state) {
  #ifndef NATIVE_SYSTEMC
  HLS_DPOPT_REGION("mixcolumns");
  #endif
  StateBlock a = {{0}};
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t k = 0; k < 4; ++k) {
      for (uint8_t j = 0; j < 4; ++j) {
        if (CMDS[i][k] == 1)
          a.arr[i][j] ^= state.arr[k][j];
        else
          a.arr[i][j] ^= GF_MUL_TABLE[CMDS[i][k]%2][state.arr[k][j]];
      }
    }
  }
  return a;
}

void AES128::AddRoundKey(StateBlock &state, unsigned char *key) {
  #ifndef NATIVE_SYSTEMC
  HLS_DPOPT_REGION("addroundkey");
  #endif
  uint8_t i, j;
  for (i = 0; i < 4; i++) {
    #ifndef NATIVE_SYSTEMC
    HLS_UNROLL_LOOP(ALL, "addroundkey");
    #endif
    for (j = 0; j < 4; j++) {
      state.arr[i][j] = state.arr[i][j] ^ key[i + 4 * j];
    }
  }
}

void AES128::GenRoundKey(const unsigned char prev_key[], unsigned char w[], uint8_t round){
  #ifndef NATIVE_SYSTEMC
  //HLS_DPOPT_REGION("GenRoundKey");
  #endif
  unsigned char temp[4];
  unsigned char rcon[4];
  uint8_t i = 0;
  for(i=0;i<16;i+=4) {
    #ifndef NATIVE_SYSTEMC
    HLS_UNROLL_LOOP(ALL, "genroundkey");
    #endif
    if (i == 0) {
      temp[0] = prev_key[12];
      temp[1] = prev_key[13];
      temp[2] = prev_key[14];
      temp[3] = prev_key[15];
      RotWord(temp);
      SubWord(temp);
      Rcon(rcon, round );
      XorWords(temp, rcon, temp);
    } else{
      temp[0] = w[i-4+0];
      temp[1] = w[i-4+1];
      temp[2] = w[i-4+2];
      temp[3] = w[i-4+3];
    }

    w[i + 0] = prev_key[i + 0 ] ^ temp[0];
    w[i + 1] = prev_key[i + 1 ] ^ temp[1];
    w[i + 2] = prev_key[i + 2 ] ^ temp[2];
    w[i + 3] = prev_key[i + 3 ] ^ temp[3];
  }
}

void AES128::KeyExpansion(const unsigned char key[], unsigned char w[]) {
  #ifndef NATIVE_SYSTEMC
  HLS_DPOPT_REGION("key_expansion");
  #endif
  unsigned char temp[4];
  unsigned char rcon[4];

  uint8_t i = 0;
  while (i < 4 * 4) {
    w[i] = key[i];
    i++;
  }

  i = 4 * 4;
  while (i < 4 * 4 * (10 + 1)) {
    #ifndef NATIVE_SYSTEMC
    HLS_UNROLL_LOOP(OFF, "Subwords");
    #endif
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if ((i &0x0c) == 0) {
      RotWord(temp);
      SubWord(temp);
      Rcon(rcon, (i >>4));
      XorWords(temp, rcon, temp);
    } 

    w[i + 0] = w[i - 4 * 4] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * 4] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * 4] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * 4] ^ temp[3];
    i += 4;
  }
}


void AES128::SubWord(unsigned char *a) {
  #ifndef NATIVE_SYSTEMC
  HLS_DPOPT_REGION("sub_word");
  #endif
  uint8_t i;
  for (i = 0; i < 4; i++) {
    #ifndef NATIVE_SYSTEMC
    HLS_UNROLL_LOOP(ALL, "Subwords");
    #endif
    a[i] = sbox[a[i]>>4][a[i]&0x0f];
  }
}

void AES128::RotWord(unsigned char *a) {
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void AES128::XorWords(unsigned char *a, unsigned char *b, unsigned char *c) {
  uint8_t i;
  for (i = 0; i < 4; i++) {
    #ifndef NATIVE_SYSTEMC
    HLS_UNROLL_LOOP(ALL, "xorwords");
    #endif
    c[i] = a[i] ^ b[i];
  }
}

void AES128::Rcon(unsigned char *a, uint8_t n) {
  #ifndef NATIVE_SYSTEMC
  HLS_DPOPT_REGION("rcon");
  #endif
  a[0] = RCON[n-1];
  a[1] = a[2] = a[3] = 0;
}

