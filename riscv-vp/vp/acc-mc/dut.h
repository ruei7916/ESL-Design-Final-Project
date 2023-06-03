#ifndef DUT_H_
#define DUT_H_
#include <systemc>
#include <cmath>
#include <iomanip>
#include "defines.h"
using namespace sc_core;
using namespace sc_dt;

#include <tlm>
#include <tlm_utils/simple_target_socket.h>


struct AES128 : public sc_module {
  tlm_utils::simple_target_socket<AES128> tsock;

  sc_fifo< sc_biguint<128> > key_in;
  sc_fifo< sc_biguint<128> > plaintext_in;
	sc_fifo< output_t > dout;
  unsigned char roundkeys[16*11];
  StateBlock state;
  output_t output;

  SC_HAS_PROCESS(AES128);

  AES128(sc_module_name n): 
    sc_module(n), 
    tsock("t_skt"), 
    base_offset(0) 
  {
    tsock.register_b_transport(this, &AES128::blocking_transport);
    SC_THREAD(encrypt_block);
  }

  ~AES128() {
	}

  unsigned int base_offset;

  void encrypt_block(){
    { wait(CLOCK_PERIOD, SC_NS); }
    while (true) {
      sc_biguint<128> key_i, plaintext_i;
      key_i = key_in.read();
      plaintext_i = plaintext_in.read();
      wait(CLOCK_PERIOD, SC_NS);
      for(uint8_t i=0;i<16;i++){
        roundkeys[i] = (sc_uint<8>)key_i.range(127-8*i,120-8*i);
      }
      for(sc_uint<3> i=0; i<4; i++){
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
        //printf("%d",round);
      }
    
      SubBytes(state);
      state = ShiftRows(state);
      GenRoundKey(roundkeys + 144, roundkeys + 160, 10);
      AddRoundKey(state, roundkeys+ 10 * 4 * 4);
    
      for(uint8_t i=0;i<4;i++){
        for(uint8_t j=0;j<4;j++){
          //output = (output<<8) + state.arr[j][i];
          output.range(127-8*(4*i+j),120-8*(4*i+j)) = state.arr[j][i];
        }
      }
      wait(10*CLOCK_PERIOD, SC_NS);
      dout.write(output);
    }
  }


  void SubBytes(StateBlock &state) {
    sc_uint<3> i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        t = state.arr[i][j];
        state.arr[i][j] = sbox[t>>4][t&0x0f];
      }
    }
  }

  StateBlock ShiftRows(StateBlock state) {
    StateBlock a;
    for(uint8_t i=0;i<4;i++){
      for(uint8_t j=0;j<4;j++){
        a.arr[i][j] = state.arr[i][(j+i)%4];
      }
    }
    return a;
  }

  StateBlock MixColumns(StateBlock state) {
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

  void AddRoundKey(StateBlock &state, unsigned char *key) {
    uint8_t i, j;
    for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        //printf("%02x ", key[j + 4 * i]);
        state.arr[i][j] = state.arr[i][j] ^ key[i + 4 * j];
      }
    }
  }

  void GenRoundKey(const unsigned char prev_key[], unsigned char w[], uint8_t round){
    unsigned char temp[4];
    unsigned char rcon[4];
    uint8_t i = 0;
    for(i=0;i<16;i+=4) {
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

  void SubWord(unsigned char *a) {
    uint8_t i;
    for (i = 0; i < 4; i++) {
      a[i] = sbox[a[i]>>4][a[i]&0x0f];
    }
  }

  void RotWord(unsigned char *a) {
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
  }

  void XorWords(unsigned char *a, unsigned char *b, unsigned char *c) {
    uint8_t i;
    for (i = 0; i < 4; i++) {
      c[i] = a[i] ^ b[i];
    }
  }

  void Rcon(unsigned char *a, uint8_t n) {
    a[0] = RCON[n-1];
    a[1] = a[2] = a[3] = 0;
  }
    output_t o_result;
    sc_biguint<128> k;
    sc_biguint<128> p;
  void blocking_transport(tlm::tlm_generic_payload &payload, sc_core::sc_time &delay){
    wait(delay);
    // unsigned char *mask_ptr = payload.get_byte_enable_ptr();
    // auto len = payload.get_data_length();
    tlm::tlm_command cmd = payload.get_command();
    sc_dt::uint64 addr = payload.get_address();
    unsigned char *data_ptr = payload.get_data_ptr();
    //std::cout<<name()<<":"<<cmd<<":"<<addr<<std::endl;

    addr -= base_offset;


    // cout << (int)data_ptr[0] << endl;
    // cout << (int)data_ptr[1] << endl;
    // cout << (int)data_ptr[2] << endl;
    word buffer;

    switch (cmd) {
      case tlm::TLM_READ_COMMAND:
        // cout << "READ" << endl;
        switch (addr) {
          case SOBEL_FILTER_RESULT_ADDR:
            o_result = dout.read();
            for(uint8_t i=0;i<4;i++){
              data_ptr[i] = (sc_uint<8>)o_result.range(127-i*8, 120-i*8);
            }
            break;
          case SOBEL_FILTER_RESULT_ADDR+4:
            for(uint8_t i=4;i<8;i++){
              data_ptr[i-4] = (sc_uint<8>)o_result.range(127-i*8, 120-i*8);
            }
            break;
          case SOBEL_FILTER_RESULT_ADDR+8:
            for(uint8_t i=8;i<12;i++){
              data_ptr[i-8] = (sc_uint<8>)o_result.range(127-i*8, 120-i*8);
            }
            break;
          case SOBEL_FILTER_RESULT_ADDR+12:
            for(uint8_t i=12;i<16;i++){
              data_ptr[i-12] = (sc_uint<8>)o_result.range(127-i*8, 120-i*8);
            }
            break;
          case SOBEL_FILTER_CHECK_ADDR:
            buffer.uint = dout.num_available();
            data_ptr[0] = buffer.uc[0];
            data_ptr[1] = buffer.uc[1];
            data_ptr[2] = buffer.uc[2];
            data_ptr[3] = buffer.uc[3];
            break;
          default:
            std::cerr << "READ Error! "<<name()<<": AES128::blocking_transport: address 0x"
                      << std::setfill('0') << std::setw(8) << std::hex << addr
                      << std::dec << " is not valid" << std::endl;
          }
        
        break;
      case tlm::TLM_WRITE_COMMAND:
        // cout << "WRITE" << endl;
        switch (addr) {
          case SOBEL_FILTER_R_ADDR:
            for(int i=0;i<4;i++){
              k.range(127-i*8, 120-i*8) = data_ptr[i];
            }
            break;
          case SOBEL_FILTER_R_ADDR+4:
            for(int i=4;i<8;i++){
              k.range(127-i*8, 120-i*8) = data_ptr[i-4];
            }
            break;
          case SOBEL_FILTER_R_ADDR+8:
            for(int i=8;i<12;i++){
              k.range(127-i*8, 120-i*8) = data_ptr[i-8];
            }
            break;
          case SOBEL_FILTER_R_ADDR+12:
            for(int i=12;i<16;i++){
              k.range(127-i*8, 120-i*8) = data_ptr[i-12];
            }
            key_in.write(k);
            break;
          case SOBEL_FILTER_R_ADDR+16:
            for(int i=0;i<4;i++){
              p.range(127-i*8, 120-i*8) = data_ptr[i];
            }
            break;
          case SOBEL_FILTER_R_ADDR+20:
            for(int i=4;i<8;i++){
              p.range(127-i*8, 120-i*8) = data_ptr[i-4];
            }
            break;
          case SOBEL_FILTER_R_ADDR+24:
            for(int i=8;i<12;i++){
              p.range(127-i*8, 120-i*8) = data_ptr[i-8];
            }
            break;
          case SOBEL_FILTER_R_ADDR+28:
            for(int i=12;i<16;i++){
              p.range(127-i*8, 120-i*8) = data_ptr[i-12];
            }
            plaintext_in.write(p);
            break;
          default:
            std::cerr << "WRITE Error! "<<name()<<": AES128::blocking_transport: address 0x"
                      << std::setfill('0') << std::setw(8) << std::hex << addr
                      << std::dec << " is not valid" << std::endl;
        }
        break;
      case tlm::TLM_IGNORE_COMMAND:
        payload.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
      default:
        payload.set_response_status(tlm::TLM_GENERIC_ERROR_RESPONSE);
        return;
      }
      payload.set_response_status(tlm::TLM_OK_RESPONSE); // Always OK
  }
};
#endif

