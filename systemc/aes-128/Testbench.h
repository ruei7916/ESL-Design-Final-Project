#ifndef TESTBENCH_H_
#define TESTBENCH_H_

#include "defines.h"
#include <string>
using namespace std;
#include <systemc>
using namespace sc_core;

#ifndef NATIVE_SYSTEMC
#include <cynw_p2p.h>
#endif


class Testbench : public sc_module {
public:
	sc_in_clk i_clk;
	sc_out < bool >  o_rst;
#ifndef NATIVE_SYSTEMC
	cynw_p2p<sc_biguint<128>>::base_out o_key;
  cynw_p2p<sc_biguint<128>>::base_out o_plaintext;
	cynw_p2p<output_t>::base_in i_result;
#else
	sc_fifo_out<sc_biguint<128>> o_key;
  sc_fifo_out<sc_biguint<128>> o_plaintext;
	sc_fifo_in<output_t> i_result;
#endif

  SC_HAS_PROCESS(Testbench);

  Testbench(sc_module_name n);
  ~Testbench();

  long GetFileSize(string filename);
  int read_plaintext(string infile_name);
  int read_key(string infile_name);
  int write_ciphertext(string outfile_name);
 

private:
  int clock_cycle( sc_time time );
  void printblock(sc_biguint<128>b);
  void source();
  void sink();
  long input_file_size;
  int num_of_blocks;
  unsigned char *input_plaintext;
  unsigned char *output_ciphertext;
  unsigned char input_key[16];
  sc_time sent_time, first_recv_time, last_recv_time;
  unsigned long latency;
};
#endif
