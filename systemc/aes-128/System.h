#ifndef SYSTEM_H_
#define SYSTEM_H_
#include <systemc>
#include "defines.h"
using namespace sc_core;

#include "Testbench.h"
#ifndef NATIVE_SYSTEMC
#include "AES128_wrap.h"
#else
#include "AES128.h"
#endif

class System: public sc_module
{
public:
	SC_HAS_PROCESS( System );
	System( sc_module_name n,  std::string input_key, std::string input_bmp, std::string output_bmp );
	~System();
private:
  Testbench tb;
#ifndef NATIVE_SYSTEMC
	AES128_wrapper dut;
#else
	AES128 dut;
#endif
	sc_clock clk;
	sc_signal<bool> rst;
#ifndef NATIVE_SYSTEMC
	cynw_p2p<sc_biguint<128>> key;
	cynw_p2p<sc_biguint<128>> plaintext;
	cynw_p2p< output_t > result;
#else
	sc_fifo<sc_biguint<128>> key;
	sc_fifo<sc_biguint<128>> plaintext;
	sc_fifo< output_t > result;
#endif
	std::string _output_bmp;
};
#endif
