#include "System.h"
System::System( sc_module_name n, std::string input_key, string input_bmp, string output_bmp ): sc_module( n ), 
  tb("tb"), dut("dut"), clk("clk", CLOCK_PERIOD, SC_NS), rst("rst"), _output_bmp(output_bmp)
{
  tb.i_clk(clk);
  tb.o_rst(rst);
  dut.i_clk(clk);
  dut.i_rst(rst);
  tb.o_key(key);
  tb.o_plaintext(plaintext);
  tb.i_result(result);
  dut.key_in(key);
  dut.plaintext_in(plaintext);
  dut.dout(result);
  
  tb.read_key(input_key);
  tb.read_plaintext(input_bmp);
}

System::~System() {
  tb.write_ciphertext(_output_bmp);
}
