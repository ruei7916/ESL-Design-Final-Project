#include "defines.h"
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
using namespace std;
using namespace sc_dt;
#include "Testbench.h"


Testbench::Testbench(sc_module_name n) : sc_module(n) {
  SC_THREAD(source);
  sensitive << i_clk.pos();
  dont_initialize();
  SC_THREAD(sink);
  sensitive << i_clk.pos();
  dont_initialize();
  #ifndef NATIVE_SYSTEMC
  o_key.clk_rst(i_clk, o_rst);
  o_plaintext.clk_rst(i_clk, o_rst);
  i_result.clk_rst(i_clk, o_rst);
  #endif
}

Testbench::~Testbench() {

}


long Testbench::GetFileSize(string filename)
{
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

int Testbench::read_plaintext(string infile_name){
  input_file_size = GetFileSize(infile_name);
  cout<<"input file size: "<<input_file_size<<endl;
  num_of_blocks = input_file_size / 16;
  cout<<"numbers of blocks: "<<num_of_blocks<<endl;
  input_plaintext = (unsigned char*)malloc((size_t)input_file_size);
  if (input_plaintext == NULL) {
    printf("malloc plaintext error\n");
    return -1;
  }
  output_ciphertext = (unsigned char*)malloc((size_t)input_file_size);
  if (output_ciphertext == NULL) {
    printf("malloc ciphertext error\n");
    return -1;
  }
  FILE *fp_s = NULL; // source file handler
  fp_s = fopen(infile_name.c_str(), "rb");
  if (fp_s == NULL) {
    printf("fopen %s error\n", infile_name.c_str());
    return -1;
  }
  fread(input_plaintext, sizeof(unsigned char),
        (size_t)input_file_size, fp_s);
  fclose(fp_s);
  return 0;
}

int Testbench::write_ciphertext(string outfile_name){
  FILE *fp_t = NULL;
  fp_t = fopen(outfile_name.c_str(), "wb");
  if (fp_t == NULL) {
    printf("fopen %s error\n", outfile_name.c_str());
    return -1;
  }
  fwrite(output_ciphertext, sizeof(unsigned char),
         (size_t)input_file_size, fp_t);

  fclose(fp_t);
  return 0;
}


int Testbench::read_key(string infile_name){
  FILE *fp_s = NULL; // source file handler
  fp_s = fopen(infile_name.c_str(), "rb");
  if (fp_s == NULL) {
    printf("fopen %s error\n", infile_name.c_str());
    return -1;
  }
  fread(input_key, sizeof(unsigned char),
        (size_t)16, fp_s);
  fclose(fp_s);
  return 0;
}

void Testbench::source() {
  #ifndef NATIVE_SYSTEMC
	o_key.reset();
  o_plaintext.reset();
  #endif
	o_rst.write(false);
	wait(5);
	o_rst.write(true);
	wait(1);
  sc_biguint<128> key,block_plaintext;
  key = 0;
  for(int i=0;i<16;i++){
    key.range(127-8*i,120-8*i) = input_key[i];
  }
  cout<<"key:        ";
  printblock(key);
  for(int i=0;i<num_of_blocks;i++){
    cout<<"."<<flush;
    if((i%64)==63)cout<<endl;
    //key = "0xff112233445566778899aabbccddeeff";
    //block_plaintext = "0x00112233445566778899aabbccddee00";
    for(int j=0;j<16;j++){
      block_plaintext.range(127-8*j,120-8*j) = input_plaintext[16*i+j];
    }
    //cout<<"plaintext:"<<endl;
    //printblock(block_plaintext);
    #ifndef NATIVE_SYSTEMC
    o_key.put(key);
    o_plaintext.put(block_plaintext);
    sent_time = sc_time_stamp();
    #else
    o_key.write(key);
    o_plaintext.write(block_plaintext);
    #endif
  }
}

void Testbench::sink(){
  #ifndef NATIVE_SYSTEMC
  i_result.reset();
  #endif
  for(int i=0;i<num_of_blocks;i++){
    wait();
    output_t ciphertext;
    #ifndef NATIVE_SYSTEMC
	  		ciphertext = i_result.get();
    #else
	  		ciphertext = i_result.read();
    #endif
    if(i==0)first_recv_time=sc_time_stamp();
    if(i==num_of_blocks-1)last_recv_time=sc_time_stamp();
    latency = clock_cycle( sc_time_stamp() - sent_time );
    //cout<<"ciphertext:\n";
    //printblock(ciphertext);
    for(int j=0;j<16;j++){
      *(output_ciphertext+16*i+j) = (sc_uint<8>)ciphertext.range(127-8*j, 120-8*j);
    }
  }
  cout<<"latency: "<<latency<<endl;
  cout<<"throughput: "<<clock_cycle(last_recv_time-first_recv_time)<<"(cycles)/"<<num_of_blocks<<"(blocks)"<<endl;
  sc_stop();

}


void Testbench::printblock(sc_biguint<128>b){
  for(int i=0;i<16;i++){
    cout<<b.range(127-8*i,120-8*i).to_string(SC_HEX_US, false)<<" ";
  }
  cout<<endl;
}

int Testbench::clock_cycle( sc_time time )
{
    sc_clock * clk_p = dynamic_cast< sc_clock * >( i_clk.get_interface() );
    sc_time clock_period = clk_p->period(); // get period from the sc_clock object.
    return ( int )( time / clock_period );
}