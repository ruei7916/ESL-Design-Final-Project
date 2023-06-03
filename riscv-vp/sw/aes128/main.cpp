#include "string.h"
#include "assert.h"
#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/types.h>


union word {
  int sint;
  unsigned int uint;
  unsigned char uc[4];
};

// ACC
static char* const AES128_0_START_ADDR = reinterpret_cast<char* const>(0x73000000);
static char* const AES128_1_START_ADDR = reinterpret_cast<char* const>(0x74000000);
static char* const AES128_0_READ_ADDR  = reinterpret_cast<char* const>(0x73000010);
static char* const AES128_1_READ_ADDR  = reinterpret_cast<char* const>(0x74000010);
static char* const AES128_0_CHECK_ADDR  = reinterpret_cast<char* const>(0x73000008);
static char* const AES128_1_CHECK_ADDR  = reinterpret_cast<char* const>(0x74000008);

// DMA0
static volatile uint32_t * const DMA0_SRC_ADDR  = (uint32_t * const)0x70000000;
static volatile uint32_t * const DMA0_DST_ADDR  = (uint32_t * const)0x70000004;
static volatile uint32_t * const DMA0_LEN_ADDR  = (uint32_t * const)0x70000008;
static volatile uint32_t * const DMA0_OP_ADDR   = (uint32_t * const)0x7000000C;
static volatile uint32_t * const DMA0_STAT_ADDR = (uint32_t * const)0x70000010;
// DMA1
static volatile uint32_t * const DMA1_SRC_ADDR  = (uint32_t * const)0x70002000;
static volatile uint32_t * const DMA1_DST_ADDR  = (uint32_t * const)0x70002004;
static volatile uint32_t * const DMA1_LEN_ADDR  = (uint32_t * const)0x70002008;
static volatile uint32_t * const DMA1_OP_ADDR   = (uint32_t * const)0x7000200C;
static volatile uint32_t * const DMA1_STAT_ADDR = (uint32_t * const)0x70002010;

static const uint32_t DMA_OP_MEMCPY = 1;

bool _is_using_dma = false;

  //int clock_cycle( sc_time time );
  //void printblock(sc_biguint<128>b);
  long input_file_size;
  int num_of_blocks;
  unsigned char *input_plaintext;
  unsigned char *output_ciphertext;
  unsigned char input_key[16];
  //sc_time sent_time, first_recv_time, last_recv_time;
  //unsigned long latency;
  unsigned char buffer0[32];
  unsigned char buffer1[32];
  bool ready = false;

  //Total number of cores
  //static const int PROCESSORS = 2;
  #define PROCESSORS 2
  //the barrier synchronization objects
  uint32_t barrier_counter=0; 
  uint32_t barrier_lock; 
  uint32_t barrier_sem; 

long GetFileSize(char* filename)
{
    struct stat stat_buf;
    int rc = stat(filename, &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

int read_plaintext(char* infile_name){
  input_file_size = 16384;//GetFileSize(infile_name);
  printf("input file size: %ld\n", input_file_size);
  num_of_blocks = input_file_size / 16;
  printf("numbers of blocks: %d\n",num_of_blocks);
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
  fp_s = fopen(infile_name, "rb");
  if (fp_s == NULL) {
    printf("fopen %s error\n", infile_name);
    return -1;
  }
  fread(input_plaintext, sizeof(unsigned char),
        (size_t)input_file_size, fp_s);
  fclose(fp_s);
  return 0;
}

int read_key(char* infile_name){
  FILE *fp_s = NULL; // source file handler
  fp_s = fopen(infile_name, "rb");
  if (fp_s == NULL) {
    printf("fopen %s error\n", infile_name);
    return -1;
  }
  fread(input_key, sizeof(unsigned char),
        (size_t)16, fp_s);
  fclose(fp_s);
  return 0;
}


int write_ciphertext(char* outfile_name){
  FILE *fp_t = NULL;
  fp_t = fopen(outfile_name, "wb");
  if (fp_t == NULL) {
    printf("fopen %s error\n", outfile_name);
    return -1;
  }
  fwrite(output_ciphertext, sizeof(unsigned char),
         (size_t)input_file_size, fp_t);

  fclose(fp_t);
  return 0;
}

int sem_init (uint32_t *__sem, uint32_t count) __THROW
{
  *__sem=count;
  return 0;
}

int sem_wait (uint32_t *__sem) __THROW
{
  uint32_t value, success; //RV32A
  __asm__ __volatile__("\
L%=:\n\t\
     lr.w %[value],(%[__sem])            # load reserved\n\t\
     beqz %[value],L%=                   # if zero, try again\n\t\
     addi %[value],%[value],-1           # value --\n\t\
     sc.w %[success],%[value],(%[__sem]) # store conditionally\n\t\
     bnez %[success], L%=                # if the store failed, try again\n\t\
"
    : [value] "=r"(value), [success]"=r"(success)
    : [__sem] "r"(__sem)
    : "memory");
  return 0;
}

int sem_post (uint32_t *__sem) __THROW
{
  uint32_t value, success; //RV32A
  __asm__ __volatile__("\
L%=:\n\t\
     lr.w %[value],(%[__sem])            # load reserved\n\t\
     addi %[value],%[value], 1           # value ++\n\t\
     sc.w %[success],%[value],(%[__sem]) # store conditionally\n\t\
     bnez %[success], L%=                # if the store failed, try again\n\t\
"
    : [value] "=r"(value), [success]"=r"(success)
    : [__sem] "r"(__sem)
    : "memory");
  return 0;
}

int barrier(uint32_t *__sem, uint32_t *__lock, uint32_t *counter, uint32_t thread_count) {
	sem_wait(__lock);
	if (*counter == thread_count - 1) { //all finished
		*counter = 0;
		sem_post(__lock);
		for (int j = 0; j < thread_count - 1; ++j) sem_post(__sem);
	} else {
		(*counter)++;
		sem_post(__lock);
		sem_wait(__sem);
	}
	return 0;
}


void write_data_to_ACC0(char* ADDR, unsigned char* buffer, int len){
  if(_is_using_dma){  
    // Using DMA 
    *DMA0_SRC_ADDR = (uint32_t)(buffer);
    *DMA0_DST_ADDR = (uint32_t)(ADDR);
    *DMA0_LEN_ADDR = len;
    *DMA0_OP_ADDR  = DMA_OP_MEMCPY;
  }else{
    // Directly Send
    memcpy(ADDR, buffer, sizeof(unsigned char)*len);
  }
}
void read_data_from_ACC0(char* ADDR, unsigned char* buffer, int len){
  if(_is_using_dma){
    // Using DMA 
    *DMA0_SRC_ADDR = (uint32_t)(ADDR);
    *DMA0_DST_ADDR = (uint32_t)(buffer);
    *DMA0_LEN_ADDR = len;
    *DMA0_OP_ADDR  = DMA_OP_MEMCPY;
  }else{
    // Directly Read
    memcpy(buffer, ADDR, sizeof(unsigned char)*len);
  }
}

void write_data_to_ACC1(char* ADDR, unsigned char* buffer, int len){
  if(_is_using_dma){  
    // Using DMA 
    *DMA1_SRC_ADDR = (uint32_t)(buffer);
    *DMA1_DST_ADDR = (uint32_t)(ADDR);
    *DMA1_LEN_ADDR = len;
    *DMA1_OP_ADDR  = DMA_OP_MEMCPY;
  }else{
    // Directly Send
    memcpy(ADDR, buffer, sizeof(unsigned char)*len);
  }
}
void read_data_from_ACC1(char* ADDR, unsigned char* buffer, int len){
  if(_is_using_dma){
    // Using DMA 
    *DMA1_SRC_ADDR = (uint32_t)(ADDR);
    *DMA1_DST_ADDR = (uint32_t)(buffer);
    *DMA1_LEN_ADDR = len;
    *DMA1_OP_ADDR  = DMA_OP_MEMCPY;
  }else{
    // Directly Read
    memcpy(buffer, ADDR, sizeof(unsigned char)*len);
  }
}


int main(unsigned hart_id) {
  /*int a=0;
	for (unsigned i=0; i<100*hart_id; ++i){
		a=a+1;
	}
  printf("hard-id=%d a=%d\n", hart_id, a);
  */
  
  if(hart_id==0){
    sem_init(&barrier_lock ,1);
    sem_init(&barrier_sem, 0); //lock all cores initially

    read_key("key");
    printf("key:  ");
    for(int i=0;i<16;i++){
      printf("%x ", input_key[i]);
    }
    printf("\n\n");
    read_plaintext("plaintext");
    memcpy(buffer0, input_key, 16);
    memcpy(buffer1, input_key, 16);
    ready = true;
  }

  
  if(hart_id==0){
    int current_block_0 = 0;
    for(;current_block_0<(num_of_blocks/2);current_block_0++){
      //printf("core %d: current block   %d\n", hart_id, current_block_0);
      memcpy(buffer0+16, input_plaintext+(current_block_0*16), 16);
      write_data_to_ACC0(AES128_0_START_ADDR, buffer0, 32);
      
      word data0;
      int output_num0=0;
      do{
        read_data_from_ACC0(AES128_0_CHECK_ADDR, data0.uc, 4);
        output_num0 = data0.sint;
      }while(output_num0==0);
      read_data_from_ACC0(AES128_0_READ_ADDR, output_ciphertext+(current_block_0*16), 16);
    }
  }else{
    while(ready==false);
    int current_block_1 = num_of_blocks/2;
    //printf("%d %d\n",current_block_1,num_of_blocks);
    for(;current_block_1<num_of_blocks;current_block_1++){
      //printf("core %d: current block   %d\n", hart_id, current_block_1);
      memcpy(buffer1+16, input_plaintext+(current_block_1*16), 16);
      write_data_to_ACC1(AES128_1_START_ADDR, buffer1, 32);
      word data1;
      int output_num1=0;
      do{
        read_data_from_ACC1(AES128_1_CHECK_ADDR, data1.uc, 4);
        output_num1 = data1.sint;
      }while(output_num1==0);
      read_data_from_ACC1(AES128_1_READ_ADDR, output_ciphertext+(current_block_1*16), 16);
    }
  }

  barrier(&barrier_sem, &barrier_lock, &barrier_counter, PROCESSORS);
  if(hart_id==0){
    write_ciphertext("out");
  }
}
