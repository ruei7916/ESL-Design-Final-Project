#include <iostream>
using namespace std;
#include "src/AES.h"
unsigned char key[] = {"fe1234567890abcd"}; //plaintext example
unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00 }; //key example
unsigned int plainLen = 16 * sizeof(unsigned char);  //bytes in plaintext

AES aes(AESKeyLength::AES_128);  ////128 - key length, can be 128, 192 or 256
unsigned char *c = new unsigned char[30];
//now variable c contains plainLen bytes - ciphertext
int main(){
    c = aes.EncryptECB(plain, plainLen, key);
    //cout<<c<<endl;
    cout<<endl;
    //aes.printHexArray(c,16);
    return 0;
}
