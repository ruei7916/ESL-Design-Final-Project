# EE6470 ESL Design Final project
AES-128 Encryption


## things inside each folder
- `c++`  
  C++ implementation of AES algorithm.  
  Forked from [https://github.com/SergeyBel/AES](https://github.com/SergeyBel/AES).
- `systemc`  
  systemc implementation
- `riscv-vp`  
  software and vp for riscv-vp

## usage
### SystemC
```bash
cd systemc/aes-128
mkdir build
cd build
cmake ..
make run
```
### Stratus
```bash
cd systemc/aes-128/stratus
make sim_V_DPA
```
### riscv-vp
- copy the files to working directory
  ```bash
  cp -r riscv-vp/vp/* $EE6470/riscv-vp/vp/src/platform
  cp -r riscv-vp/sw/* $EE6470/riscv-vp/sw
  ```
- build the "acc-mc" platform  
  ```bash
  cd $EE6470
  cd riscv-vp/vp/build
  cmake ..
  make install
  ```
- build the software
  ```bash
  cd $EE6470
  cd riscv-vp/sw
  cd aes128
  make
  ```
- run the simulation
  ```bash
  make sim
  ```
- check the result
  ```bash
  diff out golden.dat
  ```
