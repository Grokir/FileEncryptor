#include <iostream>
#include <fstream>

#include "DES/des.hpp"
#include "DESX/desx.hpp"
#include "FileRead/file_reader.hpp"

using namespace std;

void read_block  (DES& encr, ifstream& inf );
void write_block (DES& encr, ofstream& outf);

int encryption  (DES& encr, int cnt_iter, ifstream& inf, ofstream& outf);
int decryption  (DES& encr, int cnt_iter, ifstream& inf, ofstream& outf);

uint calc_count_iteration(uint file_bitsize, uint block_bitsize);

int GLB_cnt = 0;

int main(){

  DES       encryptor = DES();
  string    key, file_name;
  CFile     file;
  uint      cnt_iter; 
  ifstream  infile;
  ofstream  outfile;

  cout  << "[*] Enter key phrase (key should have length is 8 symbols): ";
  cin   >> key;

  encryptor.setKEY(key);

  cout  << "[*] Enter path to file: ";
  cin   >> file_name;

  file.   init( file_name                       );
  infile. open( file_name,           ios::binary);

  cout  << "[!] File size " << file.get_size() << " bytes\n";

  cnt_iter =  calc_count_iteration(
                file.get_bit_size(), 
                encryptor.countPlainTextBits()
              );

  char cmd;
  cout << "[*] Enter what do: (e)ncrtyption or (d)ecryption?  ";
  cin >> cmd;
  
  switch (cmd){
    case 'e':
      outfile.open(("ENC_" + file_name), ios::binary);
      if(encryption(encryptor, cnt_iter, infile, outfile) < 0)
        cout << "[!] Error encryption \n\n";
      break;

    case 'd':
      outfile.open(("DEC_" + file_name), ios::binary);
      if(decryption(encryptor, cnt_iter, infile, outfile) < 0)
        cout << "[!] Error decryption \n\n";
      break;
  }
  

  infile. close();
  outfile.close();

  cout << "\n[+] Process: DONE" << endl;
  return 0;
};



int encryption  (DES& encr, int cnt_iter, ifstream& inf, ofstream& outf){
  for(uint i = 0; i < cnt_iter; i++){
    read_block(encr, inf);
    if(encr.encrypt())
      write_block(encr, outf);
    else
      return -1;
  }
  return 0;
};

int decryption  (DES& encr, int cnt_iter, ifstream& inf, ofstream& outf){
  for(uint i = 0; i < cnt_iter; i++){
    read_block(encr, inf);
    if(encr.decrypt())
      write_block(encr, outf);
    else
      return -1;
  }
  return 0;
};



void read_block  (DES& encr, ifstream& inf ){
  string str;
  char buff;

  for(int i = 0; i < encr.countPlainTextSymbols(); ++i){
    inf.get(buff);

    if(!inf.eof())
      str += buff;
  }
  
  encr.setMSG(str);
  str.clear();
};

void write_block (DES& encr, ofstream& outf){
  outf.write(encr.getMSG().c_str(), encr.countPlainTextSymbols());
};

uint calc_count_iteration(uint file_bitsize, uint block_bitsize){
  uint cnt_iter = file_bitsize / block_bitsize;

  if(file_bitsize % block_bitsize != 0)
    ++cnt_iter;

  return cnt_iter;
};

