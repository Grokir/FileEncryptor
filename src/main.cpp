#include <iostream>
#include <fstream>

#include "DES/des.hpp"
#include "DESX/desx.hpp"
#include "FileRead/file_reader.hpp"

using namespace std;

template <typename ENCRYPTOR>
void read_block  (ENCRYPTOR& encr, ifstream& inf );

template <typename ENCRYPTOR>
void write_block (ENCRYPTOR& encr, ofstream& outf);


template <typename ENCRYPTOR>
int encryption  (ENCRYPTOR& encr, int cnt_iter, ifstream& inf, ofstream& outf);

template <typename ENCRYPTOR>
int decryption  (ENCRYPTOR& encr, int cnt_iter, ifstream& inf, ofstream& outf);

uint calc_count_iteration(uint file_bitsize, uint block_bitsize);

void DES_ALG ();
void DESX_ALG();

int main(int argc, char** argv) {
  if(argc < 2){
    cout << "[!] Invalid num of agruments!" << endl;
    return -3;
  }
  
  if(string(argv[1]) == "--des")
    DES_ALG();
  else if(string(argv[1]) == "--desx")
    DESX_ALG();
  else
    cout << "[!] Error algs flag:\n" 
         << "     --des \n"   
         << "     --desx\n";


  return 0;
};


template <typename ENCRYPTOR>
int encryption  (ENCRYPTOR& encr, int cnt_iter, ifstream& inf, ofstream& outf){
  for(uint i = 0; i < cnt_iter; i++){
    read_block(encr, inf);
    if(encr.encrypt())
      write_block(encr, outf);
    else
      return -1;
  }
  return 0;
};

template <typename ENCRYPTOR>
int decryption  (ENCRYPTOR& encr, int cnt_iter, ifstream& inf, ofstream& outf){
  for(uint i = 0; i < cnt_iter; i++){
    read_block(encr, inf);
    if(encr.decrypt())
      write_block(encr, outf);
    else
      return -1;
  }
  return 0;
};



template <typename ENCRYPTOR>
void read_block  (ENCRYPTOR& encr, ifstream& inf ){
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

template <typename ENCRYPTOR>
void write_block (ENCRYPTOR& encr, ofstream& outf){
  outf.write(encr.getMSG().c_str(), encr.countPlainTextSymbols());
};

uint calc_count_iteration(uint file_bitsize, uint block_bitsize){
  uint cnt_iter = file_bitsize / block_bitsize;

  if(file_bitsize % block_bitsize != 0)
    ++cnt_iter;

  return cnt_iter;
};


void DES_ALG (){
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

  cout << "[+] Process: DONE" << endl;
};
void DESX_ALG(){
  DESX      encryptor = DESX();
  string    key, key1, key2, file_name;
  CFile     file;
  uint      cnt_iter; 
  ifstream  infile;
  ofstream  outfile;

  cout  << "[*] Enter key  phrase (key should have length is 8 symbols): ";
  cin   >> key;
  cout  << "[*] Enter key1 phrase (key should have length is 8 symbols): ";
  cin   >> key1;
  cout  << "[*] Enter key2 phrase (key should have length is 8 symbols): ";
  cin   >> key2;

  encryptor.setKEY (key );
  encryptor.setKEY1(key1);
  encryptor.setKEY2(key2);

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

  cout << "[+] Process: DONE" << endl;
};
