#include "iface.hpp"

#include <iostream>
#include <algorithm>
#include <string>

template <typename ENCRYPTOR>
int encryption  (ENCRYPTOR& encr, int cnt_iter, std::ifstream& inf, std::ofstream& outf){
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
int decryption  (ENCRYPTOR& encr, int cnt_iter, std::ifstream& inf, std::ofstream& outf){
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
void read_block  (ENCRYPTOR& encr, std::ifstream& inf ){
  std::string str;
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
void write_block (ENCRYPTOR& encr, std::ofstream& outf){
  outf.write(encr.getMSG().c_str(), encr.countPlainTextSymbols());
};


uint calc_count_iteration(uint file_bitsize, uint block_bitsize){
  uint cnt_iter = file_bitsize / block_bitsize;

  if(file_bitsize % block_bitsize != 0)
    ++cnt_iter;

  return cnt_iter;
};


int get_pos_elem(const std::vector<CFile>& v, const std::string& elem){
  for(int i = 0; i < v.size(); i++)
    if(v[i].get_path() == elem)
      return i;

  return -1;
};

int get_pos_elem(const std::vector<std::string>& v, const std::string& elem){
  for(int i = 0; i < v.size(); i++)
    if(v[i] == elem)
      return i;

  return -1;
};


void DES_ALG (const std::vector<CFile>& files, Operation oper){
  DES             encryptor = DES();
  std::string     key, file_name;
  uint            cnt_iter; 
  std::ifstream   infile;
  std::ofstream   outfile;

  std::cout  << "[*] Enter key phrase (key should have length is 8 symbols): ";
  std::cin   >> key;

  encryptor.setKEY(key);

  for(const CFile& file : files){
    infile. open( file.get_path(), std::ios::binary);

    cnt_iter =  calc_count_iteration(
                  file.get_bit_size(), 
                  encryptor.countPlainTextBits()
                );

    switch (oper){
      case Operation::ENCR:
        outfile.open(("ENC_" + file.get_path()), std::ios::binary);
        if(encryption(encryptor, cnt_iter, infile, outfile) < 0)
          std::cout << "[!] Error encryption \n\n";
        break;

      case Operation::DECR:
        outfile.open(("DEC_" + file.get_path()), std::ios::binary);
        if(decryption(encryptor, cnt_iter, infile, outfile) < 0)
          std::cout << "[!] Error decryption \n\n";
        break;
    }
  }

  infile. close();
  outfile.close();
};


void DESX_ALG(const std::vector<CFile>& files, Operation oper){
  DESX            encryptor = DESX();
  std::string     key, key1, key2, file_name;
  uint            cnt_iter; 
  std::ifstream   infile;
  std::ofstream   outfile;

  std::cout  << "[*] Enter key  phrase (key should have length is 8 symbols): ";
  std::cin   >> key;
  std::cout  << "[*] Enter key1 phrase (key should have length is 8 symbols): ";
  std::cin   >> key1;
  std::cout  << "[*] Enter key2 phrase (key should have length is 8 symbols): ";
  std::cin   >> key2;

  encryptor.setKEY (key );
  encryptor.setKEY1(key1);
  encryptor.setKEY2(key2);

  for(const CFile& file : files){
    infile. open( file.get_path(), std::ios::binary );

    cnt_iter =  calc_count_iteration(
                  file.get_bit_size(), 
                  encryptor.countPlainTextBits()
                );
    
    switch (oper){
      case Operation::ENCR:
        outfile.open(("ENC_" + file.get_path()), std::ios::binary);
        if(encryption(encryptor, cnt_iter, infile, outfile) < 0)
          std::cout << "[!] Error encryption \n\n";
        break;

      case Operation::DECR:
        outfile.open(("DEC_" + file.get_path()), std::ios::binary);
        if(decryption(encryptor, cnt_iter, infile, outfile) < 0)
          std::cout << "[!] Error decryption \n\n";
        break;
    }
  }

  infile. close();
  outfile.close();
};
