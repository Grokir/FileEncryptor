#include "aes.hpp"

#include <bitset>
#include <map>

#include <cstdio>


const std::vector<std::vector<uint>> SubBytes_table = {
  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
  {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
  {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
  {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
  {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
  {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
  {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
  {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
  {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
  {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
  {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
  {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
  {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
  {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
  {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
  {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

void ShiftRows(std::vector<std::vector<int>>& matr) {
  for(int i = 1; i < matr.size(); i++){
    for(int k = 0; k < i; k++){
      int tmp = matr[i][0];
      
      for(int j = 1; j < matr[i].size(); i++)
        matr[i][j-1] = matr[i][j];
      
      matr[i][matr[i].size() - 1] = tmp;
    }
  }
};

uint SubByte(uint byte) {
  std::string binstr = std::bitset<8>(byte).to_string();
  uint x = std::bitset<8>(binstr.substr(0, 4)).to_ulong();
  uint y = std::bitset<8>(binstr.substr(4, 4)).to_ulong();
  return SubBytes_table[x][y];
};




//########   CLASS METHODS   ########

AES::AES() = default;

AES::AES(const uint& bin_msg_len, const uint& bin_key_len){
  this->size_of_block = bin_msg_len;
  this->size_of_key   = bin_key_len;

  if(this->size_of_key == 192)
    this->round_count = 12;
  
  if(this->size_of_key == 256)
    this->round_count = 14;
};

void AES::setKEY(const std::string& key) {
  this->clear_bin_str(this->binkey);
  // this->key.clear();
  // this->key.resize( size_of_key  / size_of_char ); /// 7 символов

  std::string binstr;
  std::size_t k = 0;
  
  for(int i = 0; ( i < ( size_of_key / size_of_char ) ) && ( i < key.size() ); i++){
    // this->key[i] = key[i];

    binstr = std::bitset<8>(key[i]).to_string();
    
    for(int j = 0; j < binstr.size(); j++){
      this->binkey[k] = char_to_binint(binstr[j]);
      ++k;
    }
  }
};

void AES::setMSG(const std::string& msg) {
  this->clear_bin_str(this->binmsg);
  // this->msg.clear();
  // this->msg.resize( size_of_block / size_of_char ); /// 8 символов

  std::string binstr;
  std::size_t k = 0;
  int i = 0;
  for(; ( i < ( size_of_block / size_of_char ) ) && ( i < msg.size() ); i++){
    // this->msg[i] = msg[i];
    
    binstr = std::bitset<8>(msg[i]).to_string();

    for(int j = 0; j < binstr.size(); j++){
      this->binmsg[k] = char_to_binint(binstr[j]);
      ++k;
    }
  }
};

std::string AES::getMSG() {
  std::string binstr = "";
  std::string    res = "";

  for(int i = 0; i < binmsg.size(); i++){
    binstr += binint_to_char(binmsg[i]); /// получаем 0 или 1 в символьном виде
    if( binstr.size() == size_of_char ){
      /// Если насчитали кол-во бит равное размеру символа, то
      /// из бинарнорого вида получаем ASCII код символа
      res += static_cast<char>(std::bitset<8>(binstr).to_ulong());
      binstr.clear();
    }
  }
  return res;
};

void AES::setBinaryKEY(const std::string& binkey) {
  this->clear_bin_str(this->binkey);

  for(int i = 0; ( i < size_of_block ) && ( i < binkey.size() ); i++){
    this->binkey[i] = char_to_binint(binkey[i]);
  }
};

// void AES::setBinaryMSG(const std::string& binmsg) {
//   this->clear_bin_str(this->binmsg);

//   for(int i = 0; ( i < size_of_block ) && ( i < binmsg.size() ); i++){
//     this->binmsg[i] = char_to_binint(binmsg[i]);
//   }
// };

// std::string AES::getBinaryMSG() {
//   std::string res = "";

//   for(std::size_t i = 0; i < size_of_block; i++)
//     res += binint_to_char(this->binmsg[i]);

//   return res;
// };

const uint AES::countPlainTextBits() const {
  return size_of_block;
};

const uint AES::countPlainTextSymbols() const {
  return ( size_of_block / size_of_char );
};

const uint AES::countKeyBits() const {
  return size_of_key;
};

const uint AES::countKeySymbols() const {
  return size_of_key / size_of_char;
};

void AES::clear_bin_str(std::vector<uint> &v){
  for(std::size_t i = 0; i < v.size(); i++)
    v[i] = 0;
};

uint AES::char_to_binint(char ch){
  if( ch == '0' ) return 0;
  return 1;
};

char AES::binint_to_char(int i){
  return static_cast<char>(i + 48);
};