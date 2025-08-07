#include "aes.hpp"

#include <bitset>


AES::AES() = default;

AES::AES(const uint& bin_msg_len, const uint& bin_key_len){
  this->size_of_block = bin_msg_len;
  this->size_of_key   = bin_key_len;

  if(this->size_of_block == 192)
    this->round_count = 12;
  
  if(this->size_of_block == 256)
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

void AES::setBinaryMSG(const std::string& binmsg) {
  this->clear_bin_str(this->binmsg);

  for(int i = 0; ( i < size_of_block ) && ( i < binmsg.size() ); i++){
    this->binmsg[i] = char_to_binint(binmsg[i]);
  }
};

std::string AES::getBinaryMSG() {
  std::string res = "";

  for(std::size_t i = 0; i < size_of_block; i++)
    res += binint_to_char(this->binmsg[i]);

  return res;
};

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