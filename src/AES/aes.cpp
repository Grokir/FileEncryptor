#include "aes.hpp"


AES::AES() = default;

AES::AES(const uint& bin_msg_len, const uint& bin_key_len){
  this->size_of_block = bin_msg_len;
  this->size_of_key   = bin_key_len;

  if(this->size_of_block == 192)
    this->round_count = 12;
  
  if(this->size_of_block == 256)
    this->round_count = 14;
};