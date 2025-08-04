#include "file_reader.hpp"

#include <fstream>
#include <bitset>

CFile::CFile() = default;

CFile::CFile(const std::string path) {
  this->init(path);
};

bool CFile::init(const std::string path) {
  std::ifstream in(path);
  in.seekg(0, std::ios::end);
  this->m_file_size = in.tellg();
  in.close();
  if (this->m_file_size < 0)
    return false;

  this->m_file_path = path;
  return true;
};

const std::int32_t CFile::get_size() const {
  return this->m_file_size;
};

const std::int64_t CFile::get_bit_size() const {
  return (this->m_file_size * 8);
};


//**************************************************


std::string fr::byte_to_bin(char byte){
  return std::bitset<BITLEN>(byte).to_string();
};

char fr::bin_to_byte(const std::string& binstr){
  return (char) std::bitset<BITLEN>(binstr.c_str()).to_ulong();
};