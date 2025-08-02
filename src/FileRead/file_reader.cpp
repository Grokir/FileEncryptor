#include "file_reader.hpp"

#include <fstream>


CFile::CFile() = default;

CFile::CFile(const std::string path) {
  this->init(path);
};

bool CFile::init(const std::string path) {
  std::ifstream in(path);
  in.seekg(0, std::ios::end);
  this->m_file_size = in.tellg();
  
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