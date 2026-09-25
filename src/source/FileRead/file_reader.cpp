#include "FileRead/file_reader.hpp"

#include <fstream>
#include <bitset>
#include <filesystem>
#include <random>
#include <cstdint>

#include <iostream>

CFile::CFile() = default;

CFile::CFile(const std::string& path) {
  this->init(path);
};

bool CFile::init(const std::string& path) {
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

const std::string CFile::get_path() const {
  return this->m_file_path;
};


//**************************************************


std::string fr::byte_to_bin(char byte){
  return std::bitset<BITLEN>(byte).to_string();
};

char fr::bin_to_byte(const std::string& binstr){
  return (char) std::bitset<BITLEN>(binstr.c_str()).to_ulong();
};

std::vector<CFile> fr::get_file_list(const std::string& path){
  std::vector<CFile> res;
  namespace fs  = std::filesystem;

  for (fs::recursive_directory_iterator i(path), end; i != end; ++i) 
    if (!is_directory(i->path()))
      res.push_back(CFile(i->path()));

  return res;
};

bool fr::rm_file_list(const std::vector<CFile>& list){
  // namespace fs = std::filesystem;
  for(const CFile& file : list)
    // if(!fs::remove(file.get_path()))
    if(!fr::wipe_and_remove(file.get_path(), 3))
      return false;

  return true;
};

bool fr::wipe_and_remove(const std::string& path, int passes) {
  namespace fs = std::filesystem;
  std::error_code ec;
  auto size = fs::file_size(path, ec);
  if (ec) return false;

  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);

  std::fstream out(path, std::ios::binary | std::ios::in | std::ios::out);
  if (!out.is_open()) return false;

  std::vector<char> buf(4096);

  for (int p = 0; p < passes; ++p) {
    out.seekp(0, std::ios::beg);
    std::uintmax_t written = 0;

    while (written < size) {
      std::size_t chunk = std::min<std::uintmax_t>(buf.size(), size - written);
      for (std::size_t i = 0; i < chunk; ++i)
        buf[i] = static_cast<char>(dist(gen));  // последний проход обычно делают нулями

      out.write(buf.data(), chunk);
      written += chunk;
    }
    out.flush();  // гарантирует, что данные дошли до ОС (но не обязательно до диска)
  }
  out.close();

  // опционально: затереть метаданные, переименовав файл перед удалением
  fs::remove(path, ec);
  return !ec;
}