#pragma once

#include <fstream>

#include "../FileRead/file_reader.hpp"

using uint = unsigned int;

enum Operation{
  ENCR, /// encryption
  DECR  /// decryption
};


template <typename ENCRYPTOR>
void read_block  (ENCRYPTOR& encr, std::ifstream& inf );
template <typename ENCRYPTOR>
void write_block (ENCRYPTOR& encr, std::ofstream& outf);

template <typename ENCRYPTOR>
int encryption  (ENCRYPTOR& encr, int cnt_iter, std::ifstream& inf, std::ofstream& outf);
template <typename ENCRYPTOR>
int decryption  (ENCRYPTOR& encr, int cnt_iter, std::ifstream& inf, std::ofstream& outf);

template <typename ENCRYPTOR>
int rewrite_encrypt  (ENCRYPTOR& encr, int cnt_iter, std::fstream& filestream);
template <typename ENCRYPTOR>
int rewrite_decrypt  (ENCRYPTOR& encr, int cnt_iter, std::fstream& filestream);

uint calc_count_iteration(uint file_bitsize, uint block_bitsize);
int  get_pos_elem(const std::vector<std::string>& v,  const std::string& elem);
int  get_pos_elem(const std::vector<CFile>& v,        const std::string& elem);

std::vector<std::string> get_bin_keys(const std::string& key, uint bit_key_len);

void DES_ALG (const std::vector<CFile>& files, const std::string& key, Operation oper);
void DESX_ALG(const std::vector<CFile>& files, const std::string& key, Operation oper);
