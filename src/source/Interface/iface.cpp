#include "Interface/iface.hpp"

#include <iostream>
#include <algorithm>
#include <string>
#include <bitset>

#include "../progressbar/progressbar.hpp"
#include "DES/des.hpp"
#include "DESX/desx.hpp"
#include "AES/aes.hpp"
#include "SHA-2/sha256.hpp"

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
int rewrite_encrypt  (ENCRYPTOR& encr, int cnt_iter, std::fstream& filestream){
  int sz_block = encr.countPlainTextSymbols();
  // std::vector<char> buf(sz_block);

  char* buf = new char[sz_block];
    
  for(uint i = 0; i < cnt_iter; i++){
    
    // Установили курсор в начало блока
    filestream.seekg(sz_block * i, std::ios::beg);
    // filestream.seekp(encr.countPlainTextSymbols() * i, std::ios::beg);

    // Читаем блок
    filestream.read(buf, static_cast<std::streamsize>(sz_block));
    std::size_t read = static_cast<std::size_t>(filestream.gcount());
    if (read == 0)
        return -1;           // файл пустой – ничего делать не нужно

    // Выполнение операции
    // for (std::size_t i = 0; i < read; ++i)
    //     buf[i] ^= 0x2;

    encr.setMSG(std::string(buf));
    if(!encr.encrypt())
      return -2;

    // 3. Перемещаемся в начало блока
    filestream.seekp(sz_block * i, std::ios::beg);
    // filestream.seekp(encr.countPlainTextSymbols() * i, std::ios::beg);

    // 4. Записываем изменённый блок
    // filestream.write(encr.getMSG().c_str(), static_cast<std::streamsize>(read));
    filestream.write(encr.getMSG().c_str(), sz_block);


    // if(encr.decrypt())
    //   write_block(encr, outf);
    // else
    //   return -1;
  }
  return 0;
};

template <typename ENCRYPTOR>
int rewrite_decrypt  (ENCRYPTOR& encr, int cnt_iter, std::fstream& filestream){
  int sz_block = encr.countPlainTextSymbols();
  // std::vector<char> buf(sz_block);
  // std::string buf;
  char* buf = new char[sz_block];

  for(uint i = 0; i < cnt_iter; i++){

    filestream.seekg(sz_block * i, std::ios::beg);

    // 1. Читаем блок
    filestream.read(buf, static_cast<std::streamsize>(sz_block));
    std::size_t read = static_cast<std::size_t>(filestream.gcount());
    if (read == 0)
        return -1;           // файл пустой – ничего делать не нужно

    // 2. XOR
    // for (std::size_t i = 0; i < read; ++i)
    //     buf[i] ^= 0x2;

    encr.setMSG(std::string(buf));
    if(!encr.decrypt())
      return -2;

    // 3. Перемещаемся в начало файла
    filestream.seekp(sz_block * i, std::ios::beg);
    // filestream.seekp(encr.countPlainTextSymbols() * i, std::ios::beg);

    // 4. Записываем изменённый блок
    // filestream.write(encr.getMSG().c_str(), static_cast<std::streamsize>(read));
    filestream.write(encr.getMSG().c_str(), sz_block);


    // if(encr.decrypt())
    //   write_block(encr, outf);
    // else
    //   return -1;
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


std::vector<std::string> get_bin_keys(const std::string& key, uint bit_key_len){
  std::vector<std::string>  res;
  std::string               tmp;
 
  SHA256 hash(key);
  for(uint32_t num : hash.hexdigest()){
    tmp += std::bitset<32>(num).to_string();
    if(tmp.length() == bit_key_len){
      res.push_back(tmp);
      tmp.clear();
    }
  }

  if(!tmp.empty())
    res.push_back(tmp);
  
  return res;
};


void AES_ALG (const std::vector<CFile>& files, const std::string& key, Operation oper){
  AES             encryptor;
  std::string     out_file_name;
  uint            cnt_iter; 
  std::fstream    filestream;
  std::ifstream   infile;
  std::ofstream   outfile;

  progressbar     pbar(files.size());

  pbar.set_todo_char("");
  pbar.set_done_char("");
  pbar.set_opening_bracket_char("[*] Process: ");
  pbar.set_closing_bracket_char("");

  SHA256 hash(key);
  uint key_len = encryptor.countKeySymbols();
  std::vector<uint> hashkey;
  for(uint byte : hash.hexdigest()){
    hashkey.push_back(byte);
    if(hashkey.size() == key_len)
      break;
  }
  encryptor.setKEY(hashkey);


  for(const CFile& file : files){
    switch (oper){
      case Operation::ENCR:
        out_file_name = file.get_path() + "e";
        break;

      case Operation::DECR:
        out_file_name = file.get_path().substr(0, file.get_path().length()-1);
        break;
    }

    // filestream.open(file.get_path(),  std::ios::in | std::ios::out | std::ios::binary );

    infile. open( file.get_path(),  std::ios::binary );
    outfile.open( out_file_name,    std::ios::binary );

    cnt_iter =  calc_count_iteration(
                  file.get_bit_size(), 
                  encryptor.countPlainTextBits()
                );

    switch (oper){
      case Operation::ENCR:
        if(encryption(encryptor, cnt_iter, infile, outfile) < 0)
        // if(rewrite_encrypt(encryptor, cnt_iter, filestream) < 0)
          std::cout << "[!] Error encryption \n\n";
        break;

      case Operation::DECR:
        if(decryption(encryptor, cnt_iter, infile, outfile) < 0)
        // if(rewrite_decrypt(encryptor, cnt_iter, filestream) < 0)
          std::cout << "[!] Error decryption \n\n";
        break;
    }
    // filestream.close();
    infile. close();
    outfile.close();

    pbar.update();
  }
  
  fr::rm_file_list(files);
};


void DES_ALG (const std::vector<CFile>& files, const std::string& key, Operation oper){
  DES             encryptor;
  std::string     out_file_name;
  uint            cnt_iter; 
  std::fstream    filestream;
  std::ifstream   infile;
  std::ofstream   outfile;

  progressbar     pbar(files.size());

  pbar.set_todo_char("");
  pbar.set_done_char("");
  pbar.set_opening_bracket_char("[*] Process: ");
  pbar.set_closing_bracket_char("");

  encryptor.setBinaryKEY(
    get_bin_keys(key, encryptor.countPlainTextBits())[0]
  );

  for(const CFile& file : files){
    switch (oper){
      case Operation::ENCR:
        out_file_name = file.get_path() + "e";
        break;

      case Operation::DECR:
        out_file_name = file.get_path().substr(0, file.get_path().length()-1);
        break;
    }

    // filestream.open(file.get_path(),  std::ios::in | std::ios::out | std::ios::binary );

    infile. open( file.get_path(),  std::ios::binary );
    outfile.open( out_file_name,    std::ios::binary );

    cnt_iter =  calc_count_iteration(
                  file.get_bit_size(), 
                  encryptor.countPlainTextBits()
                );

    switch (oper){
      case Operation::ENCR:
        if(encryption(encryptor, cnt_iter, infile, outfile) < 0)
        // if(rewrite_encrypt(encryptor, cnt_iter, filestream) < 0)
          std::cout << "[!] Error encryption \n\n";
        break;

      case Operation::DECR:
        if(decryption(encryptor, cnt_iter, infile, outfile) < 0)
        // if(rewrite_decrypt(encryptor, cnt_iter, filestream) < 0)
          std::cout << "[!] Error decryption \n\n";
        break;
    }
    // filestream.close();
    infile. close();
    outfile.close();

    pbar.update();
  }
  
  fr::rm_file_list(files);
};


void DESX_ALG(const std::vector<CFile>& files, const std::string& key, Operation oper){
  DESX                      encryptor;
  std::string               out_file_name;
  uint                      cnt_iter; 
  std::ifstream             infile;
  std::ofstream             outfile;
  progressbar               pbar(files.size());
  std::vector<std::string>  binkeys = get_bin_keys(key, encryptor.countPlainTextBits());

  pbar.set_todo_char("");
  pbar.set_done_char("");
  pbar.set_opening_bracket_char("[*] Process: ");
  pbar.set_closing_bracket_char("");


  encryptor.setBinaryKEY (binkeys[0]);
  encryptor.setBinaryKEY1(binkeys[1]);
  encryptor.setBinaryKEY2(binkeys[2]);


  for(const CFile& file : files){
    switch (oper){
      case Operation::ENCR:
        out_file_name = file.get_path() + "e";
        break;

      case Operation::DECR:
        out_file_name = file.get_path().substr(0, file.get_path().length()-1);
        break;
    }


    infile. open( file.get_path(),  std::ios::binary );
    outfile.open( out_file_name,    std::ios::binary );

    cnt_iter =  calc_count_iteration(
                  file.get_bit_size(), 
                  encryptor.countPlainTextBits()
                );
    
    switch (oper){
      case Operation::ENCR:
        if(encryption(encryptor, cnt_iter, infile, outfile) < 0)
          std::cout << "[!] Error encryption \n\n";
        break;

      case Operation::DECR:
        if(decryption(encryptor, cnt_iter, infile, outfile) < 0)
          std::cout << "[!] Error decryption \n\n";
        break;
    }
    
    pbar.update();

    infile. close();
    outfile.close();
  }

  fr::rm_file_list(files);
};
