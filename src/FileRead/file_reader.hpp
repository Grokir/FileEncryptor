#pragma once

#ifndef FILE_READER
  #define FILE_READER

  #include <cstdint>
  #include <string>
  #include <vector>


  #define BITLEN 8

  class CFile {
    private:
      std::string   m_file_path = "";
      std::int32_t  m_file_size = -1; // len in bytes
    
    public:
      CFile();
      CFile(const std::string path);
      
      bool  init(const std::string path);
      
      const std::int32_t get_size()     const;
      const std::int64_t get_bit_size() const; 
      const std::string  get_path()     const;
  };

  enum class ObjectType{
    FILE,
    DIR
  };

  namespace fr{
    std::string         byte_to_bin   (char byte);
    char                bin_to_byte   (const std::string& binstr);

    std::vector<CFile>  get_file_list (const std::string path);
    std::vector<CFile>  get_file_list (const std::string path);
  };

#endif

