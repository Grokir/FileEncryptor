#include <cstdint>
#include <string>

#ifndef FILE_READER
  #define FILE_READER

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
  };

#endif

