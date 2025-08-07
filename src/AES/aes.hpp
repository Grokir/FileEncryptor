#pragma once

#ifndef AES_H
  
  #define AES_H


  #include <cstdint>
  #include <vector>
  #include <string>

  class AES{
    private:
      uint              size_of_block = 128;   /// в битах
      const uint        size_of_char  =   8;   /// в битах
      uint              size_of_key   =  56;   /// в битах
      uint              round_count   =  10;

      std::vector<uint> binkey;               /// длина ключа  56 бита
      std::vector<uint> binmsg;               /// длина текста 64 бита

    public:
      AES();
      AES(const uint& bin_msg_len, const uint& bin_key_len);

      void        setKEY(const std::string& key);
      void        setMSG(const std::string& msg);
      std::string getMSG();

      void        setBinaryKEY(const std::string& binkey);
      void        setBinaryMSG(const std::string& binmsg);
      std::string getBinaryMSG();
      
      const uint  countPlainTextBits()    const;
      const uint  countPlainTextSymbols() const;
      const uint  countKeyBits()          const;
      const uint  countKeySymbols()       const;

      bool        encrypt();
      bool        decrypt();

    private:
      void clear_bin_str(std::vector<uint>& v);
      uint char_to_binint ( char ch );
      char binint_to_char ( int  i  );
  }; 

#endif