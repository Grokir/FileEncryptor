#ifndef AES_H
  
  #define AES_H

  #include <cstdint>
  #include <vector>
  #include <string>

  class AES{
    private:
      uint              size_of_key   = 128;   /// в битах
      uint              Nk            =   4;   
      uint              Nb            =   4;   
      uint              Nr            =  10;   
  
      std::vector<std::vector<uint>> msg;
      std::vector<std::vector<uint>> w;

    public:
      AES();
      AES(const uint& bin_key_len);

      // void        setKEY(const std::string& key);
      void        setKEY(const std::vector<uint>& key);
      void        setMSG(const std::string& msg);
      std::string getMSG();

      // void        setBinaryKEY(const std::string& binkey);
      // void        setBinaryMSG(const std::string& binmsg);
      // std::string getBinaryMSG();
      
      const uint  countPlainTextBits()    const;
      const uint  countPlainTextSymbols() const;
      const uint  countKeyBits()          const;
      const uint  countKeySymbols()       const;

      bool        encrypt();
      bool        decrypt();

    private:
      void clear_msg(std::vector<std::vector<uint>>& v);
      uint char_to_binint ( char ch );
      char binint_to_char ( int  i  );
  }; 

#endif