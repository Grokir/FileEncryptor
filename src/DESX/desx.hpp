#pragma once

#ifndef DESX_H

#define DESX_H

#include <cstdint>
#include <string>
#include <vector>

namespace CDESX {
  std::string LOGO();
};

/*********************************************************************/
/*                                                                   */
/*                                                                   */
/*   Ref:     https://vscode.ru/prog-lessons/algoritm-des.html       */
/*   Ref: https://www.opennet.ru/docs/RUS/inet_book/6/des_641.html   */
/*   Ref:          https://studfile.net/preview/9462946/             */
/*   Ref:      https://studfile.net/preview/2014326/page:30/         */
/*   Ref: https://stackoverflow.com/questions/1116350/what-is-des-x  */
/*                                                                   */
/*                                                                   */
/*********************************************************************/

class DESX {
  private:
    const uint        size_of_block   = 64;   /// в битах
    const uint        size_of_char    =  8;   /// в битах
    const uint        size_of_key     = 56;   /// в битах
    const uint        size_of_src_key = 64;   /// в битах
    const uint        round_count     = 16;

    std::vector<uint> binkey;               /// длина ключа  56 бита
    std::vector<uint> binkey1;              /// длина ключа  64 бита
    std::vector<uint> binkey2;              /// длина ключа  64 бита
    std::vector<uint> binmsg;               /// длина текста 64 бита

  public:
    DESX();
    void        setKEY (const std::string& key);
    void        setKEY1(const std::string& key1);
    void        setKEY2(const std::string& key2);
    void        setMSG (const std::string& msg);
    std::string getMSG ();

    void        setBinaryKEY (const std::string& binkey);
    void        setBinaryKEY1(const std::string& binkey1);
    void        setBinaryKEY2(const std::string& binkey2);
    void        setBinaryMSG (const std::string& binmsg);
    std::string getBinaryMSG ();
    
    const uint  countPlainTextBits   () const;
    const uint  countPlainTextSymbols() const;
    const uint  countKeyBits         () const;
    const uint  countKeySourceBits   () const;
    const uint  countKeySymbols      () const;
    bool        encrypt              ();
    bool        decrypt              ();
  
  private:
    void clear_bin_str  (std::vector<uint>& v);
    uint char_to_binint ( char ch );
    char binint_to_char ( int  i  );
    void right_shift_key( std::vector<uint>& key );
    void left_shift_key ( std::vector<uint>& key );

    std::vector<std::vector<uint>> preparing_keys ( const std::vector<uint>& key );

    std::vector<uint> IP                   ( const std::vector<uint>& msg );
    std::vector<uint> inverse_IP           ( const std::vector<uint>& msg );
    std::vector<uint> KEY_perm_with_choice ( const std::vector<uint>& v   );
    std::vector<uint> KEY_perm_with_choice2( const std::vector<uint>& v   );
    
    std::vector<uint> one_encrypt_round    ( const std::vector<uint>& key );
    void              one_decrypt_round    ( const std::vector<uint>& key );

    std::vector<uint> F                    ( const std::vector<uint>& msgR, 
                                             const std::vector<uint>& key );
    /// F модуль шифра 
    std::vector<uint> perm_with_expansion  ( const std::vector<uint>& v   );
    std::vector<uint> XOR                  ( const std::vector<uint>& lhs ,
                                             const std::vector<uint>& rhs );
    std::vector<uint> perm_with_choice     ( const std::vector<uint>& v   );
    std::vector<uint> perm_P               ( const std::vector<uint>& v   );
};

#endif