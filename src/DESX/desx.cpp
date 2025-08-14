#include "desx.hpp"

#include <bitset>

/// PRUBLIC METHODS //////////////////////////////////////////////////////

DESX::DESX() {
  binkey .resize( size_of_block );
  binkey1.resize( size_of_block );
  binkey2.resize( size_of_block );
  binmsg .resize( size_of_block );
};


void DESX::setKEY(const std::string& key) {
  this->clear_bin_str(this->binkey);

  std::string binstr;
  std::size_t k = 0;
  
  for(int i = 0; ( i < ( size_of_key / size_of_char ) ) && ( i < key.size() ); i++){
 
    binstr = std::bitset<8>(key[i]).to_string();
    
    for(int j = 0; j < binstr.size(); j++){
      this->binkey[k] = char_to_binint(binstr[j]);
      ++k;
    }
  }
};

void DESX::setKEY1(const std::string& key1) {
  this->clear_bin_str(this->binkey1);
  
  std::string binstr;
  std::size_t k = 0;
  
  for(int i = 0; ( i < ( size_of_key / size_of_char ) ) && ( i < key1.size() ); i++){
    
    binstr = std::bitset<8>(key1[i]).to_string();
    
    for(int j = 0; j < binstr.size(); j++){
      this->binkey1[k] = char_to_binint(binstr[j]);
      ++k;
    }
  }
};

void DESX::setKEY2(const std::string& key2) {
  this->clear_bin_str(this->binkey2);
 
  std::string binstr;
  std::size_t k = 0;
  
  for(int i = 0; ( i < ( size_of_key / size_of_char ) ) && ( i < key2.size() ); i++){
    
    binstr = std::bitset<8>(key2[i]).to_string();
    
    for(int j = 0; j < binstr.size(); j++){
      this->binkey2[k] = char_to_binint(binstr[j]);
      ++k;
    }
  }
};

void DESX::setMSG(const std::string& msg) {
  this->clear_bin_str(this->binmsg);
  
  std::string binstr;
  std::size_t k = 0;
  int i = 0;
  for(; ( i < ( size_of_block / size_of_char ) ) && ( i < msg.size() ); i++){
    
    binstr = std::bitset<8>(msg[i]).to_string();

    for(int j = 0; j < binstr.size(); j++){
      this->binmsg[k] = char_to_binint(binstr[j]);
      ++k;
    }
  }
};

std::string DESX::getMSG() {
  std::string binstr = "";
  std::string    res = "";

  for(int i = 0; i < binmsg.size(); i++){
    binstr += binint_to_char(binmsg[i]); /// получаем 0 или 1 в символьном виде
    if( binstr.size() == size_of_char ){
      /// Если насчитали кол-во бит равное размеру символа, то
      /// из бинарнорого вида получаем ASCII код символа
      res += static_cast<char>(std::bitset<8>(binstr).to_ulong());
      binstr.clear();
    }
  }
  return res;
};

void DESX::setBinaryKEY(const std::string& binkey) {
  this->clear_bin_str(this->binkey);

  for(int i = 0; ( i < size_of_block ) && ( i < binkey.size() ); i++){
    this->binkey[i] = char_to_binint(binkey[i]);
  }
};

void DESX::setBinaryKEY1(const std::string& binkey1) {
  this->clear_bin_str(this->binkey1);

  for(int i = 0; ( i < size_of_block ) && ( i < binkey1.size() ); i++){
    this->binkey1[i] = char_to_binint(binkey1[i]);
  }
};

void DESX::setBinaryKEY2(const std::string& binkey2) {
  this->clear_bin_str(this->binkey2);

  for(int i = 0; ( i < size_of_block ) && ( i < binkey2.size() ); i++){
    this->binkey2[i] = char_to_binint(binkey2[i]);
  }
};

void DESX::setBinaryMSG(const std::string& binmsg) {
  this->clear_bin_str(this->binmsg);

  for(int i = 0; ( i < size_of_block ) && ( i < binmsg.size() ); i++){
    this->binmsg[i] = char_to_binint(binmsg[i]);
  }
};

std::string DESX::getBinaryMSG() {
  std::string res = "";

  for(std::size_t i = 0; i < size_of_block; i++)
    res += binint_to_char(this->binmsg[i]);

  return res;
};

const uint DESX::countPlainTextBits() const {
  return size_of_block;
};

const uint DESX::countPlainTextSymbols() const {
  return ( size_of_block / size_of_char );
};

const uint DESX::countKeyBits() const {
  return size_of_key;
};

const uint DESX::countKeySymbols() const {
  return size_of_key / size_of_char;
};

bool DESX::encrypt() {
  
  std::vector<uint> tmpkey = this->binkey;

  std::vector<uint> L       ( this->size_of_block / 2 );
  std::vector<uint> R       ( this->size_of_block / 2 );

  uint j = 0;
  
  try {
    
    this->binmsg = XOR(this->binmsg, this->binkey1);
    this->binmsg = IP(this->binmsg);
    tmpkey       = KEY_perm_with_choice( tmpkey );
  
    /// производим 16 раундов шифрования
    /// с циклическим сдвигом ключа
    for(uint i = 0; i < round_count; i++)
      tmpkey = one_encrypt_round( tmpkey );
    
    /// копируем биты сообщения в L и в R
    for(uint i = 0; i < this->size_of_block; i++){
      if( i < this->size_of_block / 2 )
        L[i] = this->binmsg[i];
      else {
        R[j] = this->binmsg[i];
        ++j;
      }
    }
    
    /// И производим 32-х битовый обмен
    j = 0;
    for(uint i = 0; i < this->size_of_block; i++){
      if( i < this->size_of_block / 2 )
        this->binmsg[i] = R[i];
      else {
        this->binmsg[i] = L[j];
        ++j;
      }
    }
  
    this->binmsg = inverse_IP(this->binmsg);
    this->binmsg = XOR(this->binmsg, this->binkey2);
      

  } catch( ... ) {
    return false;
  }

  return true;
};

bool DESX::decrypt() {
  std::vector<std::vector<uint>> tmpkey = preparing_keys( this->binkey );
  std::vector<uint> L       ( this->size_of_block / 2 );
  std::vector<uint> R       ( this->size_of_block / 2 );

  uint j = 0;
    
  try {
    
    this->binmsg = XOR(this->binmsg, this->binkey2);
    this->binmsg = IP(this->binmsg);
    
    // производим 16 раундов расшифрования
    // с циклическим изъятием ключа из стека ключей

    for(int i = this->round_count - 1; i >= 0; i--)
      one_decrypt_round( tmpkey[i] );    
    
    /// копируем биты сообщения в L и в R
    for(uint i = 0; i < this->size_of_block; i++){
      if( i < this->size_of_block / 2 )
        L[i] = this->binmsg[i];
      else {
        R[j] = this->binmsg[i];
        ++j;
      }
    }
    
    /// И производим 32-х битовый обмен
    j = 0;
    for(uint i = 0; i < this->size_of_block; i++){
      if( i < this->size_of_block / 2 )
        this->binmsg[i] = R[i];
      else {
        this->binmsg[i] = L[j];
        ++j;
      }
    }
    
    this->binmsg = inverse_IP(this->binmsg);
    this->binmsg = XOR(this->binmsg, this->binkey1);
    
  } catch( ... ) {
    return false;
  }

  return true;
};

/// PRIVATE METHODS //////////////////////////////////////////////////////

void DESX::clear_bin_str(std::vector<uint> &v){
  for(std::size_t i = 0; i < v.size(); i++)
    v[i] = 0;
};

uint DESX::char_to_binint(char ch){
  if( ch == '0' ) return 0;
  return 1;
};

char DESX::binint_to_char(int i){
  return static_cast<char>(i + 48);
};

void DESX::left_shift_key(std::vector<uint>& key){
  std::size_t  n   = key.size();
  uint         tmp = key[0];
  
  for(int i = 0; i < n - 1; i++)
    key[i] = key[i + 1];
  
  key[n - 1] = tmp;
};

void DESX::right_shift_key(std::vector<uint>& key){
  std::size_t  n   = key.size();
  uint         tmp = key[n - 1];
  
  for(int i = n - 1; i > 0; i--){
    key[i] = key[i - 1];
  }
  key[0] = tmp;
};

std::vector<std::vector<uint>> DESX::preparing_keys(const std::vector<uint> &key) {
  std::vector<std::vector<uint>> keys;
  std::vector<uint> tmpkey = key;

  tmpkey = KEY_perm_with_choice( tmpkey );

  std::vector<uint> C       (  size_of_key  / 2 );
  std::vector<uint> D       (  size_of_key  / 2 );
  int j;

  for(int i = 0; i < round_count; i++){

    /// копируем биты ключа в C и в D
    j = 0;
    for(int k = 0; k < size_of_key; k++){
      if( k < size_of_key / 2 )
        C[k] = tmpkey[k];
      else {
        D[j] = tmpkey[k];
        ++j;
      }
    }

    left_shift_key( C ); 
    left_shift_key( D );

    j = 0;
    for(int k = 0; k < size_of_key; k++){
      if( k < size_of_key / 2 )
        tmpkey[k] = C[k];
      else {
        tmpkey[k] = D[j];
        ++j;
      }
    }
    keys.push_back( tmpkey );
  }

  return keys;
};


std::vector<uint> DESX::IP(const std::vector<uint> &msg) {
  /*
    Теоретическая перестановка:
      58 50 42 34 26 18 10 2
      60 52 44 36 28 20 12 4
      62 54 46 38 30 22 14 6
      64 56 48 40 32 24 16 8
      57 49 41 33 25 17 9  1
      59 51 43 35 27 19 11 3
      61 53 45 37 29 21 13 5
      63 55 47 39 31 23 15 7
  */
  /*
    Практическая перестановка:
      57 49 41 33 25 17  9  1
      59 51 43 35 27 19 11  3
      61 53 45 37 29 21 13  5
      63 55 47 39 31 23 15  7
      56 48 40 32 24 16  8  0
      58 50 42 34 26 18 10  2
      60 52 44 36 28 20 12  4
      62 54 46 38 30 22 14  6
  */
  std::vector<uint> res = 
  {
    msg[57], msg[49], msg[41], msg[33], msg[25], msg[17], msg[ 9], msg[ 1], 
    msg[59], msg[51], msg[43], msg[35], msg[27], msg[19], msg[11], msg[ 3], 
    msg[61], msg[53], msg[45], msg[37], msg[29], msg[21], msg[13], msg[ 5], 
    msg[63], msg[55], msg[47], msg[39], msg[31], msg[23], msg[15], msg[ 7], 
    msg[56], msg[48], msg[40], msg[32], msg[24], msg[16], msg[ 8], msg[ 0], 
    msg[58], msg[50], msg[42], msg[34], msg[26], msg[18], msg[10], msg[ 2], 
    msg[60], msg[52], msg[44], msg[36], msg[28], msg[20], msg[12], msg[ 4], 
    msg[62], msg[54], msg[46], msg[38], msg[30], msg[22], msg[14], msg[ 6]
  };
  return res;
};

std::vector<uint> DESX::inverse_IP(const std::vector<uint> &msg) {
  /*
    Теоретическая перестановка:
      40 8 48 16 56 24 64 32
      39 7 47 15 55 23 63 31
      38 6 46 14 54 22 62 30
      37 5 45 13 53 21 61 29
      36 4 44 12 52 20 60 28
      35 3 43 11 51 19 59 27
      34 2 42 10 50 18 58 26
      33 1 41  9 49 17 57 25
  */
  /*
    Практическая перестановка:
      39 7 47 15 55 23 63 31
      38 6 46 14 54 22 62 30
      37 5 45 13 53 21 61 29
      36 4 44 12 52 20 60 28
      35 3 43 11 51 19 59 27
      34 2 42 10 50 18 58 26
      33 1 41  9 49 17 57 25
      32 0 40  8 48 16 56 24
  */
  std::vector<uint> res = 
  {
    msg[39], msg[ 7], msg[47], msg[15], msg[55], msg[23], msg[63], msg[31], 
    msg[38], msg[ 6], msg[46], msg[14], msg[54], msg[22], msg[62], msg[30], 
    msg[37], msg[ 5], msg[45], msg[13], msg[53], msg[21], msg[61], msg[29], 
    msg[36], msg[ 4], msg[44], msg[12], msg[52], msg[20], msg[60], msg[28], 
    msg[35], msg[ 3], msg[43], msg[11], msg[51], msg[19], msg[59], msg[27], 
    msg[34], msg[ 2], msg[42], msg[10], msg[50], msg[18], msg[58], msg[26], 
    msg[33], msg[ 1], msg[41], msg[ 9], msg[49], msg[17], msg[57], msg[25], 
    msg[32], msg[ 0], msg[40], msg[ 8], msg[48], msg[16], msg[56], msg[24]
  };
  return res;
};

std::vector<uint> DESX::perm_with_expansion(const std::vector<uint> &v) {
  /* 
    Схема перестановки с расширением (номера битов):
      32  1  2  3  4  5
       4  5  6  7  8  9
       8  9 10 11 12 13
      12 13 14 15 16 17
      16 17 18 19 20 21
      20 21 22 23 24 25
      24 25 26 27 28 29
      28 29 30 31 32  1
  */

  std::vector<uint> res(48);
  const std::size_t block_size = 6;
        std::size_t v_size     = v.size();
        std::size_t step       = 1;
        std::size_t cnt_iter   = 1;
  
  res[0] = v[v_size - 1];

  for(std::size_t i = 0; ( i < v_size ) && ( step < 47 ); i++) {
    if( cnt_iter % block_size == 0 ) i -= 2;
    res[step] = v[i];
    ++step; ++cnt_iter;
  }
  res[47] = v[0];

  return res;
};

std::vector<uint> DESX::KEY_perm_with_choice(const std::vector<uint> &v) {
  
  /*
    Теоретическая перестановка с выбором 1 для ключа:
      57 49 41 33 25 17  9
       1 58 50 42 34 26 18
      10  2 59 51 43 35 27
      19 11  3 60 52 44 36
      63 55 47 39 31 23 15
       7 62 54 46 38 30 22
      14  6 61 53 45 37 29
      21 13  5 28 20 12  4
  */
 /*
    Практическая перестановка с выбором 1 для ключа:
      56 48 40 32 24 16  8
       0 57 49 41 33 25 17
       9  1 58 50 42 34 26
      18 10  2 59 51 43 35
      62 54 46 38 30 22 14
       6 61 53 45 37 29 21
      13  5 60 52 44 36 28
      20 12  4 27 19 11  3
  */
  
  std::vector<uint> res = 
  {
    v[56], v[48], v[40], v[32], v[24], v[16], v[ 8], 
    v[ 0], v[57], v[49], v[41], v[33], v[25], v[17], 
    v[ 9], v[ 1], v[58], v[50], v[42], v[34], v[26], 
    v[18], v[10], v[ 2], v[59], v[51], v[43], v[35], 
    v[62], v[54], v[46], v[38], v[30], v[22], v[14], 
    v[ 6], v[61], v[53], v[45], v[37], v[29], v[21], 
    v[13], v[ 5], v[60], v[52], v[44], v[36], v[28], 
    v[20], v[12], v[ 4], v[27], v[19], v[11], v[ 3]
  };
    
  return res;
};

std::vector<uint> DESX::KEY_perm_with_choice2(const std::vector<uint> &v) {
  /* 
    Теоретическая перестановка с выбором 1 для ключа:
      14 17 11 24  1  5
       3 28 15  6 21 10
      23 19 12  4 26  8
      16  7 27 20 13  2
      41 52 31 37 47 55
      30 40 51 45 33 48
      44 49 39 56 34 53
      46 42 50 36 29 32
  */
  /* 
    Практическая перестановка с выбором 1 для ключа:
      13 16 10 23  0  4
       2 27 14  5 20  9
      22 18 11  3 25  7
      15  6 26 19 12  1
      40 51 30 36 46 54
      29 39 50 44 32 47
      43 48 38 55 33 52
      45 41 49 35 28 31
  */
  std::vector<uint> res = 
  {
    v[13], v[16], v[10], v[23], v[ 0], v[ 4], 
    v[ 2], v[27], v[14], v[ 5], v[20], v[ 9], 
    v[22], v[18], v[11], v[ 3], v[25], v[ 7], 
    v[15], v[ 6], v[26], v[19], v[12], v[ 1], 
    v[40], v[51], v[30], v[36], v[46], v[54], 
    v[29], v[39], v[50], v[44], v[32], v[47], 
    v[43], v[48], v[38], v[55], v[33], v[52], 
    v[45], v[41], v[49], v[35], v[28], v[31]
  };

  return res;
};


std::vector<uint> DESX::one_encrypt_round(const std::vector<uint>& key) {
  std::vector<uint> newkey (    size_of_key    );

  std::vector<uint> L       ( size_of_block / 2 );
  std::vector<uint> R       ( size_of_block / 2 );
  std::vector<uint> C       (  size_of_key  / 2 );
  std::vector<uint> D       (  size_of_key  / 2 );
  
  std::vector<uint> res_2nd_xor;

  uint j = 0;

  /// копируем биты сообщения в L и в R
  for(uint i = 0; i < size_of_block; i++){
    if( i < size_of_block / 2 )
      L[i] = this->binmsg[i];
    else {
      R[j] = this->binmsg[i];
      ++j;
    }
  }
  
  j = 0;
  /// копируем биты ключа в C и в D
  for(uint i = 0; i < size_of_key; i++){
    if( i < size_of_key / 2 )
      C[i] = key[i];
    else {
      D[j] = key[i];
      ++j;
    }
  }
  
  left_shift_key( C ); 
  left_shift_key( D );

  j = 0;
  for(uint i = 0; i < size_of_key; i++){
    if( i < size_of_key / 2 )
      newkey[i] = C[i];
    else {
      newkey[i] = D[j];
      ++j;
    }
  }
  
  res_2nd_xor = XOR( L, F( R, KEY_perm_with_choice2( newkey ) ) );
  
  /// копируем биты из L и R
  /// L[i] = R[i-1]; R[i] = XOR( L[i-1], F(R[i-1]) )
  j = 0;
  for(uint i = 0; i < size_of_block; i++){
    if( i < size_of_block / 2 )
      this->binmsg[i] = R[i];
    else {
      this->binmsg[i] = res_2nd_xor[j];
      ++j;
    }
  }
  
  return newkey;
};

void DESX::one_decrypt_round(const std::vector<uint> &key) {
  std::vector<uint> L       ( size_of_block / 2 );
  std::vector<uint> R       ( size_of_block / 2 );
  
  std::vector<uint> res_2nd_xor;

  uint j = 0;

  
  /// копируем биты сообщения в L и в R
  for(uint i = 0; i < size_of_block; i++){
    if( i < size_of_block / 2 )
      L[i] = this->binmsg[i];
    else {
      R[j] = this->binmsg[i];
      ++j;
    }
  }
      
  res_2nd_xor = XOR( L, F( R, KEY_perm_with_choice2( key ) ) );
  
  /// копируем биты из L и R
  /// L[i] = R[i-1]; R[i] = XOR( L[i-1], F(R[i-1]) )
  j = 0;
  for(uint i = 0; i < size_of_block; i++){
    if( i < size_of_block / 2 )
      this->binmsg[i] = R[i];
    else {
      this->binmsg[i] = res_2nd_xor[j];
      ++j;
    }
  }
  
};

std::vector<uint> DESX::F(const std::vector<uint> &msgR, const std::vector<uint> &key) {
  return perm_P(
           perm_with_choice(
             XOR(
               perm_with_expansion( msgR ), 
               key 
             )
           ) 
         );
};

std::vector<uint> DESX::XOR(const std::vector<uint> &lhs, const std::vector<uint> &rhs) {
  /// работает как для 32=х бит, так и для 48-и бит.
  std::vector<uint> res (lhs.size());
  for(int i = 0; i < lhs.size(); i++)
    res[i] = ( lhs[i] ^ rhs[i] );
  
  return res;
};

std::vector<uint>/* 32 bits */ DESX::perm_with_choice(/* 48 bits */const std::vector<uint> &v) {
  const std::size_t S_block_input_bits  = 6;
  const std::size_t S_block_output_bits = 4;
  const std::size_t cnt_S_blocks        = 8;
        std::size_t step                = 0;
  std::vector<std::string>  binstrings(cnt_S_blocks);
  std::vector<std::vector<ulong>> S1, S2, S3, S4, S5, S6, S7, S8;
  std::vector<uint> res(S_block_output_bits * cnt_S_blocks); /// 32 bits

  /// Ссылка на формирование S блоков 
  /* https://ru.wikipedia.org/wiki/S-%D0%B1%D0%BB%D0%BE%D0%BA_(%D0%B8%D0%BD%D1%84%D0%BE%D1%80%D0%BC%D0%B0%D1%82%D0%B8%D0%BA%D0%B0)#/media/%D0%A4%D0%B0%D0%B9%D0%BB:DESX_S-box.jpg */
  
  S1 = {
          {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
          { 0, 15,  7,  3, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
          { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7, 13, 10,  5,  0},
          {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
       };
  S2 = {
          {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
          { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
          { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
          {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
       };
  S3 = {
          {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
          {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
          {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
          { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
       };
  S4 = {
          { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
          {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
          {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
          { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
       };
  S5 = {
          { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
          {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
          { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
          {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
       };
  S6 = {
          {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
          {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
          { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
          { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
       };
  S7 = {
          { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
          {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
          { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
          { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
       };
  S8 = {
          {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
          { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
          { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
          { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6,}
       };

  auto lambda_elem_selection = [this](std::size_t begin, std::size_t end, const std::vector<uint> &vec, const std::vector<std::vector<ulong>>& S){
    std::string binstr_row = "", binstr_col = "";
    binstr_row += binint_to_char(vec[begin]); /// x0
    binstr_row += binint_to_char(vec[ end ]); /// x5

    for(std::size_t i = begin + 1; i < end; i++)
      binstr_col += binint_to_char(vec[i]);

    ulong i = std::bitset<2>(binstr_row).to_ulong(); /// x0x5
    ulong j = std::bitset<4>(binstr_col).to_ulong(); /// x1x2x3x4

    return S[i][j];
  };
  
  binstrings[0] = std::bitset<S_block_output_bits>( lambda_elem_selection(0,   5, v, S1) ).to_string();
  binstrings[1] = std::bitset<S_block_output_bits>( lambda_elem_selection(6,  11, v, S2) ).to_string();
  binstrings[2] = std::bitset<S_block_output_bits>( lambda_elem_selection(12, 17, v, S3) ).to_string();
  binstrings[3] = std::bitset<S_block_output_bits>( lambda_elem_selection(18, 23, v, S4) ).to_string();
  binstrings[4] = std::bitset<S_block_output_bits>( lambda_elem_selection(24, 29, v, S5) ).to_string();
  binstrings[5] = std::bitset<S_block_output_bits>( lambda_elem_selection(30, 35, v, S6) ).to_string();
  binstrings[6] = std::bitset<S_block_output_bits>( lambda_elem_selection(36, 41, v, S7) ).to_string();
  binstrings[7] = std::bitset<S_block_output_bits>( lambda_elem_selection(42, 47, v, S8) ).to_string();

  for(int i = 0; i < cnt_S_blocks; i++){
    for(int j = 0; j < S_block_output_bits; j++){
      res[step] = char_to_binint(binstrings[i][j]);
      ++step;
    }
  }

  return res;
};


std::vector<uint> DESX::perm_P(const std::vector<uint> &v) {
  /*
    Теоретическая перестановка в битах:
      16  7 20 21
      29 12 28 17
       1 15 23 26
       5 18 31 10
       2  8 24 14
      32 27  3  9
      19 13 30  6
      22 11  4 25
  */
  /*
    Практическая перестановка в индексах битов:
      15  6 19 20
      28 11 27 16
       0 14 22 25
       4 17 30  9
       1  7 23 13
      31 26  2  8
      18 12 29  5
      21 10  3 24
  */
  std::vector<uint> res = 
  {
    v[15], v[ 6], v[19], v[20], 
    v[28], v[11], v[27], v[16], 
    v[ 0], v[14], v[22], v[25], 
    v[ 4], v[17], v[30], v[ 9], 
    v[ 1], v[ 7], v[23], v[13], 
    v[31], v[26], v[ 2], v[ 8], 
    v[18], v[12], v[29], v[ 5], 
    v[21], v[10], v[ 3], v[24]
  };

  return res;
};

std::string CDESX::LOGO() {
  return
  R"(
        ██████╗ ███████╗███████╗     ██╗  ██╗
        ██╔══██╗██╔════╝██╔════╝     ╚██╗██╔╝
        ██║  ██║█████╗  ███████╗█████╗╚███╔╝ 
        ██║  ██║██╔══╝  ╚════██║╚════╝██╔██╗ 
        ██████╔╝███████╗███████║     ██╔╝ ██╗
        ╚═════╝ ╚══════╝╚══════╝     ╚═╝  ╚═╝
                                          
           cipher for ENG & RUS languages 
                *  made by Grokir  *  
                                             
  )";
};