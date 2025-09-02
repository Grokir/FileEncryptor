#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

#include "Interface/iface.hpp"
#include "FileRead/file_reader.hpp"

using namespace std;


string help(){
  return 
  R"(
    -h, --help                        help message
    --des                             DES alg
    --desx                            DESX alg
    -f, --file <path to file>         Selected file for work
    -d, --dir  <path to dir>          Selected dir for work
    -E, --encrypt                     Encryption
    -D, --decrypt                     Decryption
  )";
    // -k, --key  <path to key-file>     Selected key
};

int main(int argc, char** argv) {  
  vector<string>  args(argc);
  vector<CFile>   files;
  Operation       oper;
  string          path;

  for(int i = 0; i < argc; i++)
    args[i] = string(argv[i]);


  if( argc < 2 || 
      std::find(args.begin(), args.end(), "-h")         !=  args.end() || 
      std::find(args.begin(), args.end(), "--help")     !=  args.end() 
    ){
    cout << help() << endl;
    return 1;
  }


  if(
      std::find(args.begin(), args.end(), "-E")         !=  args.end() ||
      std::find(args.begin(), args.end(), "--encrypt")  !=  args.end() 
  )
    oper = Operation::ENCR;
  
  if(
      std::find(args.begin(), args.end(), "-D")         !=  args.end() ||
      std::find(args.begin(), args.end(), "--decrypt")  !=  args.end() 
  )
    oper = Operation::DECR;


  if(
    std::find(args.begin(), args.end(), "-f")           !=  args.end() ||
    std::find(args.begin(), args.end(), "--file")       !=  args.end() 
  ){
    int arg_f_pos     =   get_pos_elem(args, "-f");
    int arg_file_pos  =   get_pos_elem(args, "--file");
    
    path = args[max(arg_f_pos, arg_file_pos) + 1];
    files.push_back(CFile(path));
  }

  
  if(
    std::find(args.begin(), args.end(), "-d")           !=  args.end() ||
    std::find(args.begin(), args.end(), "--dir")        !=  args.end() 
  ){
    int arg_f_pos     =  get_pos_elem(args, "-d");
    int arg_file_pos  =  get_pos_elem(args, "--dir");
    
    path = args[max(arg_f_pos, arg_file_pos) + 1];
    
    files = fr::get_file_list(path);

    if(files.empty()){
      cout << "[!] Error read directory\n";
      return -3;
    }
  }

  cout << "[+] Start wirk with '" << path << "'..." << endl;

  if(std::find(args.begin(), args.end(), "--des")       != args.end() )
    DES_ALG(files, oper);
  else if(std::find(args.begin(), args.end(), "--desx") !=  args.end() )
    DESX_ALG(files, oper);
  else
    cout << "[!] Error algs flag:\n" 
         << "     --des \n"   
         << "     --desx\n";


  std::cout << "\n[+] Process: DONE" << std::endl;

  return 0;
};

