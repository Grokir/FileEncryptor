# FileEncryptor
**So far, it encrypts  one  selected  file.**
Currently supported  algorithms: 
- [DES](https://en.wikipedia.org/wiki/Data_Encryption_Standard) 
- [DESX](https://en.wikipedia.org/wiki/DES-X)
> Check reference in my [repo](https://github.com/Grokir/DES_and_DESX_algorithms).
- Multifiles encrypt
- [Progressbar](https://github.com/gipert/progressbar)
- [SHA-2 Hashes](https://github.com/Grokir/CppLibHashes)
- [AES 128/192/256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)


## Build

1. ```pushd FileEncryptor; mkdir build```
2. Release (Debug): ```cmake -S src -B build -DCMAKE_BUILD_TYPE=Release (Debug)```
3. Build: ```cmake --build build -j4```

## Usage
```
user@host:~/FileEncryptor/bin/release$ ./filenc --help                  

    -h, --help                        help message
    --aes128                          AES-128 alg
    --aes192                          AES-192 alg
    --aes256                          AES-256 alg
    --des                             DES alg
    --desx                            DESX alg
    -f, --file <path to file>         Selected file for work
    -d, --dir  <path to dir>          Selected dir for work
    -E, --encrypt                     Encryption
    -D, --decrypt                     Decryption
```