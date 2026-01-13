cmake_minimum_required(VERSION 3.15)
project(FileEncryptor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_CXX_FLAGS_DEBUG "-fdiagnostics-color=always -g3")
set(CMAKE_CXX_FLAGS_RELEASE "-O")

set(Debug_DIR "${CMAKE_SOURCE_DIR}/bin/debug")
set(Release_DIR "${CMAKE_SOURCE_DIR}/bin/release")


message(STATUS "Build type is: ${CMAKE_BUILD_TYPE}")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Configuring for Debug build")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${Debug_DIR})
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Configuring for Release build")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${Release_DIR})
else()
    message(STATUS "Configuring for other build type: ${CMAKE_BUILD_TYPE}")
endif()



# Опционально: включаем поддержку предкомпилированных заголовков (PCH)
# Для CMake 3.16+ можно использовать target_precompile_headers

# Добавим пути к исходникам
set(SOURCES
  source/SHA-2/sha256.cpp
  source/SHA-2/sha512.cpp
  source/FileRead/file_reader.cpp
  source/Interface/iface.cpp
  source/DES/des.cpp
  source/DESX/desx.cpp
)

# set(SHA2_SOURCES
#     src/CppLibHashes/SHA-2/sha256.cpp
#     src/CppLibHashes/SHA-2/sha512.cpp
# )

# set(ECDSA_SOURCES
#     src/ECDSA/ecdsa.cpp
# )

# set(ELLIPTIC_POINT_SOURCES
#     src/EllipticPoint/elliptic_point.cpp
# )

# set(TESTS_SOURCES
#     src/Tests/tests.cpp
# )

# set(KEY_IO_SOURCES
#     src/KeyIO/key_io.cpp
# )

# set(SIG_IO_SOURCES
#     src/SignatureIO/signature_io.cpp
# )


# Добавим заголовочные файлы для удобства (необязательно)
set(HEADERS
  include/SHA-2/sha256.hpp
  include/SHA-2/sha512.hpp
  include/FileRead/file_reader.hpp
  include/Interface/iface.hpp
  include/DES/des.hpp
  include/DESX/desx.hpp
)

# set(SHA2_HEADERS
#     src/CppLibHashes/SHA-2/sha256.hpp
#     src/CppLibHashes/SHA-2/sha512.hpp
# )

# set(ECDSA_HEADERS
#     src/ECDSA/ecdsa.hpp
# )

# set(ELLIPTIC_POINT_HEADERS
#     src/EllipticPoint/elliptic_point.hpp
# )

# set(TESTS_HEADERS
#     src/Tests/tests.hpp
# )

# set(KEY_IO_HEADERS
#     src/KeyIO/key_io.hpp
# )

# set(SIG_IO_HEADERS
#     src/SignatureIO/signature_io.hpp
# )

# Собираем исполняемый файл
add_executable(FileEncryptor
    main.cpp
    ${SOURCES}
    ${HEADERS}    
)

# add_executable(EXEC_ECDSA_PROJECT
#     src/main.cpp
#     ${SHA2_SOURCES}
#     ${ECDSA_SOURCES}
#     ${ELLIPTIC_POINT_SOURCES}
#     ${TESTS_SOURCES}
#     ${KEY_IO_SOURCES}
#     ${SIG_IO_SOURCES}

#     ${SHA2_HEADERS}
#     ${ECDSA_HEADERS}
#     ${ELLIPTIC_POINT_HEADERS}
#     ${TESTS_HEADERS}
#     ${KEY_IO_HEADERS}
#     ${SIG_IO_HEADERS}
    
# )

# Указываем include директории
target_include_directories(FileEncryptor PRIVATE
    include/
)
# target_include_directories(EXEC_ECDSA_PROJECT PRIVATE
#     src/CppLibHashes/SHA-2
#     src/ECDSA
#     src/EllipticPoint
#     src/Tests
#     src/KeyIO
#     src/SignatureIO
# )


# Пример использования предкомпилированных заголовков (если хотите)
# Нужно CMake 3.16+ и файлы .pch в формате, поддерживаемом компилятором
# target_precompile_headers(EXEC_ECDSA_PROJECT PRIVATE
#     src/ECDSA/ecdsa.hpp
#     src/EllipticPoint/elliptic_point.hpp
#     src/CppLibHashes/SHA-2/sha256.hpp
#     src/CppLibHashes/SHA-2/sha512.hpp
# )
