cmake_minimum_required(VERSION 3.15)
project(filenc LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_COMPILER clang++)

set(CMAKE_CXX_FLAGS_DEBUG "-fdiagnostics-color=always -g3")
set(CMAKE_CXX_FLAGS_RELEASE "-O")

set(Debug_DIR "${CMAKE_SOURCE_DIR}/../bin/debug")
set(Release_DIR "${CMAKE_SOURCE_DIR}/../bin/release")


message(STATUS "Build type is: ${CMAKE_BUILD_TYPE}")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Configuring for Debug build")
    message(STATUS ${Debug_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${Debug_DIR})
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Configuring for Release build")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${Release_DIR})
else()
    message(STATUS "Configuring for other build type: ${CMAKE_BUILD_TYPE}")
endif()

# Добавим пути к исходникам
set(SOURCES
  source/SHA-2/sha256.cpp
  source/SHA-2/sha512.cpp
  source/FileRead/file_reader.cpp
  source/Interface/iface.cpp
  source/AES/aes.cpp
  source/DES/des.cpp
  source/DESX/desx.cpp
)

# Добавим заголовочные файлы для удобства (необязательно)
set(HEADERS
  include/SHA-2/sha256.hpp
  include/SHA-2/sha512.hpp
  include/FileRead/file_reader.hpp
  include/Interface/iface.hpp
  include/AES/aes.hpp
  include/DES/des.hpp
  include/DESX/desx.hpp
  include/Progressbar/progressbar.hpp
)

# Собираем исполняемый файл
add_executable(filenc
    test.cpp
    ${SOURCES}
    ${HEADERS}    
)

# Указываем include директории
target_include_directories(filenc PRIVATE
    include/
)

