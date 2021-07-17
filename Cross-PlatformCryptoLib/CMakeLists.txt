# CMakeList.txt : CMake project for Cross-PlatformCryptoLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)
project ("Cross-PlatformCryptoLib")

# Add source to this project's executable.
find_package(OpenSSL REQUIRED)
link_directories(${PyLib})
add_library(Cross-PlatformCryptoLib SHARED "Cross-PlatformCryptoLib.cpp" "Cross-PlatformCryptoLib.h")

target_link_libraries(Cross-PlatformCryptoLib PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(Cross-PlatformCryptoLib PRIVATE ${Pyloc})
include(${PyLoc}/Python.h )
target_link_libraries(Cross-PlatformCryptoLib PRIVATE OpenSSL::SSL OpenSSL::Crypto)
include(GenerateExportHeader)

generate_export_header(Cross-PlatformCryptoLib)