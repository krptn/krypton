# CMakeList.txt : CMake project for Cross-PlatformCryptoLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("Cross-PlatformCryptoLib")

# Add source to this project's executable.
add_library(Cross-PlatformCryptoLib SHARED "Cross-PlatformCryptoLib.cpp" "Cross-PlatformCryptoLib.h")
find_package(OpenSSL REQUIRED)
target_link_libraries(Cross-PlatformCryptoLib PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(Cross-PlatformCryptoLib PRIVATE ${PyLoc})

include(GenerateExportHeader)
generate_export_header(Cross-PlatformCryptoLib)

# TODO: Add tests and install targets if needed.