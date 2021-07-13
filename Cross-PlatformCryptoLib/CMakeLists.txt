# CMakeList.txt : CMake project for Cross-PlatformCryptoLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("Cross-PlatformCryptoLib")

# Add source to this project's executable.
add_library(Cross-PlatformCryptoLib SHARED "Cross-PlatformCryptoLib.cpp" "Cross-PlatformCryptoLib.h")

# TODO: Add tests and install targets if needed.