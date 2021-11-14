# CMakeList.txt : CMake project for CryptoLib, include source and define
# project specific logic here.
# for VSC use VS 2019 - x86_amd64 config 

cmake_minimum_required (VERSION 3.8)
project ("CryptoLib")
project ("Cross-PlatformCryptoLib")
if (MSVC AND (MSVC_VERSION GREATER 1900))
    message("Setting CONTROL FLOW GUARD") 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf /O2 /GS /QIntel-jcc-erratum /analyze /sdl /MD")
    SET(CMAKE_EXE_LINKER_FLAGS  "/guard:cf /DYNAMICBASE /O2 /GS /QIntel-jcc-erratum /analyze /sdl /MD")
    message("Setting QSPECTRE")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre /MD")
endif()

if(NOT MSVC)
    message("Setting Spectre mitigation")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mfunction-return -mindirect-branch-register ")
    target_compile_options (CryptoLib PUBLIC -fexceptions)
endif()

include_directories(${PyLoc})
link_directories(${PyLib})
find_package(OpenSSL REQUIRED)
find_package(Python3 REQUIRED)

add_library(CryptoLib SHARED "CryptoLib.cpp" "CryptoLib.h")
target_link_libraries(CryptoLib  PRIVATE OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(CryptoLib PROPERTIES SUFFIX ".pyd")
