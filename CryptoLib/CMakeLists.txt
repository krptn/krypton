# CMakeList.txt : CMake project for CryptoLib, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("CryptoLib")

cmake_minimum_required (VERSION 3.8)
project ("Cross-PlatformCryptoLib")
if (MSVC AND (MSVC_VERSION GREATER 1900))
    message("Setting CONTROL FLOW GUARD") 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf /O2 /GS /QIntel-jcc-erratum /analyze /sdl /MD")
    SET(CMAKE_EXE_LINKER_FLAGS  "/guard:cf /DYNAMICBASE /O2 /GS /QIntel-jcc-erratum /analyze /sdl /MD")
    message("Setting QSPECTRE")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre /MD")
endif()

# Add source to this project's executable.
find_package(OpenSSL REQUIRED)
link_directories(${PyLib})
include_directories(${PyLoc} include src)
include_directories(${PyBind11} include src)
add_library(CryptoLib SHARED "CryptoLib.cpp" "CryptoLib.h")
add_compile_definitions(${Platform})
find_package(PythonLibs REQUIRED)
find_package(Python3 REQUIRED)
target_link_libraries(CryptoLib  PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(CryptoLib  PRIVATE ${Pyloc})
target_link_libraries(CryptoLib  PRIVATE OpenSSL::SSL OpenSSL::Crypto)
set_target_properties(CryptoLib PROPERTIES SUFFIX ".pyd")
