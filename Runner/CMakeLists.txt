# CMakeList.txt : CMake project for Runner, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project ("Runner")

# Add source to this project's executable.
#add_executable (Runner "Runner.cpp" "Runner.h")

if (MSVC AND (MSVC_VERSION GREATER 1900))
    message("Setting CONTROL FLOW GUARD") 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf /GS")
    SET(CMAKE_EXE_LINKER_FLAGS  "/guard:cf /DYNAMICBASE")
    message("Setting QSPECTRE")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre ")
endif()

# Add source to this project's executable.

link_directories(${Conf})
include_directories(${Conf}/../../.. include src)
find_package(OpenSSL REQUIRED)
link_directories(${PyLib})
include_directories(${PyLoc} include src)
add_library(Runner SHARED "Runner.cpp" "Runner.h")
add_library(RunnerStatic STATIC "Runner.cpp" "Runner.h")
add_compile_definitions(${Platform})
find_package(PythonLibs REQUIRED)
find_package(Python3 REQUIRED)
target_link_libraries(Runner PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(Runner PRIVATE ${Pyloc})
target_link_libraries(Runner PRIVATE OpenSSL::SSL OpenSSL::Crypto)
include(GenerateExportHeader)

generate_export_header(Runner)
