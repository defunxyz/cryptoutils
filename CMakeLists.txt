cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_COMPILER "C:/msys64/mingw64/bin/g++.exe")
set(CMAKE_C_COMPILER "C:/msys64/mingw64/bin/gcc.exe")

project(Cryptoutils)

set(THIRD_PARTY_DIRECTORY "third-party/")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
# Point to the proper directory:
set(CRYPTOPP_SOURCES "${PROJECT_SOURCE_DIR}/${THIRD_PARTY_DIRECTORY}cryptopp/")
set(GHC_FILESYSTEM_BUILD_TESTING OFF)
set(GHC_FILESYSTEM_BUILD_EXAMPLES OFF)

set(cryptopp_comp_static YES) # Enable static linking
set(CMAKE_EXE_LINKER_FLAGS "")
add_compile_options(-std=c++11 -Wall -fno-devirtualize)

set(third_parties fmt ghc_filesystem cryptopp)

include_directories(${PROJECT_SOURCE_DIR}/${THIRD_PARTY_DIRECTORY}cryptopp/)
include_directories(${PROJECT_SOURCE_DIR}/${THIRD_PARTY_DIRECTORY}filesystem/include/ghc/)
include_directories(${PROJECT_SOURCE_DIR}/${THIRD_PARTY_DIRECTORY}fmt/include/fmt/)

add_subdirectory(${THIRD_PARTY_DIRECTORY}fmt)
add_subdirectory(${THIRD_PARTY_DIRECTORY}filesystem)
add_subdirectory(${THIRD_PARTY_DIRECTORY}cryptopp-cmake)

file(GLOB APP_SOURCES src/*.cpp)
foreach(SOURCE_PATH ${APP_SOURCES})
    get_filename_component(EXECUTABLE_NAME ${SOURCE_PATH} NAME_WE)
    add_executable(${EXECUTABLE_NAME} ${SOURCE_PATH})
    target_link_libraries(${EXECUTABLE_NAME} ${third_parties})
endforeach(SOURCE_PATH ${SOURCE_FILES})