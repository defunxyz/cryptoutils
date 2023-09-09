cmake_minimum_required(VERSION 3.14)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(Cryptoutils)

set(THIRD_PARTY_DIRECTORY "third-party/")
# Point to the proper directory:
set(CRYPTOPP_SOURCES "${PROJECT_SOURCE_DIR}/${THIRD_PARTY_DIRECTORY}cryptopp/")
set(GHC_FILESYSTEM_BUILD_TESTING OFF)
set(GHC_FILESYSTEM_BUILD_EXAMPLES OFF)

set(third_parties fmt ghc_filesystem cryptopp)

set(cryptopp_comp_static YES) # Enable static linking
set(CMAKE_EXE_LINKER_FLAGS "")

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(STATUS "GCC Detected: Initializing")
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} \
        -Wall \
        -Wformat \
        -Wextra \
        -Wmissing-include-dirs \
        -fdiagnostics-color=always \
        ")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(STATUS "Clang Detected: Initializing")
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS} \
        -Wall \
        -Werror \
        -fcxx-exceptions \
        -fexceptions \
        -fdiagnostics-color=always \
        ")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    message(STATUS "MSVC Detected: Initializing")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc /utf-8")
endif()

if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

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