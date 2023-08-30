# CMake generated Testfile for 
# Source directory: C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp
# Build directory: C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[cryptopp-build_cryptest]=] "C:/Program Files/CMake/bin/cmake.exe" "--build" "C:/Users/Fisnik/Documents/GitHub/cryptoutils" "--target" "cryptest" "--config" "Debug")
set_tests_properties([=[cryptopp-build_cryptest]=] PROPERTIES  FIXTURES_SETUP "cryptest-build" LABELS "cryptopp;cryptopp-cryptest" _BACKTRACE_TRIPLES "C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp/CMakeLists.txt;1242;add_test;C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp/CMakeLists.txt;0;")
add_test([=[cryptopp-cryptest]=] "C:/Users/Fisnik/Documents/GitHub/cryptoutils/bin/cryptest.exe" "v")
set_tests_properties([=[cryptopp-cryptest]=] PROPERTIES  FIXTURES_REQUIRED "cryptest-build" LABELS "cryptopp;cryptopp-cryptest" WORKING_DIRECTORY "C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp/" _BACKTRACE_TRIPLES "C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp/CMakeLists.txt;1249;add_test;C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp/CMakeLists.txt;0;")
add_test([=[cryptopp-cryptest-extensive]=] "C:/Users/Fisnik/Documents/GitHub/cryptoutils/bin/cryptest.exe" "tv" "all")
set_tests_properties([=[cryptopp-cryptest-extensive]=] PROPERTIES  FIXTURES_CLEANUP "cryptest-build" LABELS "cryptopp;cryptopp-cryptest" WORKING_DIRECTORY "C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp/" _BACKTRACE_TRIPLES "C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp/CMakeLists.txt;1257;add_test;C:/Users/Fisnik/Documents/GitHub/cryptoutils/third-party/cryptopp-cmake/cryptopp/CMakeLists.txt;0;")
