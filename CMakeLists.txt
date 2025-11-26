cmake_minimum_required(VERSION 3.10)
project(SmartCracker VERSION 1.0 DESCRIPTION "Smart Password Cracker Tool")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Trova OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)

# Aggiungi eseguibile
add_executable(smartcracker src/main.cpp)

# Linka OpenSSL
target_link_libraries(smartcracker OpenSSL::SSL OpenSSL::Crypto)

# Installazione
install(TARGETS smartcracker DESTINATION bin)
