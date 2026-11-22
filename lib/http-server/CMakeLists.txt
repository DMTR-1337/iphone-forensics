cmake_minimum_required(VERSION 3.10)
project(http-server VERSION 1.0)

# Use C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Build webserver lib
add_library(http_server src/http-server.cpp)

# Header location
target_include_directories(http_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Thread per connection
find_package(Threads REQUIRED)
target_link_libraries(http_server PUBLIC Threads::Threads)

# WS if on windows
if(WIN32)
    target_link_libraries(http_server PUBLIC ws2_32)
endif()
