cmake_minimum_required(VERSION 3.21)
project(iphone-forensics VERSION 1.0 LANGUAGES C CXX)

# Use C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Bundled http server
add_subdirectory(lib/http-server)

# Embedded SQLite amalgamation
add_library(sqlite3 STATIC lib/sqlite/sqlite3.c)
target_include_directories(sqlite3 PUBLIC lib/sqlite)
target_compile_definitions(sqlite3 PRIVATE SQLITE_OMIT_LOAD_EXTENSION SQLITE_DQS=0 SQLITE_DEFAULT_MEMSTATUS=0)

# Web UI embedded as byte arrays, regenerated when web/ changes
set(ASSETS ${CMAKE_BINARY_DIR}/generated/web-assets.hpp)
file(WRITE ${ASSETS}.tmp "/* Generated from web/ */\n#pragma once\n")
foreach(f index.html app.js style.css)
    file(READ ${CMAKE_SOURCE_DIR}/web/${f} hex HEX)
    string(REGEX REPLACE "(..)" "0x\\1," hex "${hex}")
    string(MAKE_C_IDENTIFIER ${f} name)
    file(APPEND ${ASSETS}.tmp "static const unsigned char ${name}[] = {${hex}};\n")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS web/${f})
endforeach()
file(COPY_FILE ${ASSETS}.tmp ${ASSETS} ONLY_IF_DIFFERENT)

# Application
add_executable(iphone-forensics
    src/main.cpp
    src/util.cpp
    src/plist-parser.cpp
    src/backup-scanner.cpp
    src/path-sanitizer.cpp
    src/sqlite.cpp
    src/audit-engine.cpp
    src/audit-report.cpp
    src/usbmux.cpp
    src/tls-channel.cpp
    src/device.cpp
    src/carver.cpp)
target_include_directories(iphone-forensics PRIVATE include ${CMAKE_BINARY_DIR}/generated)
target_link_libraries(iphone-forensics PRIVATE http_server sqlite3)

# Platform libraries: CNG + Schannel + shell on Windows, Security framework (SecureTransport, CommonCrypto) on macOS
if(WIN32)
    target_compile_definitions(iphone-forensics PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(iphone-forensics PRIVATE bcrypt ncrypt crypt32 secur32 shell32 ole32)
elseif(APPLE)
    target_link_libraries(iphone-forensics PRIVATE "-framework Security" "-framework CoreFoundation")
    set_source_files_properties(src/tls-channel.cpp PROPERTIES COMPILE_OPTIONS -Wno-deprecated-declarations)
endif()

if(MSVC)
    target_compile_options(iphone-forensics PRIVATE /utf-8 /W4)
else()
    target_compile_options(iphone-forensics PRIVATE -Wall -Wextra)
endif()
