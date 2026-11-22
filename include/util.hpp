#ifndef UTIL_HPP
#define UTIL_HPP

#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>
#include <functional>

namespace fs = std::filesystem;

/* Chunked byte stream: a Reader feeds a Sink and returns the byte count */
typedef std::function<void(const char*, size_t)> Sink;
typedef std::function<uint64_t(const Sink&)> Reader;

/* UTF-8 <-> native path */
fs::path to_path(const std::string& utf8);
std::string to_utf8(const fs::path& path);

/* User profile and per-user application data folders */
fs::path home_dir();
fs::path appdata_dir();

/* Environment variable as path, empty if unset */
fs::path env_path(const char* name);

/* Reader over a file opened read-only */
Reader file_reader(const fs::path& path);

/* SHA-256 of a stream, lowercase hex */
std::string sha256(const Reader& src);

/* Copy a stream to a new file dst, returns SHA-256 of the copied bytes */
std::string copy_hashed(const Reader& src, const fs::path& dst, uint64_t& bytes);

/* Open a folder or URL with the OS default handler */
void open_native(const std::string& target);

/* String helpers */
std::string lower(std::string s);

/* JSON: quote a string, build an object from pre-encoded values, or join pre-encoded elements */
std::string json(const std::string& s);
std::string json_obj(std::initializer_list<std::pair<const char*, std::string>> fields);
std::string json_arr(const std::vector<std::string>& items);
std::string jbool(bool b);

std::string base64_encode(const std::string& s);
std::string base64_decode(const std::string& s);
std::string csv(const std::vector<std::string>& cols);
std::string iso_utc(double unix_seconds);
std::string timestamp();
std::string query_param(const std::string& query, const std::string& key);

#endif
