#include "util.hpp"
#include <fstream>
#include <chrono>
#include <ctime>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <stdexcept>

/* Platform headers */
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <shellapi.h>
#include <bcrypt.h>
#elif defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#include <pwd.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
extern char** environ;
#else
#error "Windows or macOS required"
#endif

fs::path to_path(const std::string& utf8)
{
    return fs::path(std::u8string(utf8.begin(), utf8.end()));
}

std::string to_utf8(const fs::path& path)
{
    std::u8string u = path.u8string();
    return std::string(u.begin(), u.end());
}

#ifdef _WIN32
static fs::path known_folder(REFKNOWNFOLDERID id)
{
    PWSTR p = nullptr;
    fs::path r;
    if (SUCCEEDED(SHGetKnownFolderPath(id, 0, nullptr, &p))) r = p;
    CoTaskMemFree(p);
    return r;
}

fs::path home_dir() { return known_folder(FOLDERID_Profile); }
fs::path appdata_dir() { return known_folder(FOLDERID_RoamingAppData); }

fs::path env_path(const char* name)
{
    std::wstring w(name, name + strlen(name));
    const wchar_t* v = _wgetenv(w.c_str());
    return v ? fs::path(v) : fs::path();
}
#else
fs::path home_dir()
{
    const char* h = getenv("HOME");
    if (!h || !*h)
    {
        passwd* pw = getpwuid(getuid());
        h = pw ? pw->pw_dir : "";
    }
    return to_path(h);
}

fs::path appdata_dir() { return home_dir() / "Library" / "Application Support"; }

fs::path env_path(const char* name)
{
    const char* v = getenv(name);
    return v ? to_path(v) : fs::path();
}
#endif

namespace
{
    /* Incremental SHA-256 over CNG / CommonCrypto */
    class Sha256
    {
    public:
#ifdef _WIN32
        Sha256()
        {
            if (BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &h, nullptr, 0, nullptr, 0, 0) != 0) throw std::runtime_error("BCryptCreateHash failed");
        }
        ~Sha256() { BCryptDestroyHash(h); }
        void update(const char* p, size_t n) { BCryptHashData(h, (PUCHAR)p, (ULONG)n, 0); }
        std::string hex() { unsigned char md[32]; BCryptFinishHash(h, md, 32, 0); return to_hex(md); }
    private:
        BCRYPT_HASH_HANDLE h = nullptr;
#else
        Sha256() { CC_SHA256_Init(&c); }
        void update(const char* p, size_t n) { CC_SHA256_Update(&c, p, (CC_LONG)n); }
        std::string hex() { unsigned char md[32]; CC_SHA256_Final(md, &c); return to_hex(md); }
    private:
        CC_SHA256_CTX c;
#endif
        static std::string to_hex(const unsigned char* md)
        {
            static const char* x = "0123456789abcdef";
            std::string s;
            for (int k = 0; k < 32; k++) { s += x[md[k] >> 4]; s += x[md[k] & 15]; }
            return s;
        }
    };

}

Reader file_reader(const fs::path& path)
{
    return [path](const Sink& fn)
    {
        /* 1 MiB chunks, source opened read-only */
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in) throw std::runtime_error("cannot open " + to_utf8(path.filename()));
        std::vector<char> buf(1 << 20);
        uint64_t total = 0;
        while (in)
        {
            in.read(buf.data(), buf.size());
            std::streamsize n = in.gcount();
            if (n <= 0) break;
            fn(buf.data(), size_t(n));
            total += n;
        }
        if (in.bad()) throw std::runtime_error("read error on " + to_utf8(path.filename()));
        return total;
    };
}

std::string sha256(const Reader& src)
{
    Sha256 h;
    src([&](const char* p, size_t n) { h.update(p, n); });
    return h.hex();
}

std::string copy_hashed(const Reader& src, const fs::path& dst, uint64_t& bytes)
{
    if (fs::exists(dst)) throw std::runtime_error("destination already exists");
    std::ofstream out(dst, std::ios::out | std::ios::binary);
    if (!out) throw std::runtime_error("cannot create destination");
    Sha256 h;
    bytes = src([&](const char* p, size_t n) { h.update(p, n); out.write(p, n); });
    out.close();
    if (!out) throw std::runtime_error("write failed");
    return h.hex();
}

void open_native(const std::string& target)
{
#ifdef _WIN32
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    ShellExecuteW(nullptr, L"open", to_path(target).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    CoUninitialize();
#else
    /* argv-based spawn, no shell interpretation */
    pid_t pid;
    const char* argv[] = { "/usr/bin/open", target.c_str(), nullptr };
    if (posix_spawn(&pid, argv[0], nullptr, nullptr, (char* const*)argv, environ) == 0) waitpid(pid, nullptr, 0);
#endif
}

std::string lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& s)
{
    std::string o;
    for (size_t k = 0; k < s.size(); k += 3)
    {
        uint32_t v = uint8_t(s[k]) << 16 | (k + 1 < s.size() ? uint8_t(s[k + 1]) << 8 : 0) | (k + 2 < s.size() ? uint8_t(s[k + 2]) : 0);
        o += b64[v >> 18 & 63];
        o += b64[v >> 12 & 63];
        o += k + 1 < s.size() ? b64[v >> 6 & 63] : '=';
        o += k + 2 < s.size() ? b64[v & 63] : '=';
    }
    return o;
}

std::string base64_decode(const std::string& s)
{
    /* Skips whitespace and padding */
    std::string o;
    uint32_t v = 0;
    int bits = 0;
    for (char c : s)
    {
        const char* p = c ? strchr(b64, c) : nullptr;
        if (!p) continue;
        v = v << 6 | uint32_t(p - b64);
        if ((bits += 6) >= 8) o += char(v >> (bits -= 8) & 0xFF);
    }
    return o;
}

std::string json(const std::string& s)
{
    std::string o = "\"";
    for (unsigned char c : s)
    {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c < 0x20) { char b[8]; snprintf(b, sizeof b, "\\u%04x", c); o += b; }
        else o += c;
    }
    return o + "\"";
}

std::string json_obj(std::initializer_list<std::pair<const char*, std::string>> fields)
{
    std::string o;
    for (const auto& [k, v] : fields) o += (o.empty() ? "{" : ",") + (json(k) + ":") + v;
    return (o.empty() ? "{" : o) + "}";
}

std::string json_arr(const std::vector<std::string>& items)
{
    std::string o;
    for (const auto& s : items) o += (o.empty() ? "[" : ",") + s;
    return (o.empty() ? "[" : o) + "]";
}

std::string jbool(bool b)
{
    return b ? "true" : "false";
}

std::string csv(const std::vector<std::string>& cols)
{
    std::string o;
    for (size_t k = 0; k < cols.size(); k++)
    {
        if (k) o += ',';
        if (cols[k].find_first_of(",\"\r\n") == std::string::npos) { o += cols[k]; continue; }
        o += '"';
        for (char c : cols[k]) { if (c == '"') o += '"'; o += c; }
        o += '"';
    }
    return o + "\n";
}

std::string iso_utc(double t)
{
    using namespace std::chrono;
    sys_seconds secs{ seconds(int64_t(std::floor(t))) };
    sys_days day = floor<days>(secs);
    year_month_day ymd(day);
    hh_mm_ss<seconds> hms(secs - day);
    char b[40];
    snprintf(b, sizeof b, "%04d-%02u-%02uT%02d:%02d:%02dZ", int(ymd.year()), unsigned(ymd.month()), unsigned(ymd.day()),
        int(hms.hours().count()), int(hms.minutes().count()), int(hms.seconds().count()));
    return b;
}

std::string timestamp()
{
    std::time_t t = std::time(nullptr);
    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char b[32];
    std::strftime(b, sizeof b, "%Y-%m-%d_%H-%M-%S", &tm);
    return b;
}

std::string query_param(const std::string& query, const std::string& key)
{
    for (size_t p = 0; p <= query.size();)
    {
        size_t e = std::min(query.find('&', p), query.size());
        std::string kv = query.substr(p, e - p);
        size_t eq = kv.find('=');
        if (kv.substr(0, eq) == key)
        {
            /* URL decode */
            std::string v = eq == std::string::npos ? "" : kv.substr(eq + 1), o;
            for (size_t k = 0; k < v.size(); k++)
            {
                if (v[k] == '+') o += ' ';
                else if (v[k] == '%' && k + 2 < v.size()) { o += (char)std::stoi(v.substr(k + 1, 2), nullptr, 16); k += 2; }
                else o += v[k];
            }
            return o;
        }
        p = e + 1;
    }
    return "";
}
