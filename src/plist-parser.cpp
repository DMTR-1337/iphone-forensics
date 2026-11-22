#include "plist-parser.hpp"
#include "util.hpp"
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <cstring>
#include <cstdio>
#include <chrono>

const Plist& Plist::operator[](const std::string& key) const
{
    static const Plist empty;
    auto it = dict.find(key);
    return it == dict.end() ? empty : it->second;
}

namespace
{
    const size_t npos = std::string::npos;

    [[noreturn]] void fail(const char* msg) { throw std::runtime_error(std::string("plist: ") + msg); }

    /* Append code point as UTF-8 */
    void put_utf8(std::string& o, uint32_t c)
    {
        if (c < 0x80) o += char(c);
        else if (c < 0x800) o += { char(0xC0 | c >> 6), char(0x80 | (c & 0x3F)) };
        else if (c < 0x10000) o += { char(0xE0 | c >> 12), char(0x80 | (c >> 6 & 0x3F)), char(0x80 | (c & 0x3F)) };
        else o += { char(0xF0 | c >> 18), char(0x80 | (c >> 12 & 0x3F)), char(0x80 | (c >> 6 & 0x3F)), char(0x80 | (c & 0x3F)) };
    }

    /* Binary plist, see CFBinaryPList.c for the format */
    class Binary
    {
    public:
        explicit Binary(const std::string& d) : d(d)
        {
            if (d.size() < 40) fail("truncated");
            const uint64_t t = d.size() - 32;
            osize = uint8_t(d[t + 6]);
            rsize = uint8_t(d[t + 7]);
            count = be(t + 8, 8);
            top = be(t + 16, 8);
            table = be(t + 24, 8);
            if (osize < 1 || osize > 8 || rsize < 1 || rsize > 8 || top >= count || count > t || table > t || count * osize > t - table) fail("bad trailer");
        }

        Plist root() { return object(top, 0); }

    private:
        const std::string& d;
        uint64_t osize, rsize, count, top, table, nodes = 0;

        /* Big-endian unsigned read with bounds check */
        uint64_t be(uint64_t pos, uint64_t n) const
        {
            if (pos > d.size() || n > d.size() - pos) fail("out of bounds");
            uint64_t v = 0;
            for (uint64_t k = 0; k < n; k++) v = v << 8 | uint8_t(d[pos + k]);
            return v;
        }

        /* Object length from marker nibble or trailing int object */
        uint64_t length(uint64_t& pos, uint8_t low) const
        {
            if (low != 0xF) return low;
            uint8_t m = uint8_t(be(pos, 1));
            if (m >> 4 != 1 || (m & 0xF) > 3) fail("bad length");
            uint64_t n = 1ull << (m & 0xF), v = be(pos + 1, n);
            pos += 1 + n;
            return v;
        }

        Plist object(uint64_t ref, int depth)
        {
            /* Depth and node budget guard against cyclic or exploding references */
            if (ref >= count || depth > 64 || ++nodes > 1000000) fail("bad reference");
            uint64_t pos = be(table + ref * osize, osize);
            uint8_t m = uint8_t(be(pos++, 1)), low = m & 0xF;
            Plist p;

            switch (m >> 4)
            {
            case 0x0:
                if (low == 8 || low == 9) { p.type = Plist::Bool; p.i = low == 9; }
                break;
            case 0x1:
            {
                /* 16-byte ints: keep low 64 bits */
                uint64_t n = 1ull << low;
                if (n > 16) fail("bad int");
                p.type = Plist::Int;
                p.i = int64_t(n > 8 ? be(pos + 8, 8) : be(pos, n));
                break;
            }
            case 0x2:
            case 0x3:
            {
                uint64_t n = 1ull << low, v = be(pos, n);
                if (n == 4) { uint32_t u = uint32_t(v); float f; memcpy(&f, &u, 4); p.r = f; }
                else if (n == 8) memcpy(&p.r, &v, 8);
                else fail("bad real");
                p.type = m >> 4 == 2 ? Plist::Real : Plist::Date;
                break;
            }
            case 0x4:
            case 0x5:
            {
                uint64_t n = length(pos, low);
                be(pos, n);
                p.type = m >> 4 == 4 ? Plist::Data : Plist::String;
                p.s = d.substr(pos, n);
                break;
            }
            case 0x6:
            {
                /* UTF-16BE with surrogate pairs */
                uint64_t n = length(pos, low);
                p.type = Plist::String;
                for (uint64_t k = 0; k < n; k++)
                {
                    uint32_t c = uint32_t(be(pos + 2 * k, 2));
                    if (c >= 0xD800 && c < 0xDC00 && k + 1 < n) c = 0x10000 + ((c - 0xD800) << 10) + (uint32_t(be(pos + 2 * ++k, 2)) - 0xDC00);
                    put_utf8(p.s, c);
                }
                break;
            }
            case 0x8:
                p.type = Plist::Int;
                p.i = int64_t(be(pos, low + 1));
                break;
            case 0xA:
            case 0xD:
            {
                uint64_t n = length(pos, low);
                if (n > count) fail("bad collection");
                if (m >> 4 == 0xA)
                {
                    p.type = Plist::Array;
                    for (uint64_t k = 0; k < n; k++) p.arr.push_back(object(be(pos + k * rsize, rsize), depth + 1));
                }
                else
                {
                    p.type = Plist::Dict;
                    for (uint64_t k = 0; k < n; k++)
                        p.dict[object(be(pos + k * rsize, rsize), depth + 1).s] = object(be(pos + (n + k) * rsize, rsize), depth + 1);
                }
                break;
            }
            default:
                break;
            }
            return p;
        }
    };

    /* XML plist, the subset Apple writes */
    class Xml
    {
    public:
        explicit Xml(const std::string& d) : d(d) {}

        Plist root()
        {
            size_t p = d.find("<plist");
            if (p == npos || (pos = d.find('>', p)) == npos) fail("no plist element");
            pos++;
            return value(0);
        }

    private:
        const std::string& d;
        size_t pos = 0;

        /* Next element name, skipping comments; empty set for <x/> */
        std::string tag(bool& empty)
        {
            while (true)
            {
                if ((pos = d.find('<', pos)) == npos) fail("unexpected end");
                if (d.compare(pos, 4, "<!--") == 0)
                {
                    if ((pos = d.find("-->", pos)) == npos) fail("unterminated comment");
                    continue;
                }
                size_t e = d.find('>', pos);
                if (e == npos) fail("unterminated tag");
                std::string t = d.substr(pos + 1, e - pos - 1);
                pos = e + 1;
                empty = !t.empty() && t.back() == '/';
                if (empty) t.pop_back();
                return t.substr(0, t.find_first_of(" \t\r\n"));
            }
        }

        /* Element text up to its closing tag, entities decoded */
        std::string text(const std::string& name)
        {
            size_t e = d.find("</" + name, pos);
            if (e == npos) fail("unclosed element");
            std::string raw = d.substr(pos, e - pos), o;
            pos = d.find('>', e) + 1;

            for (size_t k = 0; k < raw.size(); k++)
            {
                size_t sc = raw[k] == '&' ? raw.find(';', k) : npos;
                if (sc == npos) { o += raw[k]; continue; }
                std::string ent = raw.substr(k + 1, sc - k - 1);
                if (ent == "amp") o += '&';
                else if (ent == "lt") o += '<';
                else if (ent == "gt") o += '>';
                else if (ent == "quot") o += '"';
                else if (ent == "apos") o += '\'';
                else if (ent.size() > 1 && ent[0] == '#') put_utf8(o, uint32_t(std::stoul(ent.substr(ent[1] == 'x' ? 2 : 1), nullptr, ent[1] == 'x' ? 16 : 10)));
                else { o += raw[k]; continue; }
                k = sc;
            }
            return o;
        }

        /* ISO-8601 UTC → seconds since 2001-01-01 */
        static double date(const std::string& v)
        {
            int Y, M, D, h, m, s;
            if (sscanf(v.c_str(), "%d-%d-%dT%d:%d:%d", &Y, &M, &D, &h, &m, &s) != 6) fail("bad date");
            using namespace std::chrono;
            double days = double(sys_days(year(Y) / M / D).time_since_epoch().count());
            return days * 86400.0 + h * 3600 + m * 60 + s - 978307200.0;
        }

        Plist value(int depth)
        {
            if (depth > 64) fail("too deep");
            bool empty;
            std::string t = tag(empty);
            Plist p;

            if (t == "dict" || t == "array")
            {
                p.type = t == "dict" ? Plist::Dict : Plist::Array;
                while (!empty)
                {
                    size_t save = pos;
                    bool e;
                    std::string k = tag(e);
                    if (k == "/" + t) break;
                    if (p.type == Plist::Array) { pos = save; p.arr.push_back(value(depth + 1)); }
                    else if (k == "key") { std::string name = e ? "" : text("key"); p.dict[name] = value(depth + 1); }
                    else fail("expected key");
                }
                return p;
            }
            if (t == "true" || t == "false")
            {
                p.type = Plist::Bool;
                p.i = t == "true";
                if (!empty) text(t);
                return p;
            }

            std::string v = empty ? "" : text(t);
            if (t == "string") { p.type = Plist::String; p.s = v; }
            else if (t == "integer") { p.type = Plist::Int; p.i = std::stoll(v); }
            else if (t == "real") { p.type = Plist::Real; p.r = std::stod(v); }
            else if (t == "date") { p.type = Plist::Date; p.r = date(v); }
            else if (t == "data") { p.type = Plist::Data; p.s = base64_decode(v); }
            else fail("unknown element");
            return p;
        }
    };
}

Plist parse_plist(const std::string& data)
{
    if (data.compare(0, 8, "bplist00") == 0) return Binary(data).root();
    return Xml(data).root();
}

Plist load_plist(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) fail("cannot open file");
    return parse_plist(std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()));
}

Plist plist_str(const std::string& s)
{
    Plist p;
    p.type = Plist::String;
    p.s = s;
    return p;
}

Plist plist_int(int64_t i)
{
    Plist p;
    p.type = Plist::Int;
    p.i = i;
    return p;
}

Plist plist_dict(std::initializer_list<std::pair<const std::string, Plist>> items)
{
    Plist p;
    p.type = Plist::Dict;
    p.dict = items;
    return p;
}

static std::string node(const Plist& p)
{
    auto esc = [](const std::string& s)
    {
        std::string o;
        for (char c : s) o += c == '&' ? "&amp;" : c == '<' ? "&lt;" : c == '>' ? "&gt;" : std::string(1, c);
        return o;
    };

    switch (p.type)
    {
    case Plist::Bool: return p.i ? "<true/>" : "<false/>";
    case Plist::Int: return "<integer>" + std::to_string(p.i) + "</integer>";
    case Plist::Real: return "<real>" + std::to_string(p.r) + "</real>";
    case Plist::String: return "<string>" + esc(p.s) + "</string>";
    case Plist::Data: return "<data>" + base64_encode(p.s) + "</data>";
    case Plist::Array:
    {
        std::string o = "<array>";
        for (const auto& v : p.arr) o += node(v);
        return o + "</array>";
    }
    case Plist::Dict:
    {
        std::string o = "<dict>";
        for (const auto& [k, v] : p.dict) o += "<key>" + esc(k) + "</key>" + node(v);
        return o + "</dict>";
    }
    default: return "<string/>";
    }
}

std::string to_xml(const Plist& p)
{
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">" + node(p) + "</plist>\n";
}
