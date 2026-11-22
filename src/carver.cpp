#include "carver.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>

namespace
{
    const size_t npos = std::string::npos;
    const size_t min_size = 2048;  /* smaller hits are almost always noise */

    unsigned be16(const std::string& d, size_t p) { return uint8_t(d[p]) << 8 | uint8_t(d[p + 1]); }
    unsigned be32(const std::string& d, size_t p) { return be16(d, p) << 16 | be16(d, p + 2); }

    /* JPEG from SOI: marker segments up to SOS, entropy data up to EOI; progressive scans repeat */
    bool jpeg(const std::string& d, size_t p, Carved& c)
    {
        bool frame = false;
        for (size_t k = p + 2; k + 4 <= d.size();)
        {
            if (uint8_t(d[k]) != 0xFF) return false;
            unsigned m = uint8_t(d[k + 1]);
            if (m == 0xFF) { k++; continue; }
            if (m == 0x01 || (m >= 0xD0 && m <= 0xD7)) { k += 2; continue; }
            if (m == 0xD8 || m == 0xD9 || m == 0x00) return false;

            size_t len = be16(d, k + 2);
            if (len < 2 || k + 2 + len > d.size()) return false;
            if (m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC && len >= 7)
            {
                frame = true;
                c.height = be16(d, k + 5);
                c.width = be16(d, k + 7);
            }
            k += 2 + len;
            if (m != 0xDA) continue;

            /* FF00 = stuffed byte, FFD0-D7 = restart, FFD9 = end, other marker = next segment */
            while (k + 1 < d.size())
            {
                if (uint8_t(d[k]) != 0xFF) { k++; continue; }
                unsigned n = uint8_t(d[k + 1]);
                if (n == 0xFF) { k++; continue; }
                if (n == 0x00 || (n >= 0xD0 && n <= 0xD7)) { k += 2; continue; }
                if (n == 0xD9)
                {
                    c.type = "jpeg";
                    c.offset = p;
                    c.size = k + 2 - p;
                    return frame && c.width && c.height;
                }
                break;
            }
        }
        return false;
    }

    /* Record an ISO-BMFF stream spanning [p, end) once at least one media box was seen */
    bool finish(const std::string& d, size_t p, size_t end, Carved& c)
    {
        (void)d;
        c.offset = p;
        c.size = end - p;
        return c.size >= min_size;
    }

    /* ISO base media (HEIC/MOV/MP4) from an ftyp box: walk top-level boxes to the end of the stream */
    bool isobmff(const std::string& d, size_t p, Carved& c)
    {
        /* Brand in the ftyp payload selects the kind */
        size_t first = be32(d, p);
        if (first < 16 || first > d.size() - p) return false;
        std::string brand = d.substr(p + 8, 4);
        static const char* heic[] = { "heic", "heix", "heim", "heis", "hevc", "mif1", "msf1" };
        static const char* mp4[] = { "mp41", "mp42", "isom", "iso2", "iso5", "M4V ", "M4A ", "dash" };
        if (std::any_of(std::begin(heic), std::end(heic), [&](const char* b) { return brand == b; })) c.type = "heic";
        else if (brand == "qt  ") c.type = "mov";
        else if (std::any_of(std::begin(mp4), std::end(mp4), [&](const char* b) { return brand == b; })) c.type = "mp4";
        else return false;

        /* Each box: 4-byte size (1 = 64-bit size follows, 0 = to end), 4-byte printable type */
        bool seen_media = false;
        size_t k = p;
        for (int boxes = 0; k + 8 <= d.size() && boxes < 100000; boxes++)
        {
            uint64_t len = be32(d, k);
            std::string type = d.substr(k + 4, 4);
            for (char ch : type)
                if (ch < 0x20 || ch > 0x7E) return seen_media && finish(d, p, k, c);
            if (len == 1)
            {
                if (k + 16 > d.size()) break;
                len = (uint64_t(be32(d, k + 8)) << 32) | be32(d, k + 12);
            }
            else if (len == 0) len = d.size() - k;  /* last box runs to end of stream */
            if (len < 8 || len > d.size() - k) return seen_media && finish(d, p, k, c);
            if (type == "mdat" || type == "moov" || type == "meta") seen_media = true;
            k += len;
        }
        return seen_media && finish(d, p, k, c);
    }

    /* PNG: IHDR first, chunks up to IEND */
    bool png(const std::string& d, size_t p, Carved& c)
    {
        for (size_t k = p + 8; k + 12 <= d.size();)
        {
            size_t len = be32(d, k);
            if (len > d.size() - k - 12) return false;
            std::string type = d.substr(k + 4, 4);
            if (k == p + 8 && (type != "IHDR" || len < 8)) return false;
            if (type == "IHDR")
            {
                c.width = be32(d, k + 8);
                c.height = be32(d, k + 12);
            }
            k += 12 + len;
            if (type == "IEND")
            {
                c.type = "png";
                c.offset = p;
                c.size = k - p;
                return c.width && c.height;
            }
        }
        return false;
    }
}

std::vector<Carved> carve_images(const std::string& d)
{
    static const std::string soi("\xFF\xD8\xFF", 3), sig("\x89PNG\r\n\x1a\n", 8), ftyp("ftyp", 4);
    std::vector<Carved> out;
    size_t j = d.find(soi), q = d.find(sig), f = d.find(ftyp);
    for (size_t p = 0; p < d.size();)
    {
        /* Next candidate of each kind, re-searching only the ones that fell behind */
        if (j != npos && j < p) j = d.find(soi, p);
        if (q != npos && q < p) q = d.find(sig, p);
        /* ftyp sits 4 bytes into the box, so a hit only counts when the box start is at/after p */
        while (f != npos && f >= 4 && f - 4 < p) f = d.find(ftyp, f + 1);
        size_t fb = f == npos ? npos : f - 4;  /* box start */
        size_t n = std::min({ j, q, fb });
        if (n == npos) break;

        Carved c;
        bool ok = n == j ? jpeg(d, n, c) : n == q ? png(d, n, c) : isobmff(d, n, c);
        if (ok && c.size >= min_size && !(c.offset == 0 && c.size == d.size()))
        {
            out.push_back(c);
            p = c.offset + c.size;  /* skips thumbnails nested inside this image */
        }
        else p = n + 1;
    }
    return out;
}

std::vector<std::string> photo_names(const std::string& d)
{
    static const char* exts[] = { "HEIC", "HEIF", "JPG", "JPEG", "PNG", "GIF", "DNG", "MOV", "MP4" };
    std::vector<std::string> out;
    for (size_t p = d.find('.'); p != npos; p = d.find('.', p + 1))
    {
        size_t e = p + 1;
        while (e < d.size() && e - p <= 5 && std::isalnum(uint8_t(d[e]))) e++;
        if (e < d.size() && std::isalnum(uint8_t(d[e]))) continue;
        std::string ext = d.substr(p + 1, e - p - 1);
        std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char ch) { return (char)std::toupper(ch); });
        if (std::none_of(std::begin(exts), std::end(exts), [&](const char* x) { return ext == x; })) continue;

        size_t b = p;
        while (b > 0 && p - b < 64 && (std::isalnum(uint8_t(d[b - 1])) || d[b - 1] == '_' || d[b - 1] == '-')) b--;
        std::string name = d.substr(b, e - b);

        /* SQLite record header bytes can glue onto the name; camera names start at IMG_ */
        size_t img = name.find("IMG_");
        if (img != npos) name = name.substr(img);
        if (name.size() - ext.size() - 1 >= 3) out.push_back(name);
    }
    return out;
}
