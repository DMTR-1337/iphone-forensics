#include "usbmux.hpp"
#include "util.hpp"
#include <stdexcept>
#include <cstring>

/* Platform headers, Winsock is initialized by WebServer */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET native;
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
typedef int native;
#endif

std::string Stream::read(size_t n)
{
    std::string s(n, '\0');
    if (n) read(&s[0], n);
    return s;
}

Socket::Socket()
{
#ifdef _WIN32
    /* Apple Mobile Device Service */
    native s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27015);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s == INVALID_SOCKET || connect(s, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        if (s != INVALID_SOCKET) closesocket(s);
        throw std::runtime_error("Apple Mobile Device Service is not running - install Apple Devices (Microsoft Store) or iTunes");
    }
    DWORD tv = 30000;
#else
    native s = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/var/run/usbmuxd");
    if (s < 0 || connect(s, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        if (s >= 0) close(s);
        throw std::runtime_error("cannot reach usbmuxd at /var/run/usbmuxd");
    }
    struct timeval tv = { 30, 0 };
#endif
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    fd = (intptr_t)s;
}

Socket::~Socket()
{
#ifdef _WIN32
    closesocket((native)fd);
#else
    close((native)fd);
#endif
}

void Socket::write(const std::string& data)
{
    for (size_t off = 0; off < data.size();)
    {
        int n = (int)send((native)fd, data.data() + off, (int)(data.size() - off), 0);
        if (n <= 0) throw std::runtime_error("device connection lost");
        off += n;
    }
}

size_t Socket::read_some(char* out, size_t n)
{
    int r = (int)recv((native)fd, out, (int)n, 0);
    if (r <= 0) throw std::runtime_error("device connection closed");
    return size_t(r);
}

void Socket::read(char* out, size_t n)
{
    for (size_t got = 0; got < n;) got += read_some(out + got, n - got);
}

namespace
{
    void put32(std::string& s, uint32_t v)
    {
        for (int k = 0; k < 4; k++) s += char(v >> (8 * k));
    }

    /* usbmuxd plist message: 16-byte little-endian header {length, version 1, type 8 (plist), tag} */
    Plist exchange(Socket& s, Plist req)
    {
        req.dict["ClientVersionString"] = plist_str("iphone-forensics");
        req.dict["ProgName"] = plist_str("iphone-forensics");
        req.dict["kLibUSBMuxVersion"] = plist_int(3);
        std::string body = to_xml(req), h;
        put32(h, uint32_t(16 + body.size()));
        put32(h, 1);
        put32(h, 8);
        put32(h, 1);
        s.write(h + body);

        std::string r = s.read(16);
        uint32_t len = uint8_t(r[0]) | uint8_t(r[1]) << 8 | uint8_t(r[2]) << 16 | uint32_t(uint8_t(r[3])) << 24;
        if (len < 16 || len > (16u << 20)) throw std::runtime_error("bad usbmuxd reply");
        return parse_plist(s.read(len - 16));
    }
}

std::vector<MuxDevice> mux_devices()
{
    Socket s;
    Plist r = exchange(s, plist_dict({ { "MessageType", plist_str("ListDevices") } }));
    std::vector<MuxDevice> out;
    for (const auto& d : r["DeviceList"].arr)
    {
        /* USB only, Wi-Fi sync entries are skipped */
        const Plist& p = d["Properties"];
        if (p["ConnectionType"].s != "USB") continue;
        out.push_back({ int(d["DeviceID"].type == Plist::Int ? d["DeviceID"].i : p["DeviceID"].i), p["UDID"].s.empty() ? p["SerialNumber"].s : p["UDID"].s });
    }
    return out;
}

Plist mux_pair_record(const std::string& udid)
{
    try
    {
        Socket s;
        Plist r = exchange(s, plist_dict({ { "MessageType", plist_str("ReadPairRecord") }, { "PairRecordID", plist_str(udid) } }));
        if (r["PairRecordData"].type == Plist::Data) return parse_plist(r["PairRecordData"].s);
    }
    catch (const std::exception&)
    {
    }

#ifdef _WIN32
    /* Older Apple Mobile Device Service: records live in %ProgramData%\Apple\Lockdown */
    fs::path f = env_path("ProgramData") / "Apple" / "Lockdown" / to_path(udid + ".plist");
    std::error_code ec;
    if (fs::is_regular_file(f, ec))
    {
        try { return load_plist(f); }
        catch (const std::exception&) { throw std::runtime_error("pair record exists but is not readable - run as administrator"); }
    }
#endif
    return Plist();
}

std::unique_ptr<Socket> mux_connect(int device_id, uint16_t port)
{
    auto s = std::make_unique<Socket>();
    Plist r = exchange(*s, plist_dict({ { "MessageType", plist_str("Connect") }, { "DeviceID", plist_int(device_id) },
        { "PortNumber", plist_int(uint16_t(port << 8 | port >> 8)) } }));
    if (r["Number"].i != 0) throw std::runtime_error("device refused connection to port " + std::to_string(port));
    return s;
}
