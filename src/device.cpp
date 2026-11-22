#include "device.hpp"
#include <map>
#include <stdexcept>

namespace
{
    const size_t npos = std::string::npos;

    /* AFC operations used here: read-only subset */
    enum : uint64_t { AFC_STATUS = 1, AFC_READ_DIR = 3, AFC_GET_FILE_INFO = 10, AFC_FILE_OPEN = 13, AFC_FILE_READ = 15, AFC_FILE_CLOSE = 20 };
    const uint64_t AFC_RDONLY = 1;

    std::string le64(uint64_t v)
    {
        std::string s;
        for (int k = 0; k < 8; k++) s += char(v >> (8 * k));
        return s;
    }

    uint64_t get64(const std::string& s, size_t pos)
    {
        if (pos + 8 > s.size()) throw std::runtime_error("short AFC reply");
        uint64_t v = 0;
        for (int k = 7; k >= 0; k--) v = v << 8 | uint8_t(s[pos + k]);
        return v;
    }

    std::string explain(const std::string& e)
    {
        if (e == "InvalidHostID" || e == "InvalidPairRecord") return "the iPhone no longer trusts this computer - reconnect, unlock it and tap Trust in Apple Devices / Finder";
        if (e == "PasswordProtected") return "the iPhone is locked - unlock it and try again";
        if (e == "UserDeniedPairing" || e == "PairingDialogResponsePending") return "Trust was not accepted on the iPhone";
        return "lockdown error: " + e;
    }

    /* lockdownd on port 62078: 4-byte big-endian length + plist */
    class Lockdown
    {
    public:
        explicit Lockdown(int device_id) : sock(mux_connect(device_id, 62078)), io(sock.get()) {}

        Plist request(Plist req)
        {
            req.dict["Label"] = plist_str("iphone-forensics");
            std::string body = to_xml(req), h;
            for (int k = 3; k >= 0; k--) h += char(body.size() >> (8 * k));
            io->write(h + body);

            std::string r = io->read(4);
            uint32_t len = 0;
            for (char c : r) len = len << 8 | uint8_t(c);
            if (len > (4u << 20)) throw std::runtime_error("bad lockdown reply");
            Plist reply = parse_plist(io->read(len));
            if (!reply["Error"].s.empty()) throw std::runtime_error(explain(reply["Error"].s));
            return reply;
        }

        /* Session with the pair record, TLS from here on when requested */
        void start_session(const Plist& pair)
        {
            Plist r = request(plist_dict({ { "Request", plist_str("StartSession") }, { "ProtocolVersion", plist_str("2") },
                { "HostID", plist_str(pair["HostID"].s) }, { "SystemBUID", plist_str(pair["SystemBUID"].s) } }));
            if (!r["EnableSessionSSL"].boolean()) return;
            tls = std::make_unique<TlsChannel>(*sock, pair["HostCertificate"].s, pair["HostPrivateKey"].s);
            io = tls.get();
        }

        void fill(DeviceInfo& d)
        {
            Plist r = request(plist_dict({ { "Request", plist_str("GetValue") } }));
            const Plist& v = r["Value"];
            d.name = v["DeviceName"].s;
            d.ios = v["ProductVersion"].s;
            d.product = v["ProductType"].s;
        }

        std::unique_ptr<Socket> sock;
        std::unique_ptr<TlsChannel> tls;
        Stream* io;
    };
}

std::string DeviceInfo::to_json() const
{
    return json_obj({
        { "udid", json(udid) }, { "name", json(name) }, { "ios", json(ios) }, { "product", json(product) },
        { "paired", jbool(paired) }, { "problem", json(problem) } });
}

std::vector<DeviceInfo> list_devices(std::string& error)
{
    std::vector<DeviceInfo> out;
    try
    {
        for (const auto& m : mux_devices())
        {
            DeviceInfo d;
            d.udid = m.udid;
            try
            {
                /* Basic values are readable without a session */
                Lockdown(m.id).fill(d);
                d.paired = !mux_pair_record(m.udid)["HostID"].s.empty();
                if (!d.paired) d.problem = "not trusted yet: unlock the iPhone, open Apple Devices (Windows) or Finder (macOS) and tap Trust";
            }
            catch (const std::exception& e)
            {
                d.problem = e.what();
            }
            out.push_back(d);
        }
    }
    catch (const std::exception& e)
    {
        error = e.what();
    }
    return out;
}

AfcSession::AfcSession(const std::string& udid)
{
    int id = -1;
    for (const auto& m : mux_devices())
        if (m.udid == udid) id = m.id;
    if (id < 0) throw std::runtime_error("the iPhone is no longer connected");

    Plist pair = mux_pair_record(udid);
    if (pair["HostID"].s.empty()) throw std::runtime_error("no pair record - trust this computer on the iPhone first (Apple Devices / Finder)");

    Lockdown ld(id);
    ld.start_session(pair);
    info.udid = udid;
    info.paired = true;
    ld.fill(info);

    /* AFC is rooted at /var/mobile/Media */
    Plist svc = ld.request(plist_dict({ { "Request", plist_str("StartService") }, { "Service", plist_str("com.apple.afc") } }));
    sock = mux_connect(id, uint16_t(svc["Port"].i));
    io = sock.get();
    if (svc["EnableServiceSSL"].boolean())
    {
        tls = std::make_unique<TlsChannel>(*sock, pair["HostCertificate"].s, pair["HostPrivateKey"].s);
        io = tls.get();
    }
}

/* AFC packet: "CFA6LPAA", entire length, header length, packet number, operation (little-endian u64) */
std::string AfcSession::call(uint64_t op, const std::string& head)
{
    io->write("CFA6LPAA" + le64(40 + head.size()) + le64(40 + head.size()) + le64(packet++) + le64(op) + head);

    std::string r = io->read(40);
    if (r.compare(0, 8, "CFA6LPAA") != 0) throw std::runtime_error("bad AFC reply");
    uint64_t total = get64(r, 8), self = get64(r, 16), rop = get64(r, 32);
    if (self < 40 || total < self || total > (64u << 20)) throw std::runtime_error("bad AFC packet size");
    std::string data = io->read(size_t(self - 40)) + io->read(size_t(total - self));
    if (rop == AFC_STATUS && get64(data, 0) != 0) throw std::runtime_error("AFC error " + std::to_string(get64(data, 0)));
    return data;
}

AfcStat AfcSession::stat(const std::string& path)
{
    /* Reply: key\0value\0 pairs */
    std::string d = call(AFC_GET_FILE_INFO, path + '\0');
    std::map<std::string, std::string> kv;
    for (size_t p = 0; p < d.size();)
    {
        size_t a = d.find('\0', p);
        if (a == npos) break;
        size_t b = std::min(d.find('\0', a + 1), d.size());
        kv[d.substr(p, a - p)] = d.substr(a + 1, b - a - 1);
        p = b + 1;
    }
    AfcStat s;
    const std::string& t = kv["st_ifmt"];
    s.type = t == "S_IFREG" ? "file" : t == "S_IFDIR" ? "directory" : t == "S_IFLNK" ? "symlink" : "other";
    s.size = kv["st_size"].empty() ? 0 : std::stoull(kv["st_size"]);
    return s;
}

void AfcSession::walk(const std::string& dir, const Visit& fn)
{
    walk(dir, fn, 0);
}

void AfcSession::walk(const std::string& dir, const Visit& fn, int depth)
{
    if (depth > 32) return;
    std::string d = call(AFC_READ_DIR, dir + '\0');
    for (size_t p = 0; p < d.size();)
    {
        size_t e = std::min(d.find('\0', p), d.size());
        std::string name = d.substr(p, e - p);
        p = e + 1;
        if (name.empty() || name == "." || name == "..") continue;

        std::string path = dir + "/" + name;
        AfcStat s = stat(path);
        fn(path, s);
        if (s.type == "directory") walk(path, fn, depth + 1);
    }
}

Reader AfcSession::reader(const std::string& path)
{
    return [this, path](const Sink& fn)
    {
        uint64_t handle = get64(call(AFC_FILE_OPEN, le64(AFC_RDONLY) + path + '\0'), 0), total = 0;
        try
        {
            /* Empty chunk = end of file */
            for (std::string chunk; !(chunk = call(AFC_FILE_READ, le64(handle) + le64(1 << 16))).empty(); total += chunk.size())
                fn(chunk.data(), chunk.size());
        }
        catch (...)
        {
            try { call(AFC_FILE_CLOSE, le64(handle)); }
            catch (...) {}
            throw;
        }
        call(AFC_FILE_CLOSE, le64(handle));
        return total;
    };
}
