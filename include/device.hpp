#ifndef DEVICE_HPP
#define DEVICE_HPP

#include "tls-channel.hpp"
#include "util.hpp"

/* USB-connected iPhone */
struct DeviceInfo
{
    std::string udid, name, ios, product, problem;
    bool paired = false;

    std::string to_json() const;
};

/* Attached devices; error set when usbmuxd is unreachable */
std::vector<DeviceInfo> list_devices(std::string& error);

/* AFC file metadata */
struct AfcStat
{
    std::string type;  /* file, directory, symlink, other */
    uint64_t size = 0;
};

typedef std::function<void(const std::string& path, const AfcStat& st)> Visit;

/* Read-only AFC session on the device media folder (/var/mobile/Media) */
class AfcSession
{
public:
    explicit AfcSession(const std::string& udid);

    DeviceInfo info;

    /* Every entry below dir, depth first, links not followed */
    void walk(const std::string& dir, const Visit& fn);

    /* Streaming reader, file opened read-only */
    Reader reader(const std::string& path);

private:
    std::unique_ptr<Socket> sock;
    std::unique_ptr<TlsChannel> tls;
    Stream* io = nullptr;
    uint64_t packet = 0;

    std::string call(uint64_t op, const std::string& head);
    AfcStat stat(const std::string& path);
    void walk(const std::string& dir, const Visit& fn, int depth);
};

#endif
