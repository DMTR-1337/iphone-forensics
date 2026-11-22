#ifndef USBMUX_HPP
#define USBMUX_HPP

#include "plist-parser.hpp"
#include <memory>

/* Blocking byte stream */
class Stream
{
public:
    virtual ~Stream() = default;
    virtual void write(const std::string& data) = 0;

    /* Exactly n bytes or throws */
    virtual void read(char* out, size_t n) = 0;
    std::string read(size_t n);
};

/* Connection to usbmuxd; after mux_connect() a raw tunnel to a device port */
class Socket : public Stream
{
public:
    Socket();
    ~Socket();
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    void write(const std::string& data) override;
    void read(char* out, size_t n) override;
    using Stream::read;

    /* At least one byte */
    size_t read_some(char* out, size_t n);

private:
    intptr_t fd;
};

/* USB-attached device */
struct MuxDevice
{
    int id;
    std::string udid;
};

std::vector<MuxDevice> mux_devices();

/* Pair record written when the user tapped Trust in Apple Devices / iTunes / Finder; empty if none */
Plist mux_pair_record(const std::string& udid);

/* Tunnel to a TCP port on the device */
std::unique_ptr<Socket> mux_connect(int device_id, uint16_t port);

#endif
