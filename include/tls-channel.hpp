#ifndef TLSCHANNEL_HPP
#define TLSCHANNEL_HPP

#include "usbmux.hpp"

/* TLS client over an open socket, authenticating with the host certificate of a pair record (Schannel / SecureTransport) */
class TlsChannel : public Stream
{
public:
    TlsChannel(Socket& sock, const std::string& cert_pem, const std::string& key_pem);
    ~TlsChannel();

    void write(const std::string& data) override;
    void read(char* out, size_t n) override;
    using Stream::read;

private:
    struct Impl;
    std::unique_ptr<Impl> p;
};

#endif
