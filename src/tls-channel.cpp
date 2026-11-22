#include "tls-channel.hpp"
#include "util.hpp"
#include <stdexcept>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace
{
    const size_t npos = std::string::npos;

    [[noreturn]] void fail(const std::string& msg) { throw std::runtime_error("TLS: " + msg); }

    /* PEM body to DER */
    std::string pem_der(const std::string& pem, bool& pkcs8)
    {
        size_t b = pem.find("-----BEGIN "), e = pem.find("-----END ");
        if (b == npos || e == npos || e < b) fail("invalid PEM in pair record");
        pkcs8 = pem.compare(b, 27, "-----BEGIN PRIVATE KEY-----") == 0;
        size_t body = pem.find('\n', b);
        if (body == npos || body > e) fail("invalid PEM in pair record");
        return base64_decode(pem.substr(body, e - body));
    }

    /* DER TLV at pos: returns content offset and sets len */
    size_t der(const std::string& d, size_t pos, size_t& len)
    {
        if (pos + 2 > d.size()) fail("truncated key");
        size_t l = uint8_t(d[pos + 1]), c = pos + 2;
        if (l & 0x80)
        {
            size_t n = l & 0x7F;
            if (n > 4 || c + n > d.size()) fail("bad key length");
            for (l = 0; n--;) l = l << 8 | uint8_t(d[c++]);
        }
        if (l > d.size() - c) fail("bad key length");
        len = l;
        return c;
    }

    /* RSA key as PKCS#1 DER, unwrapping PKCS#8 PrivateKeyInfo {version, algorithm, OCTET STRING} */
    std::string rsa_key(const std::string& pem)
    {
        bool pkcs8;
        std::string d = pem_der(pem, pkcs8);
        if (!pkcs8) return d;
        size_t len, c = der(d, 0, len);
        c = der(d, c, len) + len;
        c = der(d, c, len) + len;
        c = der(d, c, len);
        return d.substr(c, len);
    }

    std::string der_wrap(char tag, const std::string& body)
    {
        std::string o(1, tag), l;
        for (size_t n = body.size(); n; n >>= 8) l.insert(l.begin(), char(n & 0xFF));
        if (body.size() < 128) o += char(body.size());
        else o += char(0x80 | l.size()) + l;
        return o + body;
    }

    /* PKCS#8 PrivateKeyInfo {0, rsaEncryption, OCTET STRING pkcs1} */
    [[maybe_unused]] std::string pkcs8(const std::string& pkcs1)
    {
        static const char alg[] = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
        return der_wrap(0x30, std::string("\x02\x01\x00", 3) + std::string(alg, 15) + der_wrap(0x04, pkcs1));
    }
}

#ifdef _WIN32
#define SECURITY_WIN32
#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#include <schannel.h>
#include <security.h>

struct TlsChannel::Impl
{
    Socket& sock;
    CredHandle cred = {};
    CtxtHandle ctx = {};
    bool cred_ok = false, ctx_ok = false;
    PCCERT_CONTEXT cert = nullptr;
    SecPkgContext_StreamSizes sizes = {};
    std::string in, plain;  /* encrypted input not yet decrypted, decrypted not yet read */

    explicit Impl(Socket& s) : sock(s) {}
    ~Impl()
    {
        if (ctx_ok) DeleteSecurityContext(&ctx);
        if (cred_ok) FreeCredentialsHandle(&cred);
        if (cert) CertFreeCertificateContext(cert);
    }

    void recv_more()
    {
        char buf[16384];
        in.append(buf, sock.read_some(buf, sizeof(buf)));
    }
};

static void check(SECURITY_STATUS st, const char* what)
{
    if (st == SEC_E_OK) return;
    char b[96];
    snprintf(b, sizeof(b), "%s failed (0x%08lx)", what, (unsigned long)st);
    fail(b);
}

TlsChannel::TlsChannel(Socket& sock, const std::string& cert_pem, const std::string& key_pem) : p(std::make_unique<Impl>(sock))
{
    /* Host certificate */
    bool unused;
    std::string cert = pem_der(cert_pem, unused), key = rsa_key(key_pem);
    p->cert = CertCreateCertificateContext(X509_ASN_ENCODING, (const BYTE*)cert.data(), (DWORD)cert.size());
    if (!p->cert) fail("invalid host certificate");

    /* Schannel cannot use ephemeral keys: the key is persisted under a random name only for the handshake (named import needs PKCS#8) */
    std::string blob = pkcs8(key);
    struct Key
    {
        NCRYPT_PROV_HANDLE prov = 0;
        NCRYPT_KEY_HANDLE handle = 0;
        ~Key()
        {
            if (handle) NCryptDeleteKey(handle, 0);
            if (prov) NCryptFreeObject(prov);
        }
    } k;
    std::wstring name = L"iphone-forensics-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    NCryptBuffer nb = { ULONG((name.size() + 1) * sizeof(wchar_t)), NCRYPTBUFFER_PKCS_KEY_NAME, (PVOID)name.c_str() };
    NCryptBufferDesc nd = { NCRYPTBUFFER_VERSION, 1, &nb };
    SECURITY_STATUS st = NCryptOpenStorageProvider(&k.prov, MS_KEY_STORAGE_PROVIDER, 0);
    if (st == ERROR_SUCCESS) st = NCryptImportKey(k.prov, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &nd, &k.handle, (PBYTE)blob.data(), (DWORD)blob.size(), NCRYPT_OVERWRITE_KEY_FLAG);
    check(st, "NCryptImportKey");

    CRYPT_KEY_PROV_INFO info = {};
    info.pwszContainerName = (LPWSTR)name.c_str();
    info.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
    if (!CertSetCertificateContextProperty(p->cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &info)) fail("cannot attach host key");

    /* Device certificate is self-signed by the device, validation is manual (skipped) */
    SCHANNEL_CRED sc = {};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1;
    sc.paCred = &p->cert;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS;
    check(AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr, &p->cred, nullptr), "AcquireCredentialsHandle");
    p->cred_ok = true;

    /* Handshake */
    const DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM | ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_MANUAL_CRED_VALIDATION;
    DWORD attr = 0;
    bool first = true;
    st = SEC_I_CONTINUE_NEEDED;
    while (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_INCOMPLETE_MESSAGE)
    {
        if (!first && (p->in.empty() || st == SEC_E_INCOMPLETE_MESSAGE)) p->recv_more();
        SecBuffer ib[2] = { { ULONG(p->in.size()), SECBUFFER_TOKEN, p->in.data() }, { 0, SECBUFFER_EMPTY, nullptr } };
        SecBufferDesc id = { SECBUFFER_VERSION, 2, ib };
        SecBuffer ob = { 0, SECBUFFER_TOKEN, nullptr };
        SecBufferDesc od = { SECBUFFER_VERSION, 1, &ob };
        st = InitializeSecurityContextW(&p->cred, first ? nullptr : &p->ctx, nullptr, flags, 0, 0, first ? nullptr : &id, 0, first ? &p->ctx : nullptr, &od, &attr, nullptr);
        if (first && !FAILED(st)) p->ctx_ok = true;
        first = false;

        if (ob.pvBuffer)
        {
            if (ob.cbBuffer) p->sock.write(std::string((const char*)ob.pvBuffer, ob.cbBuffer));
            FreeContextBuffer(ob.pvBuffer);
        }
        if (st == SEC_E_INCOMPLETE_MESSAGE) continue;
        if (FAILED(st)) check(st, "TLS handshake");
        p->in = ib[1].BufferType == SECBUFFER_EXTRA ? p->in.substr(p->in.size() - ib[1].cbBuffer) : "";
    }
    check(st, "TLS handshake");
    check(QueryContextAttributesW(&p->ctx, SECPKG_ATTR_STREAM_SIZES, &p->sizes), "QueryContextAttributes");
}

void TlsChannel::write(const std::string& data)
{
    const SecPkgContext_StreamSizes& z = p->sizes;
    for (size_t off = 0; off < data.size();)
    {
        size_t n = std::min<size_t>(data.size() - off, z.cbMaximumMessage);
        std::string buf(z.cbHeader + n + z.cbTrailer, '\0');
        memcpy(&buf[z.cbHeader], data.data() + off, n);
        SecBuffer b[4] = { { z.cbHeader, SECBUFFER_STREAM_HEADER, &buf[0] }, { ULONG(n), SECBUFFER_DATA, &buf[z.cbHeader] },
            { z.cbTrailer, SECBUFFER_STREAM_TRAILER, &buf[z.cbHeader + n] }, { 0, SECBUFFER_EMPTY, nullptr } };
        SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
        check(EncryptMessage(&p->ctx, 0, &d, 0), "EncryptMessage");
        p->sock.write(buf.substr(0, b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer));
        off += n;
    }
}

void TlsChannel::read(char* out, size_t n)
{
    while (p->plain.size() < n)
    {
        if (!p->in.empty())
        {
            SecBuffer b[4] = { { ULONG(p->in.size()), SECBUFFER_DATA, p->in.data() }, { 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr } };
            SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
            SECURITY_STATUS st = DecryptMessage(&p->ctx, &d, 0, nullptr);
            if (st == SEC_E_OK)
            {
                /* Decrypted in place: copy data, keep trailing record bytes */
                std::string extra;
                for (const auto& x : b)
                {
                    if (x.BufferType == SECBUFFER_DATA) p->plain.append((const char*)x.pvBuffer, x.cbBuffer);
                    if (x.BufferType == SECBUFFER_EXTRA) extra.assign((const char*)x.pvBuffer, x.cbBuffer);
                }
                p->in = extra;
                continue;
            }
            if (st == SEC_I_CONTEXT_EXPIRED) fail("device closed the session");
            if (st != SEC_E_INCOMPLETE_MESSAGE) check(st, "DecryptMessage");
        }
        p->recv_more();
    }
    memcpy(out, p->plain.data(), n);
    p->plain.erase(0, n);
}

#else
#include <Security/Security.h>
#include <Security/SecureTransport.h>

/* Exported by Security.framework, not declared in public headers */
extern "C" SecIdentityRef SecIdentityCreate(CFAllocatorRef allocator, SecCertificateRef certificate, SecKeyRef privateKey);

struct TlsChannel::Impl
{
    Socket& sock;
    SSLContextRef ctx = nullptr;

    explicit Impl(Socket& s) : sock(s) {}
    ~Impl()
    {
        if (!ctx) return;
        SSLClose(ctx);
        CFRelease(ctx);
    }

    static OSStatus on_read(SSLConnectionRef c, void* data, size_t* len)
    {
        try { ((Impl*)c)->sock.read((char*)data, *len); return noErr; }
        catch (const std::exception&) { *len = 0; return errSSLClosedAbort; }
    }

    static OSStatus on_write(SSLConnectionRef c, const void* data, size_t* len)
    {
        try { ((Impl*)c)->sock.write(std::string((const char*)data, *len)); return noErr; }
        catch (const std::exception&) { *len = 0; return errSSLClosedAbort; }
    }
};

TlsChannel::TlsChannel(Socket& sock, const std::string& cert_pem, const std::string& key_pem) : p(std::make_unique<Impl>(sock))
{
    bool unused;
    std::string cert = pem_der(cert_pem, unused), key = rsa_key(key_pem);
    CFDataRef cd = CFDataCreate(nullptr, (const UInt8*)cert.data(), cert.size());
    CFDataRef kd = CFDataCreate(nullptr, (const UInt8*)key.data(), key.size());
    const void* keys[] = { kSecAttrKeyType, kSecAttrKeyClass };
    const void* vals[] = { kSecAttrKeyTypeRSA, kSecAttrKeyClassPrivate };
    CFDictionaryRef attrs = CFDictionaryCreate(nullptr, keys, vals, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    SecCertificateRef c = SecCertificateCreateWithData(nullptr, cd);
    SecKeyRef k = SecKeyCreateWithData(kd, attrs, nullptr);
    SecIdentityRef id = c && k ? SecIdentityCreate(nullptr, c, k) : nullptr;
    for (CFTypeRef r : { (CFTypeRef)cd, (CFTypeRef)kd, (CFTypeRef)attrs, (CFTypeRef)c, (CFTypeRef)k })
        if (r) CFRelease(r);
    if (!id) fail("cannot load host certificate/key from pair record");
    CFArrayRef certs = CFArrayCreate(nullptr, (const void**)&id, 1, &kCFTypeArrayCallBacks);
    CFRelease(id);

    /* Device certificate is self-signed by the device, server auth is skipped */
    p->ctx = SSLCreateContext(nullptr, kSSLClientSide, kSSLStreamType);
    SSLSetIOFuncs(p->ctx, Impl::on_read, Impl::on_write);
    SSLSetConnection(p->ctx, p.get());
    SSLSetProtocolVersionMin(p->ctx, kTLSProtocol1);
    SSLSetSessionOption(p->ctx, kSSLSessionOptionBreakOnServerAuth, true);
    SSLSetCertificate(p->ctx, certs);
    CFRelease(certs);

    OSStatus st;
    while ((st = SSLHandshake(p->ctx)) == errSSLServerAuthCompleted || st == errSSLWouldBlock);
    if (st != noErr) fail("handshake failed (" + std::to_string(st) + ")");
}

void TlsChannel::write(const std::string& data)
{
    for (size_t off = 0; off < data.size();)
    {
        size_t n = 0;
        if (SSLWrite(p->ctx, data.data() + off, data.size() - off, &n) != noErr && n == 0) fail("write failed");
        off += n;
    }
}

void TlsChannel::read(char* out, size_t n)
{
    for (size_t off = 0; off < n;)
    {
        size_t got = 0;
        if (SSLRead(p->ctx, out + off, n - off, &got) != noErr && got == 0) fail("read failed");
        off += got;
    }
}
#endif

TlsChannel::~TlsChannel() = default;
