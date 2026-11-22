#include "http-server.hpp"
#include <iostream>
#include <sstream>
#include <thread>
#include <algorithm>
#include <cctype>

/* Platform headers */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

WebServer::WebServer(int port, const std::string& host) : port(port), host(host)
{
#ifdef _WIN32
    /* Initialize Winsock */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    server_fd = INVALID_SOCKET;
#else
    server_fd = -1;
#endif
}

WebServer::~WebServer()
{
#ifdef _WIN32
    /* Close listener and cleanup Winsock */
    if (server_fd != INVALID_SOCKET) closesocket(server_fd);
    WSACleanup();
#else
    if (server_fd >= 0) close(server_fd);
#endif
}

void WebServer::get(const std::string& path, handlertype handler, const std::string& type)
{
    /* Register route handler with its content type */
    routes[path] = std::make_pair(type, handler);
}

bool WebServer::runserver(std::function<void(int)> ready)
{
    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
#ifdef _WIN32
    if (server_fd == INVALID_SOCKET) return false;

    /* Exclusive bind, SO_REUSEADDR on Windows would allow port hijacking */
    setsockopt(server_fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&opt, sizeof(opt));
#else
    if (server_fd < 0) return false;

    /* Allow port reuse */
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#endif

    /* Bind to host:port */
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) return false;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) return false;
    if (listen(server_fd, 16) < 0) return false;

    /* Resolve actual port when 0 was requested */
    socklen_t len = sizeof(addr);
    getsockname(server_fd, (struct sockaddr*)&addr, &len);
    port = ntohs(addr.sin_port);

    std::cout << "Listening on " << host << ":" << port << "...\n";
    if (ready) ready(port);

    /* Accept incoming connections, one thread each so idle sockets cannot block */
    while (true)
    {
        sockettype client = accept(server_fd, nullptr, nullptr);

#ifdef _WIN32
        if (client != INVALID_SOCKET) std::thread(&WebServer::handle_request, this, client).detach();
#else
        if (client >= 0) std::thread(&WebServer::handle_request, this, client).detach();
#endif
    }
}

void WebServer::handle_request(sockettype client)
{
    /* Receive timeout for idle/preconnected sockets */
#ifdef _WIN32
    DWORD tv = 5000;
#else
    struct timeval tv = { 5, 0 };
#endif
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    /* Read request head */
    std::string raw;
    char buf[4096];
    while (raw.find("\r\n\r\n") == std::string::npos && raw.size() < 65536)
    {
        int n = (int)recv(client, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, n);
    }

    /* Parse request line */
    std::istringstream in(raw);
    std::string line, method, target, ver;
    std::getline(in, line);
    std::istringstream(line) >> method >> target >> ver;

    Request req;
    size_t q = target.find('?');
    req.path = target.substr(0, q);
    if (q != std::string::npos) req.query = target.substr(q + 1);

    /* Parse headers, keys lowercased */
    while (std::getline(in, line) && line != "\r")
    {
        size_t c = line.find(':');
        if (c == std::string::npos) continue;
        std::string k = line.substr(0, c), v = line.substr(c + 1);
        std::transform(k.begin(), k.end(), k.begin(), [](unsigned char ch) { return (char)std::tolower(ch); });
        v.erase(0, v.find_first_not_of(' '));
        if (!v.empty() && v.back() == '\r') v.pop_back();
        req.headers[k] = v;
    }

    /* Default to 404 */
    std::string body = "<h1>404 Not Found</h1>", type = "text/html";
    std::string status = "HTTP/1.1 404 Not Found\r\n";
    std::string p = std::to_string(port);
    auto route = routes.find(req.path);

    /* Loopback binding: reject foreign Host headers (DNS rebinding) */
    if (host == "127.0.0.1" && req.headers["host"] != host + ":" + p && req.headers["host"] != "localhost:" + p)
    {
        body = "<h1>403 Forbidden</h1>";
        status = "HTTP/1.1 403 Forbidden\r\n";
    }
    else if (method == "GET" && route != routes.end())
    {
        /* Execute route */
        try
        {
            body = route->second.second(req);
            type = route->second.first;
            status = "HTTP/1.1 200 OK\r\n";
        }
        catch (const std::exception& e)
        {
            body = e.what();
            type = "text/plain";
            status = "HTTP/1.1 500 Internal Server Error\r\n";
        }
    }

    /* Build and send response */
    std::string res = status +
        "Content-Type: " + type + "; charset=utf-8\r\n"
        "Content-Length: " + std::to_string(body.length()) + "\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n\r\n" + body;

    for (size_t off = 0; off < res.length();)
    {
        int n = (int)send(client, res.c_str() + off, (int)(res.length() - off), 0);
        if (n <= 0) break;
        off += n;
    }

    /* Close connection */
#ifdef _WIN32
    closesocket(client);
#else
    close(client);
#endif
}
