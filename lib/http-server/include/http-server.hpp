#ifndef WEBSERVER_HPP
#define WEBSERVER_HPP

#include <string>
#include <map>
#include <functional>

/* Cross platform socket type */
#ifdef _WIN32
#include <winsock2.h>
typedef SOCKET sockettype;
#else
typedef int sockettype;
#endif

/* Parsed request passed to handlers */
struct Request
{
    std::string path;
    std::string query;
    std::map<std::string, std::string> headers;
};

typedef std::function<std::string(const Request&)> handlertype;

class WebServer
{
public:
    /* Constructor, port 0 = ephemeral */
    WebServer(int port, const std::string& host = "127.0.0.1");

    /* Socket cleanup destructor */
    ~WebServer();

    /* Register a route */
    void get(const std::string& path, handlertype handler, const std::string& type = "text/html");

    /* Start main server loop, ready is called with the bound port; false on bind failure */
    bool runserver(std::function<void(int)> ready = nullptr);

private:
    int port;
    std::string host;
    sockettype server_fd;
    std::map<std::string, std::pair<std::string, handlertype>> routes;

    /* Handle individual requests */
    void handle_request(sockettype client);
};

#endif
