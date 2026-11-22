#include "http-server.hpp"
#include "audit-engine.hpp"
#include "path-sanitizer.hpp"
#include "web-assets.hpp"
#include <iostream>
#include <csignal>
#include <cstdlib>

template <size_t N> static std::string asset(const unsigned char (&data)[N])
{
    return std::string((const char*)data, N);
}

int main(int argc, char** argv)
{
#ifndef _WIN32
    /* Closed browser sockets must not kill the process */
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Optional port argument, default ephemeral */
    WebServer server(argc > 1 ? std::atoi(argv[1]) : 0);
    AuditEngine engine;

    /* Embedded UI */
    server.get("/", [](const Request&) { return asset(index_html); });
    server.get("/app.js", [](const Request&) { return asset(app_js); }, "text/javascript");
    server.get("/style.css", [](const Request&) { return asset(style_css); }, "text/css");

    /* API routes require the X-Audit header: cross-site pages cannot send it without a CORS preflight, which is never answered */
    auto api = [&](const std::string& path, handlertype fn)
    {
        server.get(path, [fn](const Request& r) -> std::string
        {
            if (!r.headers.count("x-audit")) return "{\"error\":\"missing X-Audit header\"}";
            return fn(r);
        }, "application/json");
    };

    api("/api/env", [](const Request&)
    {
        std::vector<std::string> roots;
        for (const auto& r : default_backup_roots())
        {
            std::error_code ec;
            roots.push_back(json_obj({ { "path", json(to_utf8(r)) }, { "exists", jbool(fs::exists(r, ec)) } }));
        }
#ifdef _WIN32
        const char* os = "windows";
#else
        const char* os = "macos";
#endif
        fs::path base = home_dir() / "iphone_forensics";
        return json_obj({ { "os", json(os) }, { "roots", json_arr(roots) }, { "workspaceBase", json(to_utf8(base)) }, { "cloud", json(cloud_provider(base)) } });
    });

    api("/api/scan", [](const Request& r)
    {
        std::string custom = query_param(r.query, "path");
        std::vector<fs::path> roots = custom.empty() ? default_backup_roots() : std::vector<fs::path>{ to_path(custom) };
        std::vector<std::string> backups, errors;
        for (const auto& root : roots)
        {
            std::error_code ec;
            if (!fs::exists(root, ec))
            {
                if (!custom.empty()) errors.push_back(json("folder not found: " + custom));
                continue;
            }
            std::string err;
            for (const auto& b : scan_backups(root, err)) backups.push_back(b.to_json());
            if (!err.empty()) errors.push_back(json(err));
        }
        return json_obj({ { "backups", json_arr(backups) }, { "errors", json_arr(errors) } });
    });

    api("/api/devices", [](const Request&)
    {
        std::string err;
        std::vector<std::string> list;
        for (const auto& d : list_devices(err)) list.push_back(d.to_json());
        return json_obj({ { "devices", json_arr(list) }, { "error", json(err) } });
    });

    api("/api/start", [&](const Request& r)
    {
        /* Either a connected iPhone (device=<udid>) or a backup folder (backup=<path>) */
        std::string base = query_param(r.query, "base"), device = query_param(r.query, "device");
        fs::path b = base.empty() ? home_dir() / "iphone_forensics" : to_path(base);
        std::string err = device.empty() ? engine.start(to_path(query_param(r.query, "backup")), b) : engine.start_device(device, b);
        return err.empty() ? std::string("{\"ok\":true}") : "{\"error\":" + json(err) + "}";
    });

    api("/api/export", [&](const Request&)
    {
        std::string err = engine.start_export();
        return err.empty() ? std::string("{\"ok\":true}") : "{\"error\":" + json(err) + "}";
    });

    api("/api/carve", [&](const Request&)
    {
        std::string err = engine.start_carve();
        return err.empty() ? std::string("{\"ok\":true}") : "{\"error\":" + json(err) + "}";
    });

    api("/api/status", [&](const Request& r)
    {
        std::string have = query_param(r.query, "have");
        return engine.status(have.empty() ? -1 : std::atoi(have.c_str()));
    });

    api("/api/open", [&](const Request& r)
    {
        /* Only the two workspace folders can be opened */
        std::string what = query_param(r.query, "what");
        if (what != "reports" && what != "exports") return std::string("{\"error\":\"unknown folder\"}");
        fs::path p = engine.folder(what);
        if (p.empty()) return std::string("{\"error\":\"no audit workspace yet\"}");
        open_native(to_utf8(p));
        return std::string("{\"ok\":true}");
    });

    /* Open the browser once listening */
    bool ok = server.runserver([](int port)
    {
        std::string url = "http://127.0.0.1:" + std::to_string(port) + "/";
        std::cout << "iPhone Forensics UI: " << url << "\n";
        open_native(url);
    });

    if (!ok) std::cerr << "Could not start the local web server\n";
    return ok ? 0 : 1;
}
