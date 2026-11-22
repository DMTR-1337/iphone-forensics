#include "audit-engine.hpp"
#include "audit-report.hpp"
#include "path-sanitizer.hpp"
#include <iostream>
#include <cstdio>
#include <ctime>

/* Lifecycle, threading and JSON. The analysis, export and report steps live in audit-report.cpp. */

AuditEngine::~AuditEngine()
{
    if (worker.joinable()) worker.join();
}

std::string AuditEngine::start(const fs::path& dir, const fs::path& base)
{
    /* Re-validate server side, the UI selection is not trusted */
    BackupInfo b = inspect_backup(dir);
    if (b.encrypted) return "encrypted";
    if (!b.usable) return "backup not usable: " + b.problem;
    if (is_inside(base, dir)) return "the workspace must not be inside the backup folder";

    std::lock_guard<std::mutex> lock(mu);
    return begin(b, "", base);
}

std::string AuditEngine::start_device(const std::string& udid, const fs::path& base)
{
    if (udid.empty()) return "no device selected";
    BackupInfo b;
    b.path = to_path("usb:" + udid);
    b.snapshot = "live device";
    b.last_backup = iso_utc(double(std::time(nullptr)));

    std::lock_guard<std::mutex> lock(mu);
    return begin(b, udid, base);
}

/* Caller holds mu */
std::string AuditEngine::begin(const BackupInfo& b, const std::string& udid, const fs::path& base)
{
    if (running) return "a job is already running";
    std::string cloud = cloud_provider(base);
    if (!cloud.empty()) return "cloud:" + cloud;

    fs::path ws = base / timestamp();
    std::error_code ec;
    if (fs::exists(ws, ec)) return "workspace already exists, try again in a second";
    for (const char* d : { "working", "exports", "reports" })
    {
        fs::create_directories(ws / d, ec);
        if (ec) return "cannot create workspace: " + ec.message();
    }

    a = Audit();
    a.backup = b;
    a.udid = udid;
    a.ws = ws;
    launch(&AuditEngine::analyze);
    return "";
}

std::string AuditEngine::start_export()
{
    std::lock_guard<std::mutex> lock(mu);
    if (running) return "a job is already running";
    if (!a.analyzed) return "run a successful analysis first";
    if (a.exported) return "already exported to this workspace; start a new audit to export again";
    launch(&AuditEngine::export_files);
    return "";
}

std::string AuditEngine::start_carve()
{
    std::lock_guard<std::mutex> lock(mu);
    if (running) return "a job is already running";
    if (!a.analyzed) return "run a successful analysis first";
    if (a.carved) return "remnant search already done for this workspace";
    launch(&AuditEngine::carve);
    return "";
}

std::string AuditEngine::status(int have) const
{
    Report r;
    std::lock_guard<std::mutex> lock(mu);
    char p[16];
    snprintf(p, sizeof p, "%.3f", progress);
    return json_obj({
        { "running", jbool(running) }, { "phase", json(phase) }, { "progress", p }, { "error", json(error) },
        { "log", r.arr(log) }, { "version", std::to_string(version) },
        { "result", have == version || result.empty() ? "null" : result } });
}

fs::path AuditEngine::folder(const std::string& name) const
{
    std::lock_guard<std::mutex> lock(mu);
    return a.ws.empty() ? fs::path() : a.ws / name;
}

/* Caller holds mu */
void AuditEngine::launch(void (AuditEngine::*job)())
{
    if (worker.joinable()) worker.join();
    running = true;
    error.clear();
    log.clear();
    worker = std::thread(&AuditEngine::run, this, job);
}

void AuditEngine::run(void (AuditEngine::*job)())
{
    std::string err;
    try
    {
        (this->*job)();
        verify_sources();
        set("Done", 1);
    }
    catch (const std::exception& e)
    {
        err = e.what();
    }

    try { write_summary(); }
    catch (const std::exception&) {}

    std::string r = build_result();
    std::lock_guard<std::mutex> lock(mu);
    if (!err.empty()) phase = "Stopped";
    error = err;
    result = r;
    version++;
    running = false;
}

void AuditEngine::set(const std::string& p, double f)
{
    std::lock_guard<std::mutex> lock(mu);

    /* Console gets phase names only (no counters, paths or identifiers) */
    std::string name = p.substr(0, p.find(" ("));
    if (name != phase.substr(0, phase.find(" ("))) std::cout << "[audit] " << name << std::endl;
    phase = p;
    progress = f;
}

void AuditEngine::note(const std::string& line)
{
    std::lock_guard<std::mutex> lock(mu);
    log.push_back(line);
}

Reader AuditEngine::reader_for(const std::string& physical)
{
    if (!physical.starts_with("afc:")) return file_reader(to_path(physical));
    if (!a.afc) throw std::runtime_error("no iPhone session");
    return a.afc->reader(physical.substr(4));
}

void AuditEngine::copy_source(const std::string& src, const std::string& name)
{
    /* A live device can write between reads: retry until the pre-hash and the copy agree */
    fs::path dst = a.ws / "working" / to_path(name);
    for (int attempt = 1;; attempt++)
    {
        HashRecord h{ name, src };
        h.before = sha256(reader_for(src));
        uint64_t n = 0;
        fs::remove(dst);
        h.copy = copy_hashed(reader_for(src), dst, n);
        if (h.copy == h.before)
        {
            a.hashes.push_back(h);
            note("copied " + name + " (" + std::to_string(n) + " bytes), SHA-256 matches source");
            return;
        }
        if (attempt == 3) throw std::runtime_error(name + " kept changing while copying - close the Photos app or wait for the backup to finish");
        note(name + " changed during copy, retrying");
    }
}

void AuditEngine::verify_sources()
{
    set("Re-verifying source hashes", 0.98);
    for (auto& h : a.hashes)
    {
        h.after = sha256(reader_for(h.source));
        note(h.label + ": source " + (h.after == h.before ? "unchanged" : a.udid.empty() ? "CHANGED" : "changed on the live device"));
    }
}

std::string AuditEngine::build_result() const
{
    Report r;
    auto num = [](uint64_t v) { return std::to_string(v); };

    /* Breakdown map -> array of {name, count, bytes} */
    auto bd = [&](const Breakdown& b)
    {
        std::vector<std::string> o;
        for (const auto& [k, v] : b) o.push_back(json_obj({ { "name", json(k) }, { "count", num(v.first) }, { "bytes", num(v.second) } }));
        return json_arr(o);
    };

    std::vector<std::string> hashes, trash, ranges, rows;
    for (const auto& h : a.hashes)
        hashes.push_back(json_obj({ { "label", json(h.label) }, { "before", json(h.before) }, { "copy", json(h.copy) }, { "after", json(h.after) } }));
    for (const auto& x : a.trash)
        trash.push_back(json_obj({ { "value", json(x.value) }, { "count", num(x.count) }, { "dated", num(x.dated) }, { "meaning", json(r.meaning(x.value)) } }));
    for (const auto& range : a.ranges) ranges.push_back(r.arr(range));
    for (const auto& row : a.deleted) rows.push_back(r.arr(row));

    return json_obj({
        { "backup", a.backup.to_json() }, { "live", jbool(!a.udid.empty()) }, { "workspace", json(to_utf8(a.ws)) }, { "hashes", json_arr(hashes) },
        { "total", num(a.inventory.size()) }, { "byExists", bd(a.by_exists) }, { "byCategory", bd(a.by_category) }, { "byDomain", bd(a.by_domain) }, { "byFolder", bd(a.by_folder) },
        { "photos", json_obj({ { "status", json(a.photos_status) }, { "table", json(a.asset_table) }, { "trash", json_arr(trash) },
            { "ranges", json_arr(ranges) }, { "head", r.arr(a.deleted_head) }, { "rows", json_arr(rows) }, { "byMatch", bd(a.by_match) } }) },
        { "export", json_obj({ { "analyzed", jbool(a.analyzed) }, { "done", jbool(a.exported) },
            { "need", num(a.need) }, { "space", num(a.space) }, { "byStatus", bd(a.by_export) } }) },
        { "carve", json_obj({ { "done", jbool(a.carved) }, { "traces", num(a.traces) }, { "byType", bd(a.by_carve) } }) } });
}
