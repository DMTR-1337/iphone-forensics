#ifndef AUDITENGINE_HPP
#define AUDITENGINE_HPP

#include "backup-scanner.hpp"
#include "device.hpp"
#include <map>
#include <set>
#include <mutex>
#include <thread>

/* One photo-related file record, from Manifest.db or an AFC listing */
struct InventoryEntry
{
    std::string file_id, domain, relative, type, category, exists;
    fs::path physical;  /* backup file, or "afc:<device path>" */
    uint64_t size = 0;
};

/* Integrity record for a copied source database file */
struct HashRecord
{
    std::string label, source;
    std::string before, copy, after;
};

/* Runs the audit workflow on a background thread */
class AuditEngine
{
public:
    ~AuditEngine();

    /* Validate inputs, create workspace, start analysis; returns error text or empty */
    std::string start(const fs::path& backup_dir, const fs::path& base);
    std::string start_device(const std::string& udid, const fs::path& base);

    /* Start export of inventoried files; returns error text or empty */
    std::string start_export();

    /* Start the remnant search (database free space, images embedded in caches) */
    std::string start_carve();

    /* Progress, log and (if newer than have) results as JSON */
    std::string status(int have) const;

    /* Workspace subfolder, empty before the first audit */
    fs::path folder(const std::string& name) const;

private:
    /* name → {count, bytes} */
    typedef std::map<std::string, std::pair<uint64_t, uint64_t>> Breakdown;
    struct Trash { std::string value; int64_t count, dated; };

    /* Everything produced by one audit, reset on start */
    struct Audit
    {
        BackupInfo backup;
        std::string udid;  /* set in device mode */
        std::unique_ptr<AfcSession> afc;
        fs::path ws;
        std::vector<InventoryEntry> inventory;
        std::vector<HashRecord> hashes;
        Breakdown by_domain, by_folder, by_category, by_exists, by_match, by_export, by_carve;
        std::vector<Trash> trash;
        std::vector<std::vector<std::string>> ranges, deleted;
        std::vector<std::string> deleted_head;
        std::set<std::string> trashed_ids;  /* fileIDs of ZTRASHEDSTATE = 1 assets present in the backup */
        std::string photos_status = "not analyzed", asset_table, photos_db;
        uint64_t need = 0, space = 0, traces = 0;
        bool analyzed = false, exported = false, carved = false;
    } a;

    mutable std::mutex mu;
    std::thread worker;
    bool running = false;
    double progress = 0;
    int version = 0;
    std::string phase, error, result;
    std::vector<std::string> log;

    std::string begin(const BackupInfo& b, const std::string& udid, const fs::path& base);
    void launch(void (AuditEngine::*job)());
    void run(void (AuditEngine::*job)());
    void analyze();
    void inventory_backup();
    void inventory_device();
    void analyze_photos();
    void export_files();
    void carve();
    Reader reader_for(const std::string& physical);
    void copy_source(const std::string& src, const std::string& name);
    void verify_sources();
    void write_summary() const;
    std::string build_result() const;
    void set(const std::string& phase, double progress);
    void note(const std::string& line);
};

#endif
