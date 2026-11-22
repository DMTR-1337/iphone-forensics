#ifndef BACKUPSCANNER_HPP
#define BACKUPSCANNER_HPP

#include "util.hpp"

/* Metadata and validation state of one backup folder */
struct BackupInfo
{
    fs::path path;
    std::string device, ios, product, last_backup, snapshot;
    bool encrypted = false;
    bool usable = false;  /* complete, parseable, unencrypted, idle */
    std::string problem;  /* why not usable */

    std::string to_json() const;
};

/* Default MobileSync backup roots for this OS */
std::vector<fs::path> default_backup_roots();

/* Inspect a single backup folder */
BackupInfo inspect_backup(const fs::path& dir);

/* Inspect dir if it is a backup, else its child backup folders; error set if unreadable */
std::vector<BackupInfo> scan_backups(const fs::path& dir, std::string& error);

#endif
