# iPhone Forensics

A read-only, non-destructive iOS media and database forensics tool for Windows and macOS with an embedded local web interface (EN / FI). 

The utility performs logical acquisition over USB or parses unencrypted local iTunes/Finder backups to inventory `Photos.sqlite` records, extract items in the *Recently Deleted* state, carve residual media streams from local caches, and export verifiable artifacts without modifying source media.

---

## Acquisition Sources

- **Direct USB Connection:** Communicates directly with `DCIM` and `PhotoData` via a custom C++ implementation of the Apple USB stack (`usbmuxd`, `lockdownd` over TLS, and `AFC` restricted strictly to read-only opcodes). Requires one-time host pairing (*Trust*) and the Apple Mobile Device Service (via Apple Devices or iTunes on Windows).
- **Local Backup:** Parses completed, unencrypted iOS device backups. Encrypted backups are automatically detected and bypassed; the tool never prompts for or attempts to bypass backup passphrases.

---

## Capabilities

- **Database & File Inventory:** Performs a schema-aware traversal of `Manifest.db`, resolving physical file paths and categorizing artifacts by domain, relative path, and asset class (`media`, `thumbnail`, `container`, `database`).
- **Recently Deleted Extraction:** Queries `ZASSET.ZTRASHEDSTATE` and cross-references `ZTRASHEDDATE` (converting Apple Core Data timestamps to ISO-8601) to correlate database entries with surviving physical files.
- **Cache Carving & WAL Analysis:** Scans `Photos.sqlite` free lists and Write-Ahead Logs (WAL) for deleted record metadata, and carves contiguous `JPEG`, `PNG`, `HEIC`, `MOV`, and `MP4` byte streams from cache containers. Carved artifacts are deduplicated and classified via SHA-256 against existing inventory (`copy-of-existing` vs. `permanently-deleted-candidate`).
- **Deterministic Export:** Exports surviving originals and derivatives with preserved extensions, prefixing trashed assets with `recently-deleted__`. Enforces strict path sanitization against directory traversal, reserved OS filenames, path-length limits, and case collisions.
- **Forensic Integrity:** Sources are opened strictly read-only. All database parsing is executed against hashed working copies, with SHA-256 verification performed prior to, during, and following acquisition.

---

## Architecture

The codebase follows a modular, minimal-dependency C++ design with a strict one-class-per-header/source pair layout. The embedded web interface is served by my custom zero-dependency HTTP engine, [cpp-web-server](https://github.com/dmtr-1337/cpp-web-server).

```text
├── include/ & src/
│   ├── AuditEngine      # Acquisition workflow orchestration, worker threading, JSON serialization
│   ├── Report           # Artifact classification, timestamp normalization, CSV/Markdown reporting
│   ├── Sqlite           # Read-only C++ wrapper around the SQLite C API
│   ├── BackupScanner    # Manifest.db traversal and domain resolution
│   ├── PlistParser      # Binary and XML property list deserialization
│   ├── Carver           # Signature-based media stream carving
│   ├── PathSanitizer    # Cross-platform filesystem path validation
│   └── usb/             # Custom usbmux, TLS channel, and AFC protocol stack
├── web/                 # Embedded frontend assets (HTML/JS/CSS) compiled into the binary
└── lib/
    ├── http-server/     # Custom cpp-web-server (loopback-only HTTP/1.1 server)
    └── sqlite/          # SQLite amalgamation
```

---

## Build & Usage

### Prerequisites
- CMake 3.20+
- C++20 compliant compiler (MSVC on Windows, Apple Clang on macOS)
- OpenSSL (for `lockdownd` TLS pairing over USB)

### Compilation
```bash
cmake -S . -B build
cmake --build build --config Release        # Windows (MSVC)
cmake --build build                         # macOS (Clang)
```

### Execution
```bash
./build/Release/iphone-forensics.exe [port] # Windows
./build/iphone-forensics [port]             # macOS
```
By default, the server binds to `127.0.0.1` on an ephemeral port and launches the default browser. Supply an optional port argument to bind statically. *(Note: On macOS, the host terminal requires **Full Disk Access** to read protected backup directories).*

---

## Output Structure

Artifacts and audit logs are written to `~/iphone_forensics/<YYYY-MM-DD_HH-MM-SS>/`:

- `working/`: SHA-256 verified working copies of `Manifest.db`, `Photos.sqlite`, and WAL/SHM sidecars.
- `exports/`: Extracted media and thumbnails preserving original `domain/relativePath` hierarchy.
- `carved/`: Media streams recovered from cache files, sorted by SHA-256 classification.
- `reports/`: Structured audit logs (`inventory.csv`, `recently_deleted.csv`, `export_manifest.csv`, `deleted_traces.csv`, `carved.csv`, and `summary.md`).

---

## Technical Scope & Limitations

- **Cryptographic Erasure:** Permanently deleted files on modern iOS devices cannot be recovered. iOS enforces per-file hardware-backed encryption and destroys the corresponding file key upon deletion; furthermore, neither AFC nor logical backups expose raw unallocated flash blocks.
- **Derivative Artifacts:** Cached images and thumbnails are low-resolution derivatives generated by the OS. Their presence in cache containers does not independently confirm the deletion state of the original asset.

---

## Security & Operational Guarantees

- **Network Isolation:** Binds exclusively to the loopback interface (`127.0.0.1`) with zero outbound telemetry or external network requests.
- **CSRF & DNS-Rebinding Mitigation:** API endpoints validate the `Host` header against loopback addresses and enforce the presence of a custom `X-Audit` request header.
- **Non-Destructive Execution:** Target devices and backup directories are never written to, renamed, repaired, or altered in file permissions.

---

## License

Licensed under the **GNU General Public License v3.0** (inherited from the bundled [cpp-web-server](https://github.com/dmtr-1337/cpp-web-server) library).