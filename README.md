# Torrent Health Auditor

A lightweight web application that scans your qBittorrent and Deluge clients to identify failed, unregistered, or problematic torrents.

## Features

- **Multi-Client Support** – Connect multiple qBittorrent and Deluge clients simultaneously
- **Smart Classification** – Distinguishes between hard failures (unregistered, deleted, banned) and soft failures (temporary tracker issues)
- **Shared File Detection** – Identifies torrents that share the same files to prevent accidental data loss
- **Bulk Operations** – Delete multiple torrents at once with optional file removal
- **Real-Time Scanning** – Live progress updates as clients are scanned
- **Responsive UI** – Clean, dark-themed interface with filtering and sorting

## Quick Start

### Requirements

- Python 3.7+
- qBittorrent and/or Deluge with Web UI enabled

### Installation

**Windows:**
```powershell
# Clone or download this repository
cd torrent-checker

# Install dependencies
pip install -r requirements.txt

# Run the application
python torrent_check.py
```

**Linux:**
```bash
# Clone or download this repository
cd torrent-checker

# Install dependencies
pip3 install -r requirements.txt

# Run the application
python3 torrent_check.py
```

### Access

Open your browser and navigate to:
```
http://localhost:5000
```

## Usage

1. **Add Clients** – Click "+ Client" and enter your torrent client details
   - qBittorrent: Provide Web UI URL, username, and password
   - Deluge: Provide Web UI URL and password

2. **Scan** – Click "Scan All" to check all configured clients

3. **Review Results** – View failed torrents classified as:
   - **Hard** – Unregistered, deleted, or banned torrents
   - **Soft** – Temporary tracker issues (usually resolve automatically)

4. **Take Action** – Select torrents and delete them (optionally with files)

## Configuration

The application stores client configurations in `settings.json` (created automatically on first run).

Environment variables:
- `TORRENT_UI_PORT` – Server port (default: 5000)
- `TORRENT_UI_SECRET` – Flask secret key (default: dev-secret)

## Tips

- Use "Hide Soft" toggle to focus on torrents that need immediate attention
- Check "Shared ×N" badges before deleting to avoid removing files used by other torrents
- Enable "Compact" mode for a denser view when managing many torrents

---

**Note:** This tool only identifies problems – it does not attempt to fix trackers or re-download torrents.
