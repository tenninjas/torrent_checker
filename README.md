# Torrent Checker

A lightweight **Flask web app** to scan your torrent clients (qBittorrent or Deluge) for **unregistered / failed torrents** and optionally delete them (with or without data).

---

## 🚀 Features
- Works with **qBittorrent** and **Deluge Web**
- Sortable + filterable list view
- Batch select & delete (with optional data removal)
- Add clients via UI or config file
- No database — simple `settings.json`

---

## 🧩 Requirements
- Python **3.9+**
- Access to qBittorrent/Deluge Web UI
- Flask & requests (auto-installed)

---

## ⚙️ Install & Run

### Windows 11 (PowerShell)
```powershell
git clone https://github.com/<you>/<repo>.git
cd <repo>
py -3 -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python torrent_check.py
```

### Linux
```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python torrent_check.py
```

Then open **http://localhost:5000**

---

## ⚙️ Configuration
A `settings.json` file is created on first run.

Example:
```json
{
  "clients": [
    {
      "id": "qbit-main",
      "type": "qbittorrent",
      "base_url": "http://192.168.1.10:8080",
      "username": "admin",
      "password": "pass"
    },
    {
      "id": "deluge-nas",
      "type": "deluge",
      "base_url": "http://192.168.1.20:8112",
      "password": "deluge"
    }
  ]
}
```
---

## 🧠 Usage
1. Start the app → open browser  
2. Add clients via **+ Client**  
3. Click **Scan**  
4. Filter, sort, and select torrents  
5. Click **Delete** → confirm  
   - Toggle **Also delete files** if desired

---

## 📜 License
MIT License

---

### ❤️ Credits
Built for home-lab torrent cleanup — supports qBittorrent & Deluge.
