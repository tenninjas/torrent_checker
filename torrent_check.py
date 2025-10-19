#!/usr/bin/env python3

import os
import json
import re
import queue
import logging
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple, Set
from urllib.parse import urlparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

import requests
from flask import Flask, request, redirect, url_for, render_template, jsonify

APP_TITLE = "Torrent Checker"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(APP_DIR)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("TORRENT_UI_SECRET", "dev-secret")

SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "settings.json")
DEFAULT_SETTINGS = {"clients": []}
LOG_FILE = os.path.join(os.path.dirname(__file__), "scan_debug.log")

# ---------- Logging Setup ----------

def setup_scan_logging():
    """Setup logging to both console and file. Clear log file on each scan."""
    # Remove old log file if it exists
    if os.path.exists(LOG_FILE):
        try:
            os.remove(LOG_FILE)
        except Exception as e:
            print(f"Warning: Could not delete old log file: {e}")
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, mode='w', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# Global logger (will be initialized on scan)
logger = None

def log(msg):
    """Log message to both console and file."""
    if logger:
        logger.info(msg)
    else:
        print(msg)

# ---------- Classification Patterns ----------

HARD_KEYWORDS = [
    "unregistered", "not registered", "torrent not found", "deleted", "removed",
    "replaced", "superseded", "duplicate", "already exists", "banned", "blacklisted",
    "invalid passkey", "unauthorized", "forbidden", "ratio too low", "hit and run",
    "client banned", "rejected by tracker", "info_hash not found", "hash not found",
    "requires re-download", "season pack", "season pack uploaded", "complete season",
    "complete season uploaded", "full season", "entire season", "s1 pack", "s2 pack"
]

HARD_SEASON_PACK_PATTERNS = [
    re.compile(r'\bseason\s*pack(s)?\b', re.IGNORECASE),
    re.compile(r'\bseason\s*pack\s*uploaded\b', re.IGNORECASE),
    re.compile(r'\bs(?:eason)?\s*\d{1,2}\s*pack\b', re.IGNORECASE),
    re.compile(r'\bcomplete\s+season(s)?\b', re.IGNORECASE),
    re.compile(r'\bcomplete\s+season\s*uploaded\b', re.IGNORECASE),
    re.compile(r'\bcomplete\s*s0?\d{1,2}\b', re.IGNORECASE),
    re.compile(r'\bfull\s+season(s)?\b', re.IGNORECASE),
    re.compile(r'\bentire\s+season(s)?\b', re.IGNORECASE),
]

SOFT_KEYWORDS = [
    "timed out", "timeout", "temporary failure in name resolution",
    "could not resolve host", "no such host", "connection refused",
    "connection reset", "unreachable", "tls handshake", "ssl handshake",
    "http 5", "502", "503", "504", "tracker is down", "offline"
]

EXCLUDE_TRACKER_PHRASES = ["this torrent is private"]

# ---------- Helpers ----------

def normpath_case(p: str) -> str:
    if not p:
        return ""
    try:
        return os.path.normcase(os.path.normpath(p))
    except Exception:
        return p

def best_root_from_qbit(info: dict) -> str:
    """
    Get the content root path for a qBittorrent torrent.
    qBittorrent's content_path points directly to where the content lives.
    """
    content_path = (info.get("content_path") or "").strip()
    
    if content_path:
        return normpath_case(content_path)
    
    save_path = (info.get("save_path") or "").strip()
    name = (info.get("name") or "").strip()
    
    if save_path and name:
        return normpath_case(os.path.join(save_path, name))
    
    return normpath_case(save_path or name or "")

def best_root_from_deluge(save_path: str, name: str) -> str:
    """
    Get the content root path for a Deluge torrent.
    For Deluge, content is located at save_path + name.
    """
    sp = (save_path or "").strip()
    nm = (name or "").strip()
    
    if not sp or not nm:
        return normpath_case(sp or nm or "")
    
    return normpath_case(os.path.join(sp, nm))

# ---------- Settings ----------

@dataclass
class ClientConfig:
    id: str
    type: str
    name: str
    base_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = False

def load_settings() -> Dict[str, Any]:
    if not os.path.exists(SETTINGS_PATH):
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, indent=2)
        return DEFAULT_SETTINGS.copy()
    with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_settings(data: Dict[str, Any]) -> None:
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def generate_client_id(settings: Dict[str, Any]) -> str:
    existing = {(c.get("id") or "") for c in settings.get("clients", [])}
    i = 1
    while True:
        cid = f"c-{i:04d}"
        if cid not in existing:
            return cid
        i += 1

def parse_clients(settings: Dict[str, Any]) -> List[ClientConfig]:
    out = []
    for c in settings.get("clients", []):
        out.append(ClientConfig(
            id=c["id"],
            type=c["type"],
            name=c.get("name", c["id"]),
            base_url=c["base_url"].rstrip("/"),
            username=c.get("username"),
            password=c.get("password"),
            verify_ssl=bool(c.get("verify_ssl", False)),
        ))
    return out

# ---------- Path Normalization ----------

def detect_common_base_path(paths: List[str]) -> str:
    """
    Detect the common base path from a list of paths.
    Returns the longest common directory prefix.
    """
    if not paths:
        return ""
    
    if len(paths) == 1:
        path = normpath_case(paths[0])
        return os.path.dirname(path) if path else ""
    
    normalized = [normpath_case(p) for p in paths if p]
    if not normalized:
        return ""
    
    split_paths = [p.split(os.sep) for p in normalized]
    
    common_parts = []
    for parts in zip(*split_paths):
        if len(set(parts)) == 1:
            common_parts.append(parts[0])
        else:
            break
    
    if not common_parts:
        return ""
    
    common_path = os.sep.join(common_parts)
    
    if common_path and not common_path.endswith(os.sep):
        common_path += os.sep
    
    return common_path

def normalize_path_with_base(path: str, base_path: str) -> str:
    """
    Normalize a path by stripping the base path prefix.
    Returns the relative path from the base.
    """
    if not path:
        return ""
    
    normalized = normpath_case(path)
    
    if base_path and normalized.startswith(base_path):
        relative = normalized[len(base_path):]
        return relative.lstrip(os.sep)
    
    return normalized

# ---------- Classifier ----------

def classify_torrent(trackers: List[Dict[str, Any]]) -> Tuple[str, List[str], str]:
    """
    Returns: (class, reasons, first_bad_tracker)
    class: "hard" | "soft" | "ok"
    """
    reasons = []
    has_working = False
    first_bad_tracker = ""
    seen_reasons = set()
    
    for tr in trackers:
        status = tr.get("status", "")
        msg = (tr.get("msg") or tr.get("message") or "").strip()
        url = tr.get("url", "")
        
        if msg and any(ex in msg.lower() for ex in EXCLUDE_TRACKER_PHRASES):
            continue
            
        if status == 2 or "working" in str(status).lower():
            has_working = True
            
        if msg:
            msg_lower = msg.lower()
            is_hard = False
            
            for keyword in HARD_KEYWORDS:
                if keyword in msg_lower:
                    is_hard = True
                    break
            
            if not is_hard:
                for pattern in HARD_SEASON_PACK_PATTERNS:
                    if pattern.search(msg):
                        is_hard = True
                        break
            
            if is_hard:
                cleaned_msg = clean_error_message(msg)
                if cleaned_msg and cleaned_msg not in seen_reasons:
                    reasons.append(cleaned_msg)
                    seen_reasons.add(cleaned_msg)
                    if not first_bad_tracker:
                        first_bad_tracker = extract_host(url)
                        if not first_bad_tracker:
                            first_bad_tracker = extract_tracker_from_message(msg)
    
    if reasons:
        return ("hard", reasons, first_bad_tracker)
    
    soft_reasons = []
    seen_soft = set()
    for tr in trackers:
        msg = (tr.get("msg") or tr.get("message") or "").strip()
        if msg:
            msg_lower = msg.lower()
            for keyword in SOFT_KEYWORDS:
                if keyword in msg_lower:
                    cleaned_msg = clean_error_message(msg)
                    if cleaned_msg and cleaned_msg not in seen_soft:
                        soft_reasons.append(cleaned_msg)
                        seen_soft.add(cleaned_msg)
                        if not first_bad_tracker:
                            first_bad_tracker = extract_host(tr.get("url", ""))
                            if not first_bad_tracker:
                                first_bad_tracker = extract_tracker_from_message(msg)
                    break
    
    if not has_working and soft_reasons:
        return ("soft", soft_reasons, first_bad_tracker)
    
    return ("ok", [], "")

def clean_error_message(msg: str) -> str:
    if not msg:
        return ""
    
    import re
    
    cleaned = msg
    if cleaned.lower().startswith("error:"):
        cleaned = cleaned[6:].strip()
    
    url_patterns = [
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        r'ftp://[^\s<>"{}|\\^`\[\]]+',
        r'www\.[^\s<>"{}|\\^`\[\]]+',
    ]
    
    for pattern in url_patterns:
        cleaned = re.sub(pattern, '', cleaned)
    
    cleaned = ' '.join(cleaned.split())
    cleaned = cleaned.rstrip(':').strip()
    
    return cleaned

def extract_tracker_from_message(msg: str) -> str:
    if not msg:
        return ""
    
    import re
    
    url_pattern = r'https?://([^/\s<>"{}|\\^`\[\]]+)'
    match = re.search(url_pattern, msg)
    
    if match:
        return match.group(1).lower()
    
    return ""

def extract_host(url: str) -> str:
    try:
        hostname = (urlparse(url).hostname or "").lower()
        if not hostname and url:
            return url.lower().strip()
        return hostname
    except Exception:
        return url.lower().strip() if url else ""

# ---------- qBittorrent Client ----------

class QbitClient:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.verify = self.cfg.verify_ssl

    def login(self) -> None:
        r = self.s.post(f"{self.cfg.base_url}/api/v2/auth/login",
                        data={"username": self.cfg.username or "", "password": self.cfg.password or ""},
                        timeout=10)
        r.raise_for_status()
        if r.text.strip() != "Ok.":
            raise RuntimeError("qBittorrent login failed")

    def list_torrents(self) -> List[Dict[str, Any]]:
        self.login()
        r = self.s.get(f"{self.cfg.base_url}/api/v2/torrents/info", timeout=15)
        r.raise_for_status()
        return r.json() or []

    def get_trackers(self, thash: str) -> List[Dict[str, Any]]:
        r = self.s.get(f"{self.cfg.base_url}/api/v2/torrents/trackers", params={"hash": thash}, timeout=10)
        r.raise_for_status()
        data = r.json()
        return [t for t in (data or []) if not self._is_pseudo_tracker(t.get("url", ""))]

    def get_files(self, thash: str) -> List[Dict[str, Any]]:
        r = self.s.get(f"{self.cfg.base_url}/api/v2/torrents/files", params={"hash": thash}, timeout=10)
        r.raise_for_status()
        return r.json() or []

    @staticmethod
    def _is_pseudo_tracker(url: str) -> bool:
        url_lower = url.lower()
        return any(x in url_lower for x in ["dht://", "pex://", "lsd://", "** [dht]", "** [pex]", "** [lsd]"])

    def exists(self, h: str) -> bool:
        self.login()
        r = self.s.get(f"{self.cfg.base_url}/api/v2/torrents/info", params={"hashes": h}, timeout=10)
        r.raise_for_status()
        arr = r.json()
        return isinstance(arr, list) and any((t.get("hash") or "").lower() == h.lower() for t in arr)

    def delete(self, hashes: List[str], delete_data: bool = False) -> Tuple[bool, str]:
        self.login()
        r = self.s.post(f"{self.cfg.base_url}/api/v2/torrents/delete",
                        data={"hashes": "|".join(hashes), "deleteFiles": "true" if delete_data else "false"},
                        timeout=15)
        if r.status_code == 200:
            return True, "Deleted"
        return False, f"HTTP {r.status_code}: {r.text}"

# ---------- Deluge Client ----------

class DelugeClient:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.verify = self.cfg.verify_ssl
        self.rpc_url = f"{self.cfg.base_url}/json"
        self._rid = 0
        self._torrents_cache = None

    def _rpc(self, method: str, params: list):
        self._rid += 1
        payload = {"method": method, "params": params, "id": self._rid}
        r = self.s.post(self.rpc_url, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        if data.get("error"):
            raise RuntimeError(f"Deluge RPC error: {data['error']}")
        return data.get("result")

    def login(self) -> None:
        if not self._rpc("auth.login", [self.cfg.password or ""]):
            raise RuntimeError("Deluge login failed")

    def list_torrents(self) -> List[Dict[str, Any]]:
        self.login()
        fields = ["name", "hash", "save_path", "state", "tracker_host", "tracker_status", "trackers", "total_size"]
        result = self._rpc("web.update_ui", [fields, {}]) or {}
        tdict = result.get("torrents", {}) or {}
        
        self._torrents_cache = tdict
        
        torrents = []
        for thash, t in tdict.items():
            torrents.append({
                "hash": thash,
                "name": t.get("name", ""),
                "save_path": t.get("save_path", ""),
                "state": t.get("state", ""),
                "tracker_host": t.get("tracker_host", ""),
                "tracker_status": t.get("tracker_status", ""),
                "trackers": t.get("trackers", []),
                "total_size": t.get("total_size", 0)
            })
        
        return torrents

    def get_trackers(self, thash: str) -> List[Dict[str, Any]]:
        if self._torrents_cache and thash in self._torrents_cache:
            t = self._torrents_cache[thash]
        else:
            self.login()
            fields = ["tracker_status", "tracker_host", "trackers"]
            result = self._rpc("web.update_ui", [fields, {}]) or {}
            tdict = result.get("torrents", {}) or {}
            t = tdict.get(thash, {})
        
        trackers = []
        status_msg = (t.get("tracker_status") or "").strip()
        host = (t.get("tracker_host") or "").strip()
        
        if status_msg:
            is_working = "announce ok" in status_msg.lower() or status_msg.lower() == "ok"
            tracker_url = host if host else "unknown"
            trackers.append({
                "url": tracker_url,
                "status": 2 if is_working else 0,
                "message": status_msg
            })
        
        if not trackers and host:
            trackers.append({
                "url": host,
                "status": 0,
                "message": "No tracker status available"
            })
        
        tracker_list = t.get("trackers", [])
        if not trackers and tracker_list:
            for tracker_info in tracker_list:
                if isinstance(tracker_info, dict):
                    url = tracker_info.get("url", "")
                    if url:
                        trackers.append({
                            "url": url,
                            "status": 0,
                            "message": "Tracker status unknown"
                        })
                        break
        
        return trackers

    def get_files(self, thash: str) -> List[Dict[str, Any]]:
        self.login()
        try:
            result = self._rpc("web.get_torrent_files", [thash]) or {}
            files = result.get("files", []) or []
            return [{"name": f.get("path", ""), "size": f.get("size", 0)} for f in files]
        except Exception:
            try:
                result = self._rpc("core.get_torrent_status", [thash, ["files"]]) or {}
                files = result.get("files", []) or []
                return [{"name": f.get("path", ""), "size": f.get("size", 0)} for f in files]
            except Exception:
                return []

    def exists(self, h: str) -> bool:
        self.login()
        fields = ["hash"]
        result = self._rpc("web.update_ui", [fields, {}]) or {}
        tdict = result.get("torrents", {}) or {}
        return any((k or "").lower() == h.lower() for k in tdict.keys())

    def delete(self, hashes: List[str], delete_data: bool = False) -> Tuple[bool, str]:
        self.login()
        for h in hashes:
            try:
                self._rpc("core.remove_torrent", [h, bool(delete_data)])
            except Exception as e:
                return False, f"Failed on {h}: {e}"
        return True, "Deleted"

# ---------- Shared File Detection ----------

def get_anchor_file(client_adapter, thash: str) -> Optional[Tuple[str, int]]:
    """
    Returns (relative_path, size) for the anchor file.
    Strategy: Use largest file.
    """
    try:
        files = client_adapter.get_files(thash)
        if not files:
            return None
        largest = max(files, key=lambda f: f.get("size", 0))
        return (largest.get("name", ""), largest.get("size", 0))
    except Exception:
        pass
    return None

def detect_shared_files_global(failed_items: List[Dict[str, Any]], all_torrents: List[Dict[str, Any]], adapters: Dict[str, Any], client_results: List[Dict[str, Any]]) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    """
    OPTIMIZED: Compare FAILED torrents against ALL torrents to detect shared files.
    
    Steps:
    1. Detect base paths from all torrents
    2. Group ALL torrents by (normalized_content_path, total_size)
    3. For each FAILED torrent, check if it matches ANY other torrent (failed or OK)
    4. If multiple torrents match on path+size, verify with anchor file check
    
    Returns tuple of (detected_bases dict, shared_ok_torrents list).
    """
    log("\n" + "="*80)
    log("SHARED FILE DETECTION - Starting")
    log("="*80)
    
    # Initialize shared_ok_torrents at the start of the function
    shared_ok_torrents = []  # Track OK torrents that share with failed ones
    
    # Create client ID to name mapping
    client_names = {}
    for result in client_results:
        client_id = result.get("client_id", "")
        client_label = result.get("client_label", client_id)
        client_names[client_id] = client_label
    
    # First pass: detect base paths per client using ALL torrents
    log("\n" + "-"*80)
    log("PHASE 1: BASE PATH DETECTION")
    log("-"*80)
    
    detected_bases = {}
    for result in client_results:
        client_id = result.get("client_id", "")
        all_paths = result.get("all_paths", [])
        
        if client_id and all_paths:
            base = detect_common_base_path(all_paths)
            detected_bases[client_id] = base
            if base:
                log(f"\n[{client_id}] Detected base path: '{base}'")
                log(f"[{client_id}] Sample paths (first 5):")
                for i, path in enumerate(all_paths[:5], 1):
                    log(f"  [{i}] Original: {path}")
            else:
                log(f"\n[{client_id}] No common base path detected")
                log(f"[{client_id}] Sample paths (first 3):")
                for i, path in enumerate(all_paths[:3], 1):
                    log(f"  [{i}] {path}")
        else:
            detected_bases[client_id] = ""
    
    log(f"\n{'='*80}")
    log(f"PHASE 1 SUMMARY:")
    log(f"  Total clients: {len(client_results)}")
    log(f"  Clients with base path: {sum(1 for b in detected_bases.values() if b)}")
    log(f"  Total failed torrents: {len(failed_items)}")
    log(f"  Total all torrents: {len(all_torrents)}")
    log(f"{'='*80}")
    
    # DEBUG: Check failed torrents have content_path
    log("\n" + "-"*80)
    log("PHASE 2: FAILED TORRENT PATH VALIDATION")
    log("-"*80)
    
    failed_with_empty_path = 0
    failed_with_zero_size = 0
    
    log("\nExamining failed torrents (showing first 5):")
    for i, item in enumerate(failed_items[:5], 1):
        content_path = item.get("content_path", "")
        total_size = item.get("total_size", 0)
        name = item.get("name", "")[:60]
        client_id = item.get("client_id", "")
        client_name = client_names.get(client_id, client_id)
        classification = item.get("class", "")
        
        if not content_path:
            failed_with_empty_path += 1
        if total_size == 0:
            failed_with_zero_size += 1
            
        log(f"\n[{i}] {name}")
        log(f"    Client: {client_name}")
        log(f"    Classification: {classification}")
        log(f"    content_path: '{content_path}'")
        log(f"    total_size: {total_size:,} bytes")
        log(f"    Issues: {('EMPTY PATH, ' if not content_path else '') + ('ZERO SIZE' if total_size == 0 else 'None')}")
    
    log(f"\n{'='*80}")
    log(f"PHASE 2 SUMMARY:")
    log(f"  Total failed torrents: {len(failed_items)}")
    log(f"  Failed with empty path: {failed_with_empty_path}")
    log(f"  Failed with zero size: {failed_with_zero_size}")
    log(f"  Failed with valid path+size: {len(failed_items) - failed_with_empty_path - failed_with_zero_size}")
    log(f"{'='*80}")
    
    # Second pass: Group ALL torrents (failed + ok) by (normalized_content_path, total_size)
    log("\n" + "-"*80)
    log("PHASE 3: GROUPING ALL TORRENTS BY PATH+SIZE")
    log("-"*80)
    
    by_path_size: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    
    # Track per-client grouping stats
    client_grouping_stats = {}
    
    log("\nProcessing all torrents for grouping...")
    for torrent in all_torrents:
        client_id = torrent.get("client_id", "")
        content_path = torrent.get("content_path", "")
        total_size = torrent.get("total_size", 0)
        base = detected_bases.get(client_id, "")
        
        normalized = normalize_path_with_base(content_path, base)
        
        # Track stats
        if client_id not in client_grouping_stats:
            client_grouping_stats[client_id] = {
                'total': 0,
                'with_path': 0,
                'normalized_samples': []
            }
        
        client_grouping_stats[client_id]['total'] += 1
        
        if normalized and total_size > 0:
            client_grouping_stats[client_id]['with_path'] += 1
            
            # Store some samples
            if len(client_grouping_stats[client_id]['normalized_samples']) < 3:
                client_grouping_stats[client_id]['normalized_samples'].append({
                    'name': torrent.get('name', '')[:60],
                    'original': content_path[:80],
                    'normalized': normalized[:80],
                    'size': total_size
                })
            
            key = (normalized, total_size)
            by_path_size.setdefault(key, []).append(torrent)
    
    # Print per-client grouping statistics
    for client_id, stats in client_grouping_stats.items():
        log(f"\n[{client_id}] Grouping statistics:")
        log(f"  Total torrents processed: {stats['total']}")
        log(f"  Torrents with valid path+size: {stats['with_path']}")
        log(f"  Torrents skipped (no path or size=0): {stats['total'] - stats['with_path']}")
        
        if stats['normalized_samples']:
            log(f"\n  Sample normalized paths:")
            for i, sample in enumerate(stats['normalized_samples'], 1):
                log(f"    Example {i}: {sample['name']}")
                log(f"      Original:   {sample['original']}")
                log(f"      Normalized: {sample['normalized']}")
                log(f"      Size:       {sample['size']:,} bytes")
    
    log(f"\n{'='*80}")
    log(f"PHASE 3 SUMMARY:")
    log(f"  Unique (path, size) combinations: {len(by_path_size)}")
    log(f"  Groups with 1 torrent: {sum(1 for group in by_path_size.values() if len(group) == 1)}")
    log(f"  Groups with 2+ torrents: {sum(1 for group in by_path_size.values() if len(group) >= 2)}")
    log(f"{'='*80}")
    
    # Show sample grouping keys
    log(f"\nSample grouping keys (first 5 multi-member groups):")
    multi_groups = [(key, group) for key, group in by_path_size.items() if len(group) >= 2]
    for i, ((path, size), group) in enumerate(multi_groups[:5], 1):
        log(f"\n  Group {i}:")
        log(f"    Normalized Path: {path[:100]}")
        log(f"    Size: {size:,} bytes")
        log(f"    Members: {len(group)} torrents")
        for j, torrent in enumerate(group, 1):
            thash = torrent.get('hash', '')[:8]
            client_id = torrent.get('client_id', '')
            client_name = client_names.get(client_id, client_id)
            name = torrent.get('name', '')
            original_path = torrent.get('content_path', '')
            log(f"      [{j}] {name}")
            log(f"          Client: {client_name} | Hash: {thash}")
            log(f"          Original Path: {original_path}")
    
    # Third pass: For each FAILED torrent, check if it shares with ANY torrent
    log("\n" + "-"*80)
    log("PHASE 4: ANALYZING FAILED TORRENT GROUP MEMBERSHIP")
    log("-"*80)
    
    # Create a map of hash -> failed item for quick lookup
    failed_by_hash = {}
    for item in failed_items:
        key = f"{item.get('client_id')}|{item.get('hash')}"
        failed_by_hash[key] = item
    
    log(f"\nBuilt failed torrent lookup map: {len(failed_by_hash)} entries")
    
    # Analyze which groups the failed torrents are in
    failed_in_groups = {}
    for item in failed_items:
        client_id = item.get("client_id", "")
        content_path = item.get("content_path", "")
        total_size = item.get("total_size", 0)
        base = detected_bases.get(client_id, "")
        
        normalized = normalize_path_with_base(content_path, base)
        
        if normalized and total_size > 0:
            key = (normalized, total_size)
            group_size = len(by_path_size.get(key, []))
            failed_in_groups[item.get('hash')] = {
                'group_size': group_size,
                'normalized': normalized[:80],
                'size': total_size,
                'name': item.get('name', '')[:60],
                'client_id': client_id,
                'classification': item.get('class', '')
            }
    
    solo_count = sum(1 for info in failed_in_groups.values() if info['group_size'] == 1)
    multi_count = sum(1 for info in failed_in_groups.values() if info['group_size'] > 1)
    no_group_count = len(failed_items) - len(failed_in_groups)
    
    log(f"\n{'='*80}")
    log(f"PHASE 4 SUMMARY:")
    log(f"  Failed torrent distribution:")
    log(f"    - In solo groups (1 torrent): {solo_count}")
    log(f"    - In multi-torrent groups (2+): {multi_count}")
    log(f"    - Not in any group (invalid path/size): {no_group_count}")
    log(f"{'='*80}")
    
    if multi_count > 0:
        log(f"\nFailed torrents in multi-torrent groups (first 5):")
        count = 0
        for thash, info in failed_in_groups.items():
            if info['group_size'] > 1 and count < 5:
                count += 1
                client_id = info['client_id']
                client_name = client_names.get(client_id, client_id)
                log(f"\n  [{count}] {info['name']}")
                log(f"      Hash: {thash}")
                log(f"      Client: {client_name}")
                log(f"      Classification: {info['classification']}")
                log(f"      Normalized path: {info['normalized']}")
                log(f"      Size: {info['size']:,} bytes")
                log(f"      Total in group: {info['group_size']} torrents")
    
    # Process each group
    log("\n" + "-"*80)
    log("PHASE 5: CHECKING GROUPS FOR SHARED FILES")
    log("-"*80)
    
    shared_group_counter = 0
    groups_checked = 0
    
    # Focus on multi-member groups with failed torrents
    groups_to_check = []
    for (path, size), group in by_path_size.items():
        if len(group) < 2:
            # Single torrent - mark as not shared
            for torrent in group:
                key = f"{torrent.get('client_id')}|{torrent.get('hash')}"
                if key in failed_by_hash:
                    failed_by_hash[key]["shared"] = False
                    failed_by_hash[key]["shared_count"] = 1
                    failed_by_hash[key]["shared_group_id"] = None
            continue
        
        # Check if this group contains ANY failed torrents
        failed_in_group = []
        ok_in_group = []
        for torrent in group:
            key = f"{torrent.get('client_id')}|{torrent.get('hash')}"
            if key in failed_by_hash:
                failed_in_group.append(torrent)
            else:
                ok_in_group.append(torrent)
        
        # Only process groups that contain at least one failed torrent
        if failed_in_group:
            groups_to_check.append(((path, size), group, failed_in_group, ok_in_group))
    
    log(f"\nGroups to check: {len(groups_to_check)}")
    log(f"(Multi-member groups containing at least one failed torrent)")
    
    for (path, size), group, failed_in_group, ok_in_group in groups_to_check:
        groups_checked += 1
        
        # Multiple torrents with same path+size - verify with anchor file
        log(f"\n{'─'*80}")
        log(f"Checking Group #{groups_checked}:")
        log(f"  Path: {path[:80]}")
        log(f"  Size: {size:,} bytes")
        log(f"  Total members: {len(group)}")
        log(f"  Failed torrents: {len(failed_in_group)}")
        log(f"  OK torrents: {len(ok_in_group)}")
        
        # Show details of all torrents in this group
        log(f"\n  Group members:")
        for i, torrent in enumerate(group, 1):
            key = f"{torrent.get('client_id')}|{torrent.get('hash')}"
            status = "FAILED" if key in failed_by_hash else "OK"
            client_id = torrent.get('client_id', '')
            name = torrent.get('name', '')[:50]
            original_path = torrent.get('content_path', '')
            log(f"    [{i}] {status:6} | {client_id:8} | {name}")
            if i <= 3:  # Show path for first 3
                log(f"         Path: {original_path[:100]}")
        
        # Get anchor files for all torrents in the group
        log(f"\n  Retrieving anchor files...")
        anchor_map = {}
        for torrent in group:
            thash = torrent.get("hash", "")
            client_id = torrent.get("client_id", "")
            adapter = adapters.get(client_id)
            
            if adapter:
                anchor = get_anchor_file(adapter, thash)
                if anchor:
                    anchor_map[f"{client_id}|{thash}"] = anchor
                    log(f"    ✓ {torrent.get('name', '')[:40]}: {anchor[0][:50]} ({anchor[1]:,} bytes)")
                else:
                    log(f"    ✗ {torrent.get('name', '')[:40]}: No anchor file")
        
        log(f"\n  Retrieved {len(anchor_map)}/{len(group)} anchor files")
        
        # Group by anchor file
        anchor_groups: Dict[Tuple[str, int], List[str]] = {}
        for torrent_key, anchor in anchor_map.items():
            anchor_groups.setdefault(anchor, []).append(torrent_key)
        
        log(f"  Unique anchor files: {len(anchor_groups)}")
        
        if len(anchor_groups) > 0:
            log(f"\n  Anchor file groups:")
            for i, (anchor, members) in enumerate(anchor_groups.items(), 1):
                anchor_name = anchor[0][:60] if anchor[0] else "unknown"
                anchor_size = anchor[1]
                log(f"    [{i}] '{anchor_name}' ({anchor_size:,} bytes)")
                log(f"        Shared by {len(members)} torrent(s)")
                if len(members) > 1:
                    log(f"        → This is a SHARED group!")
        
        # Assign shared status
        for torrent in group:
            key = f"{torrent.get('client_id')}|{torrent.get('hash')}"
            
            # Only process if this is a failed torrent
            if key not in failed_by_hash:
                continue
            
            anchor = anchor_map.get(key)
            
            if not anchor:
                failed_by_hash[key]["shared"] = False
                failed_by_hash[key]["shared_count"] = 1
                failed_by_hash[key]["shared_group_id"] = None
                log(f"\n  → Failed torrent has no anchor file, marked NOT shared")
                continue
            
            matches = anchor_groups.get(anchor, [])
            
            if len(matches) > 1:
                # This failed torrent shares files with other torrents
                shared_group_counter += 1
                group_id = f"shared_{shared_group_counter}"
                
                failed_by_hash[key]["shared"] = True
                failed_by_hash[key]["shared_count"] = len(matches)
                failed_by_hash[key]["shared_group_id"] = group_id
                
                # Count failed vs OK
                failed_count = sum(1 for m in matches if m in failed_by_hash)
                ok_count = len(matches) - failed_count
                
                log(f"\n  → SHARED FILES DETECTED!")
                log(f"     Failed torrent: {torrent.get('name', '')[:60]}")
                log(f"     Shares with: {len(matches)-1} other torrent(s)")
                log(f"       - {failed_count-1} other failed torrent(s)")
                log(f"       - {ok_count} OK torrent(s)")
                
                # Add all matching torrents to the group (including OK ones)
                for match_key in matches:
                    match_torrent = next((t for t in group if f"{t.get('client_id')}|{t.get('hash')}" == match_key), None)
                    if match_torrent:
                        # Mark this torrent with the shared group ID
                        if match_key not in failed_by_hash:
                            # This is an OK torrent that shares with a failed one
                            shared_ok_torrents.append({
                                "hash": match_torrent.get("hash"),
                                "name": match_torrent.get("name"),
                                "save_path": match_torrent.get("content_path"),
                                "content_path": match_torrent.get("content_path"),
                                "total_size": match_torrent.get("total_size"),
                                "class": "ok",
                                "reasons": [],
                                "first_bad_tracker": "",
                                "client_id": match_torrent.get("client_id"),
                                "shared": True,
                                "shared_count": len(matches),
                                "shared_group_id": group_id
                            })
                            log(f"       + Added OK torrent to shared group: {match_torrent.get('name', '')[:60]}")
            else:
                failed_by_hash[key]["shared"] = False
                failed_by_hash[key]["shared_count"] = 1
                failed_by_hash[key]["shared_group_id"] = None
                log(f"\n  → Failed torrent has unique anchor, NOT shared")
    
    log("\n" + "="*80)
    log(f"SHARED FILE DETECTION - COMPLETE")
    log(f"{'='*80}")
    log(f"Final Statistics:")
    log(f"  Groups checked: {groups_checked}")
    log(f"  Shared groups created: {shared_group_counter}")
    log(f"  Failed torrents marked as shared: {sum(1 for item in failed_by_hash.values() if item.get('shared'))}")
    log(f"  OK torrents sharing with failed: {len(shared_ok_torrents)}")
    log(f"{'='*80}\n")
    
    return detected_bases, shared_ok_torrents

# ---------- Scan Orchestrator ----------

def scan_client(client_adapter, client_cfg: ClientConfig, progress_queue=None) -> Dict[str, Any]:
    """
    Scan a single client and return results.
    Returns BOTH failed torrents AND all torrent metadata for shared detection.
    """
    try:
        log(f"[{client_cfg.id}] Starting scan for {client_cfg.name}")
        torrents = client_adapter.list_torrents()
        total = len(torrents)
        log(f"[{client_cfg.id}] Found {total} torrents")
        
        if progress_queue:
            progress_queue.put(('progress', {
                'client_id': client_cfg.id,
                'current': 0,
                'total': total,
                'percent': 0
            }))
        
        failed_items = []  # Only failed torrents
        all_torrents = []  # ALL torrents (for shared detection)
        all_paths = []
        
        for idx, t in enumerate(torrents):
            thash = t.get("hash") or t.get("id")
            if not thash:
                continue
            
            # Get content path and size for ALL torrents
            if isinstance(client_adapter, QbitClient):
                content_path = best_root_from_qbit(t)
            else:
                content_path = best_root_from_deluge(t.get("save_path", ""), t.get("name", ""))
            
            total_size = t.get("size") or t.get("total_size", 0)
            
            # Collect paths from ALL torrents
            if content_path:
                all_paths.append(content_path)
            
            # Store ALL torrent metadata for shared detection
            all_torrents.append({
                "hash": thash,
                "name": t.get("name", ""),
                "content_path": content_path,
                "total_size": total_size,
                "client_id": client_cfg.id
            })
            
            # Progress updates
            if idx > 0 and (idx % 50 == 0 or idx == total - 1):
                percent = int((idx / total) * 100) if total > 0 else 0
                if progress_queue:
                    progress_queue.put(('progress', {
                        'client_id': client_cfg.id,
                        'current': idx,
                        'total': total,
                        'percent': percent
                    }))
            
            # Get trackers and classify
            try:
                trackers = client_adapter.get_trackers(thash)
            except Exception as e:
                log(f"[{client_cfg.id}] Failed to get trackers for {thash}: {e}")
                trackers = []
            
            classification, reasons, first_bad = classify_torrent(trackers)
            
            # Only add to failed_items if it's actually failed
            if classification != "ok":
                failed_items.append({
                    "hash": thash,
                    "name": t.get("name", ""),
                    "save_path": content_path,  # Keep for backwards compatibility
                    "content_path": content_path,  # Add for consistency with all_torrents
                    "total_size": total_size,
                    "class": classification,
                    "reasons": reasons,
                    "first_bad_tracker": first_bad,
                    "client_id": client_cfg.id,
                    "shared": False,
                    "shared_count": 1,
                    "shared_group_id": None
                })
        
        if progress_queue:
            progress_queue.put(('progress', {
                'client_id': client_cfg.id,
                'current': total,
                'total': total,
                'percent': 100
            }))
        
        hard_count = sum(1 for item in failed_items if item["class"] == "hard")
        soft_count = sum(1 for item in failed_items if item["class"] == "soft")
        
        log(f"[{client_cfg.id}] Scan complete:")
        log(f"  - Total torrents scanned: {total}")
        log(f"  - Failed torrents found: {len(failed_items)} ({hard_count} hard, {soft_count} soft)")
        log(f"  - OK torrents: {total - len(failed_items)}")
        
        # Show sample failed torrent paths
        if failed_items:
            log(f"  - Sample failed torrent paths:")
            for item in failed_items[:3]:
                log(f"    * {item.get('name', '')[:50]}")
                log(f"      Path: {item.get('content_path', '')}")
        
        return {
            "client_id": client_cfg.id,
            "client_label": client_cfg.name,
            "stats": {"hard": hard_count, "soft": soft_count},
            "items": failed_items,
            "all_torrents": all_torrents,  # NEW: Include ALL torrents
            "all_paths": all_paths
        }
    except Exception as e:
        log(f"[{client_cfg.id}] SCAN FAILED: {e}")
        import traceback
        traceback.print_exc()
        return {
            "client_id": client_cfg.id,
            "client_label": client_cfg.name,
            "stats": {"hard": 0, "soft": 0},
            "items": [],
            "all_torrents": [],
            "all_paths": [],
            "error": str(e)
        }

def scan_all_clients(settings: Dict[str, Any], levels: Set[str]) -> Dict[str, Any]:
    """Non-streaming scan for /scan_json endpoint."""
    global logger
    logger = setup_scan_logging()
    
    started_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    log(f"\n{'='*80}")
    log(f"SCAN STARTED: {started_at}")
    log(f"{'='*80}\n")
    
    clients_cfg = parse_clients(settings)
    results = []
    adapters = {}
    
    for cfg in clients_cfg:
        if cfg.type.lower() == "qbittorrent":
            adapters[cfg.id] = QbitClient(cfg)
        elif cfg.type.lower() == "deluge":
            adapters[cfg.id] = DelugeClient(cfg)
    
    with ThreadPoolExecutor(max_workers=len(clients_cfg)) as executor:
        futures = {}
        for cfg in clients_cfg:
            adapter = adapters.get(cfg.id)
            if adapter:
                future = executor.submit(scan_client, adapter, cfg, None)
                futures[future] = cfg.id
        
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                client_id = futures[future]
                results.append({
                    "client_id": client_id,
                    "client_label": client_id,
                    "stats": {"hard": 0, "soft": 0},
                    "items": [],
                    "all_torrents": [],
                    "error": str(e)
                })
    
    # Collect failed items and ALL torrents
    failed_items = []
    all_torrents = []
    for result in results:
        failed_items.extend(result.get("items", []))
        all_torrents.extend(result.get("all_torrents", []))
    
    # Perform shared file detection (compare failed against ALL)
    detected_bases, shared_ok_torrents = detect_shared_files_global(failed_items, all_torrents, adapters, results)
    
    # Add detected base paths to results
    for result in results:
        client_id = result.get("client_id", "")
        result["detected_base_path"] = detected_bases.get(client_id, "")
        # Remove all_torrents from output (not needed in response)
        result.pop("all_torrents", None)
    
    # Add shared_ok_torrents as a separate field in the response (not in items)
    # This allows the frontend to access them for the modal without showing in main table
    for result in results:
        client_id = result.get("client_id", "")
        result["shared_ok_torrents"] = [t for t in shared_ok_torrents if t.get("client_id") == client_id]
    
    # Filter by levels after shared detection
    if levels:
        for result in results:
            result["items"] = [item for item in result["items"] if item["class"] in levels]
            result["stats"]["hard"] = sum(1 for item in result["items"] if item["class"] == "hard")
            result["stats"]["soft"] = sum(1 for item in result["items"] if item["class"] == "soft")
    
    completed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    log(f"\n{'='*80}")
    log(f"SCAN COMPLETED: {completed_at}")
    log(f"Log file saved to: {LOG_FILE}")
    log(f"{'='*80}\n")
    
    return {
        "clients": results,
        "started_at": started_at,
        "completed_at": completed_at
    }

def scan_all_clients_streaming(settings: Dict[str, Any], levels: Set[str]):
    """Streaming SSE scan with real-time progress."""
    import queue
    
    global logger
    logger = setup_scan_logging()
    
    started_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    log(f"\n{'='*80}")
    log(f"STREAMING SCAN STARTED: {started_at}")
    log(f"{'='*80}\n")
    
    clients_cfg = parse_clients(settings)
    
    if not clients_cfg:
        yield f"data: {json.dumps({'type': 'error', 'message': 'No clients configured'})}\n\n"
        return
    
    adapters = {}
    results_queue = queue.Queue()
    progress_queue = queue.Queue()
    
    for cfg in clients_cfg:
        if cfg.type.lower() == "qbittorrent":
            adapters[cfg.id] = QbitClient(cfg)
        elif cfg.type.lower() == "deluge":
            adapters[cfg.id] = DelugeClient(cfg)
    
    yield f"data: {json.dumps({'type': 'start', 'total_clients': len(clients_cfg), 'started_at': started_at})}\n\n"
    
    def scan_and_report(adapter, cfg, prog_q):
        try:
            result = scan_client(adapter, cfg, prog_q)
            results_queue.put(('success', result))
        except Exception as e:
            results_queue.put(('error', {
                "client_id": cfg.id,
                "client_label": cfg.name,
                "stats": {"hard": 0, "soft": 0},
                "items": [],
                "all_torrents": [],
                "error": str(e)
            }))
    
    with ThreadPoolExecutor(max_workers=len(clients_cfg)) as executor:
        futures = []
        for cfg in clients_cfg:
            adapter = adapters.get(cfg.id)
            if adapter:
                future = executor.submit(scan_and_report, adapter, cfg, progress_queue)
                futures.append(future)
        
        results = []
        completed = 0
        
        while completed < len(clients_cfg):
            try:
                event_type, data = progress_queue.get_nowait()
                if event_type == 'progress':
                    yield f"data: {json.dumps({'type': 'progress', **data})}\n\n"
            except queue.Empty:
                pass
            
            try:
                status, result = results_queue.get(timeout=0.1)
                results.append(result)
                completed += 1
                
                yield f"data: {json.dumps({'type': 'client_complete', 'client_id': result['client_id'], 'completed': completed, 'total': len(clients_cfg)})}\n\n"
                
            except queue.Empty:
                yield f": heartbeat\n\n"
        
        while not progress_queue.empty():
            try:
                event_type, data = progress_queue.get_nowait()
                if event_type == 'progress':
                    yield f"data: {json.dumps({'type': 'progress', **data})}\n\n"
            except queue.Empty:
                break
        
        for future in futures:
            future.result()
    
    # Collect failed items and ALL torrents
    failed_items = []
    all_torrents = []
    for result in results:
        failed_items.extend(result.get("items", []))
        all_torrents.extend(result.get("all_torrents", []))
    
    # Perform shared file detection (compare failed against ALL)
    detected_bases, shared_ok_torrents = detect_shared_files_global(failed_items, all_torrents, adapters, results)
    
    # Add detected base paths and remove all_torrents
    for result in results:
        client_id = result.get("client_id", "")
        result["detected_base_path"] = detected_bases.get(client_id, "")
        result.pop("all_torrents", None)
    
    # Add shared_ok_torrents as a separate field (not in items)
    for result in results:
        client_id = result.get("client_id", "")
        result["shared_ok_torrents"] = [t for t in shared_ok_torrents if t.get("client_id") == client_id]
    
    # Filter by levels
    if levels:
        for result in results:
            result["items"] = [item for item in result["items"] if item["class"] in levels]
            result["stats"]["hard"] = sum(1 for item in result["items"] if item["class"] == "hard")
            result["stats"]["soft"] = sum(1 for item in result["items"] if item["class"] == "soft")
    
    completed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    log(f"\n{'='*80}")
    log(f"STREAMING SCAN COMPLETED: {completed_at}")
    log(f"Log file saved to: {LOG_FILE}")
    log(f"{'='*80}\n")
    
    final_data = {
        "type": "complete",
        "clients": results,
        "started_at": started_at,
        "completed_at": completed_at
    }
    
    yield f"data: {json.dumps(final_data)}\n\n"

# ---------- Flask Routes ----------

@app.get("/favicon.ico")
def favicon():
    return ("", 204)

@app.route("/")
def index():
    cfgs = parse_clients(load_settings())
    return render_template('index.html', title=APP_TITLE, clients=cfgs)

@app.get("/settings_json")
def get_settings_json():
    settings = load_settings()
    return jsonify(settings)

@app.get("/scan_json")
def scan_json():
    levels_param = request.args.get("levels", "hard,soft")
    levels = set(l.strip().lower() for l in levels_param.split(",") if l.strip())
    if not levels:
        levels = {"hard", "soft"}
    
    settings = load_settings()
    result = scan_all_clients(settings, levels)
    return jsonify(result)

@app.get("/scan_stream")
def scan_stream():
    levels_param = request.args.get("levels", "hard,soft")
    levels = set(l.strip().lower() for l in levels_param.split(",") if l.strip())
    if not levels:
        levels = {"hard", "soft"}
    
    settings = load_settings()
    
    def generate():
        try:
            for event in scan_all_clients_streaming(settings, levels):
                yield event
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
    
    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@app.post("/clients/add")
def add_client():
    data = request.get_json(silent=True)
    form = data if data else request.form

    ctype = (form.get("type") or "").strip().lower()
    name = (form.get("name") or "").strip()
    base_url = (form.get("base_url") or "").strip().rstrip("/")
    username = form.get("username") or None
    password = form.get("password") or None
    verify_ssl = (str(form.get("verify_ssl")).lower() in ("1", "true", "yes", "on"))

    if not name or not base_url or ctype not in ("qbittorrent", "deluge"):
        return redirect(url_for("index"))

    settings = load_settings()
    cid = generate_client_id(settings)

    entry = {"id": cid, "type": ctype, "name": name, "base_url": base_url, "verify_ssl": verify_ssl}
    if ctype == "qbittorrent":
        entry["username"] = username or ""
        entry["password"] = password or ""
    else:
        entry["password"] = password or ""

    settings.setdefault("clients", []).append(entry)
    save_settings(settings)
    return redirect(url_for("index"))

@app.post("/clients/delete")
def delete_client():
    data = request.get_json(silent=True) or {}
    client_id = data.get("client_id")
    
    if not client_id:
        return jsonify({"ok": False, "error": "client_id required"}), 400
    
    settings = load_settings()
    clients = settings.get("clients", [])
    
    original_count = len(clients)
    clients = [c for c in clients if c.get("id") != client_id]
    
    if len(clients) == original_count:
        return jsonify({"ok": False, "error": "Client not found"}), 404
    
    settings["clients"] = clients
    save_settings(settings)
    
    return jsonify({"ok": True, "message": "Client deleted"})

@app.post("/api/torrents/delete")
def api_delete_torrent():
    data = request.get_json(silent=True) or {}
    cid = data.get("client_id")
    tid = data.get("torrent_id")
    delete_files = bool(data.get("delete_files", False))
    
    if not cid or not tid:
        return jsonify({"ok": False, "error": "client_id and torrent_id required"}), 400

    settings = load_settings()
    clients_cfg = parse_clients(settings)
    cfg = next((c for c in clients_cfg if c.id == cid), None)
    
    if not cfg:
        return jsonify({"ok": False, "error": "client not found"}), 404

    if cfg.type.lower() == "qbittorrent":
        adapter = QbitClient(cfg)
    elif cfg.type.lower() == "deluge":
        adapter = DelugeClient(cfg)
    else:
        return jsonify({"ok": False, "error": "unknown client type"}), 400

    try:
        if not adapter.exists(tid):
            return jsonify({"ok": False, "error": f"Torrent not found on client '{cid}'."}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to verify torrent existence: {e}"}), 500

    ok, msg = adapter.delete([tid], delete_data=delete_files)
    status = 200 if ok else 500
    payload = {"ok": ok, "message": msg} if ok else {"ok": False, "error": msg}
    return jsonify(payload), status

@app.get("/__ping")
def ping():
    return "ok"

if __name__ == "__main__":
    if not os.path.exists(SETTINGS_PATH):
        save_settings(DEFAULT_SETTINGS.copy())
    app.run(host="0.0.0.0", port=int(os.environ.get("TORRENT_UI_PORT", "5000")), debug=True)
