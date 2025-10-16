#!/usr/bin/env python3
# Production build: no demo rows. Tracker domain + live filter + no auto-scan.

import os
import json
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

import requests
from flask import Flask, request, redirect, url_for, render_template_string, jsonify
from jinja2 import ChoiceLoader, DictLoader

APP_TITLE = "Torrent Checker"
SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "settings.json")
DEFAULT_SETTINGS = {"clients": []}

@dataclass
class ClientConfig:
    id: str
    type: str  # qbittorrent | deluge
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

# Keywords used to detect likely "error/unregistered" tracker messages
_EXPANDED_KEYWORDS = [
    "unregistered","not registered","torrent not registered","not found","torrent not found",
    "info_hash not found","hash not found","deleted","removed","duplicate","dupe",
    "season pack","complete season","banned","nuked","invalid passkey","connection failed",
    "timeout","http 404","404","410","whitelist required","client not allowed","forbidden"
]

class QbitClient:
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.verify = self.cfg.verify_ssl

    def login(self) -> None:
        url = f"{self.cfg.base_url}/api/v2/auth/login"
        data = {"username": self.cfg.username or "", "password": self.cfg.password or ""}
        r = self.s.post(url, data=data, timeout=10)
        r.raise_for_status()
        if r.text.strip() != "Ok.":
            raise RuntimeError("qBittorrent login failed")

    def exists(self, h: str) -> bool:
        self.login()
        url = f"{self.cfg.base_url}/api/v2/torrents/info"
        r = self.s.get(url, params={"hashes": h}, timeout=10)
        r.raise_for_status()
        arr = r.json()
        return isinstance(arr, list) and any((t.get("hash") or "").lower() == h.lower() for t in arr)

    def _trackers_for(self, thash: str) -> List[Dict[str, Any]]:
        tr_url = f"{self.cfg.base_url}/api/v2/torrents/trackers"
        rr = self.s.get(tr_url, params={"hash": thash}, timeout=10)
        rr.raise_for_status()
        data = rr.json()
        return data if isinstance(data, list) else []

    @staticmethod
    def _best_tracker_host(trackers: List[Dict[str, Any]]) -> str:
        cands = []
        for t in trackers:
            url = (t or {}).get("url") or ""
            try:
                host = urlparse(url).hostname or ""
            except Exception:
                host = ""
            if host:
                cands.append({"host": host, "status": int((t or {}).get("status", 0))})
        if not cands:
            return ""
        # Prefer working (status==2), otherwise highest status
        cands.sort(key=lambda x: (x["status"] == 2, x["status"]), reverse=True)
        return cands[0]["host"]

    def list_problem_torrents(self) -> List[Dict[str, Any]]:
        self.login()
        info_url = f"{self.cfg.base_url}/api/v2/torrents/info"
        r = self.s.get(info_url, timeout=15)
        r.raise_for_status()
        torrents = r.json() or []

        problem = []
        for t in torrents:
            thash = t.get("hash")
            name = t.get("name") or thash
            state = (t.get("state") or "").lower()

            # Fetch trackers once: use for messages and host
            tracker_msgs = []
            tracker_host = ""
            try:
                trackers = self._trackers_for(thash)
                # messages
                for tr in trackers:
                    msg = (tr.get("msg") or "").strip()
                    if msg:
                        tracker_msgs.append(msg)
                # host
                tracker_host = self._best_tracker_host(trackers)
            except Exception:
                pass

            display_msgs = [m for m in tracker_msgs if any(k in m.lower() for k in _EXPANDED_KEYWORDS)]
            if state == "error" and not display_msgs:
                if tracker_msgs:
                    display_msgs = tracker_msgs
                else:
                    display_msgs = ["Error state"]

            if display_msgs:
                problem.append({
                    "id": thash,
                    "name": name,
                    "client_id": self.cfg.id,
                    "client_name": self.cfg.name,
                    "tracker": tracker_host,
                    "error": " | ".join(dict.fromkeys(display_msgs))[:500],
                })
        return problem

    def delete(self, hashes: List[str], delete_data: bool = False) -> Tuple[bool, str]:
        self.login()
        url = f"{self.cfg.base_url}/api/v2/torrents/delete"
        data = {"hashes": "|".join(hashes), "deleteFiles": "true" if delete_data else "false"}
        r = self.s.post(url, data=data, timeout=15)
        if r.status_code == 200:
            return True, "Deleted"
        return False, f"HTTP {r.status_code}: {r.text}"

class DelugeClient:
    """Deluge Web JSON-RPC at /json"""
    def __init__(self, cfg: ClientConfig):
        self.cfg = cfg
        self.s = requests.Session()
        self.s.verify = self.cfg.verify_ssl
        self.rpc_url = f"{self.cfg.base_url}/json"
        self._rid = 0

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

    def exists(self, h: str) -> bool:
        self.login()
        fields = ["hash"]
        result = self._rpc("web.update_ui", [fields, {}]) or {}
        tdict = result.get("torrents", {}) or {}
        return any((k or "").lower() == h.lower() for k in tdict.keys())

    def list_problem_torrents(self) -> List[Dict[str, Any]]:
        self.login()
        fields = ["name", "state", "hash", "tracker_status", "error_message", "tracker_host", "trackers"]
        result = self._rpc("web.update_ui", [fields, {}]) or {}
        tdict = result.get("torrents", {}) or {}

        problem = []
        for thash, t in tdict.items():
            name = t.get("name") or thash
            state = (t.get("state") or "").lower()
            tracker_host = (t.get("tracker_host") or "").strip()

            # Fallback: derive from trackers list if missing
            if not tracker_host:
                try:
                    for tr in (t.get("trackers") or []):
                        host = urlparse((tr or {}).get("url") or "").hostname
                        if host:
                            tracker_host = host
                            break
                except Exception:
                    pass

            msgs = []
            for key in ("tracker_status", "error_message"):
                val = (t.get(key) or "").strip()
                if not val:
                    continue
                lv = val.lower()
                if any(k in lv for k in _EXPANDED_KEYWORDS) or state == "error":
                    msgs.append(val)

            if state == "error" and not msgs:
                msgs.append("Error state")

            if msgs:
                problem.append({
                    "id": thash,
                    "name": name,
                    "client_id": self.cfg.id,
                    "client_name": self.cfg.name,
                    "tracker": tracker_host,
                    "error": " | ".join(dict.fromkeys(msgs))[:500],
                })
        return problem

    def delete(self, hashes: List[str], delete_data: bool = False) -> Tuple[bool, str]:
        self.login()
        for h in hashes:
            try:
                self._rpc("core.remove_torrent", [h, bool(delete_data)])
            except Exception as e:
                return False, f"Failed on {h}: {e}"
        return True, "Deleted"

def get_adapters(settings: Dict[str, Any]) -> Dict[str, Any]:
    adapters: Dict[str, Any] = {}
    for cfg in parse_clients(settings):
        if cfg.type.lower() == "qbittorrent":
            adapters[cfg.id] = QbitClient(cfg)
        elif cfg.type.lower() == "deluge":
            adapters[cfg.id] = DelugeClient(cfg)
    return adapters

def scan_by_client(adapters: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    per: List[Dict[str, Any]] = []
    for _, adapter in adapters.items():
        cfg = adapter.cfg
        try:
            probs = adapter.list_problem_torrents()
            rows.extend(probs)
            per.append({"id": cfg.id, "name": cfg.name, "type": cfg.type, "base_url": cfg.base_url,
                        "status": "ok", "found_count": len(probs)})
        except Exception as e:
            per.append({"id": cfg.id, "name": cfg.name, "type": cfg.type, "base_url": cfg.base_url,
                        "status": "error", "found_count": 0, "error": str(e)})
    rows.sort(key=lambda r: (r["client_name"].lower(), r["name"].lower()))
    return rows, per

app = Flask(__name__)
app.secret_key = os.environ.get("TORRENT_UI_SECRET", "dev-secret")

BASE_TEMPLATE = r"""
<!doctype html>
<html data-bs-theme="dark">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    :root { --brand-accent: #8ab4f8; }
    body { padding: 20px; }
    .header { display:flex; gap:12px; align-items:center; justify-content:flex-start; margin-bottom: 12px; }
    .brand { color: var(--brand-accent); }
    .progress-thin { height: 6px; }
    .click-x { cursor: pointer; font-weight: 700; }
    .click-x:hover { color: #ff6b6b; }
    .w-15 { width: 15%; }
    .w-20 { width: 20%; }
    .w-25 { width: 25%; }
    thead th { background-color: rgba(255,255,255,0.05); }
    .table > :not(caption) > * > * { vertical-align: middle; }
    .table { margin-bottom: 0; }
    th.sortable { cursor: pointer; user-select: none; }
    th.sortable .sort-indicator { opacity: 0.75; font-size: 0.85em; margin-left: 6px; }
    table.results-table { table-layout: fixed; }
    table.results-table th:first-child, table.results-table td:first-child { width: 32px; }
    table.results-table th.w-15, table.results-table td.col-client { width: 15%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    table.results-table th.w-20, table.results-table td.col-tracker { width: 20%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    table.results-table th.w-25, table.results-table td.col-torrent { width: 25%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    table.results-table td.error { word-break: break-word; }
  </style>
</head>
<body>
  <div class="header">
    <div class="d-flex align-items-center gap-2">
      <h3 class="m-0"><span class="brand">●</span> {{ title }}</h3>
      <button id="scanBtn" class="btn btn-primary btn-sm" type="button" title="Scan clients for issues">Scan</button>
      <button id="toggleAddClientBtn" class="btn btn-success btn-sm" type="button" title="Add a client">+ Client</button>
      <button id="closeAddClientBtn" class="btn btn-outline-secondary btn-sm d-none" type="button" title="Close add client form">Close</button>
      <span id="lastScan" class="badge text-bg-secondary ms-2">Last scanned: —</span>
      <div class="d-flex align-items-center ms-2" id="filterControls" style="gap:6px;">
        <input id="filterInput" class="form-control form-control-sm" placeholder="Filter…">
        <select id="filterField" class="form-select form-select-sm" style="width:auto;">
<option value="all" selected>All</option>
<option value="client">Client</option>
<option value="tracker">Tracker</option>
<option value="torrent">Torrent</option>
<option value="error">Error Message</option>
</select>
      </div>
    </div>
  </div>

  {% block content %}{% endblock %}

  <script>
    function escapeHtml(s) {
      const map = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
      return (s||"").toString().replace(/[&<>"']/g, c => map[c]);
    }

    document.addEventListener('DOMContentLoaded', () => {
      var sortState = { key: 'client', dir: 'asc' };

      function sortRows(rows, key, dir) {
        const arr = [...(rows||[])];
        const byClient = (a,b) => {
          const ak = (a.client_name||'').toLowerCase();
          const bk = (b.client_name||'').toLowerCase();
          if (ak !== bk) return ak < bk ? -1 : 1;
          const an = (a.name||'').toLowerCase();
          const bn = (b.name||'').toLowerCase();
          return an < bn ? -1 : an > bn ? 1 : 0;
        };
        const byTorrent = (a,b) => {
          const an = (a.name||'').toLowerCase();
          const bn = (b.name||'').toLowerCase();
          if (an !== bn) return an < bn ? -1 : 1;
          const ak = (a.client_name||'').toLowerCase();
          const bk = (b.client_name||'').toLowerCase();
          return ak < bk ? -1 : ak > bk ? 1 : 0;
        };
        const byTracker = (a,b) => {
          const at = (a.tracker||'').toLowerCase();
          const bt = (b.tracker||'').toLowerCase();
          if (at !== bt) return at < bt ? -1 : 1;
          const ak = (a.client_name||'').toLowerCase();
          const bk = (b.client_name||'').toLowerCase();
          if (ak !== bk) return ak < bk ? -1 : 1;
          const an = (a.name||'').toLowerCase();
          const bn = (b.name||'').toLowerCase();
          return an < bn ? -1 : an > bn ? 1 : 0;
        };
        if (key === 'torrent') arr.sort(byTorrent);
        else if (key === 'tracker') arr.sort(byTracker);
        else arr.sort(byClient);
        if (dir === 'desc') arr.reverse();
        return arr;
      }

      function applySortIndicators() {
        const thClient = document.getElementById('thClient');
        const thTracker = document.getElementById('thTracker');
        const thTorrent = document.getElementById('thTorrent');
        const thError = document.getElementById('thError');
        for (const th of [thClient, thTracker, thTorrent, thError]) {
          if (!th) continue;
          const key = th.dataset.sort;
          const active = key === sortState.key;
          th.setAttribute('aria-sort', active ? sortState.dir : 'none');
          const ind = th.querySelector('.sort-indicator');
          if (!ind) continue;
          ind.textContent = active ? (sortState.dir === 'asc' ? '▲' : '▼') : '↕';
          ind.title = active ? (sortState.dir === 'asc' ? 'Ascending' : 'Descending') : 'Click to sort';
        }
      }

      let lastRows = [];
      let allRows = [];
      // --- selection & delete helpers ---
      let selected = new Set();
      function onSelectionChanged(){
        selected.clear();
        document.querySelectorAll('.rowChk:checked').forEach(chk=>{
          const id = chk.dataset.id||''; const cid = chk.dataset.clientId||'';
          selected.add(JSON.stringify({id, client_id: cid}));
        });
        const n = selected.size;
        const pill = document.getElementById('deletePill');
        const selAll = document.getElementById('selectAll');
        if (selAll) selAll.checked = (n>0 && n===document.querySelectorAll('.rowChk').length);
        if (!pill) return;
        if (n===0){ pill.classList.add('d-none'); pill.textContent=''; return; }
        pill.classList.remove('d-none');
        pill.textContent = n===1 ? 'Delete' : `Delete all (${n})`;
      }
      function getSelectedList(){ return Array.from(selected).map(s=>JSON.parse(s)); }
      async function requestDeleteSelected(){
        const list = getSelectedList(); if (!list.length) return;
        const delToggle = document.getElementById('deleteModeToggle');
        const deleteFiles = !!(delToggle && delToggle.checked);
        const resp = await fetch('/delete_torrents', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({items: list, delete_files: deleteFiles})
        });
        if (!resp.ok) { alert('Delete failed: '+resp.status); return; }
        const data = await resp.json();
        const okIds = new Set((data.deleted||[]).map(x=>String(x.id)));
        if (Array.isArray(allRows)){
          allRows = allRows.filter(r=>!okIds.has(String(r.id||r.hash||r.info_hash||r.torrent_hash||r.name||'')));
        }
        renderRows(allRows);
        selected.clear(); onSelectionChanged();
      }
      document.addEventListener('click',(e)=>{
        if (e.target && e.target.id==='deletePill'){
          const n = selected.size;
          if (!n) return;
          if (confirm(n===1? 'Delete this torrent from client?' : `Delete ${n} torrents from client?`)){
            requestDeleteSelected();
          }
        }
      });
      document.addEventListener('change', (e)=>{
        if (e.target && e.target.id==='selectAll'){
          const checked = e.target.checked;
          document.querySelectorAll('.rowChk').forEach(c=>{ c.checked = checked; });
          onSelectionChanged();
        }
      });
      // --- end selection & delete helpers ---

      const scanBtn   = document.getElementById('scanBtn');
      const toggleAdd = document.getElementById('toggleAddClientBtn');
      const closeAdd  = document.getElementById('closeAddClientBtn');
      const addCard   = document.getElementById('addClientCard');
      const resultsCard = document.getElementById('resultsCard');
      const rowsTbody   = document.getElementById('rowsTbody');
      const adapterErrors = document.getElementById('adapterErrors');
      const lastScanEl = document.getElementById('lastScan');
      function setLastScan(text){ if(lastScanEl) lastScanEl.textContent = 'Last scanned: ' + (text || '—'); }

      function startPerClientUI() {
        document.querySelectorAll('[id^="status-"]').forEach(el => el.textContent = "Scanning…");
        document.querySelectorAll('[id^="bar-"]').forEach(el => el.classList.remove('d-none'));
        scanBtn?.setAttribute('disabled', 'true');
        setLastScan('Scanning…');
      }
      function endPerClientUI() {
        document.querySelectorAll('[id^="bar-"]').forEach(el => el.classList.add('d-none'));
        scanBtn?.removeAttribute('disabled');
        try { setLastScan(new Date().toLocaleString()); } catch(e){}
      }

      function renderClientResults(perClients) {
        for (const pc of (perClients || [])) {
          const statusEl = document.getElementById('status-' + pc.id);
          const barEl    = document.getElementById('bar-' + pc.id);
          if (!statusEl) continue;
          if (pc.status === 'ok') {
            statusEl.innerHTML = pc.found_count > 0
              ? '<span class="text-warning">Found ' + pc.found_count + '</span>'
              : '<span class="text-success">None</span>';
          } else {
            statusEl.innerHTML = '<span class="text-danger">Error</span> <span class="small text-muted">' + escapeHtml(pc.error||"") + '</span>';
          }
          if (barEl) barEl.classList.add('d-none');
        }
      }

      function renderErrors(errs) {
        if (!adapterErrors) return;
        adapterErrors.innerHTML = (errs && errs.length > 0)
          ? '<div class="alert alert-warning m-2"><strong>Action error:</strong><ul class="mb-0">' +
            errs.map(e => '<li>' + escapeHtml(e) + '</li>').join('') +
            '</ul></div>'
          : '';
      }

      function filterRows(rows) {
        if (!rows || !rows.length) return [];
        const q = (filterText || '').toLowerCase().trim();
        if (!q) return rows;
        const k = (filterKey || 'all').toLowerCase();
        if (k === 'all') {
          return rows.filter(r => [r.client_name, r.tracker, r.name, r.error]
            .some(v => String(v || '').toLowerCase().includes(q)));
        }
        const keyMap = { client: 'client_name', tracker: 'tracker', torrent: 'name', error: 'error' };
        const f = keyMap[k] || 'client_name';
        return rows.filter(r => ((r[f] || '').toString().toLowerCase().includes(q)));
      }

      function renderRows(rows) {
        rows = filterRows(rows || []);
        rows = sortRows(rows || [], sortState.key, sortState.dir);
        try { applySortIndicators(); } catch(e) {}
        lastRows = rows || [];
        rowsTbody.innerHTML = "";
        if (!rows || rows.length === 0) {
          resultsCard.classList.add('d-none');
          return;
        }
        resultsCard.classList.remove('d-none');
        for (const r of rows) {
          const tr = document.createElement('tr');
          tr.innerHTML = ''
            + '<td><input type="checkbox" class="rowChk" /></td>'
            + '<td class="col-client">' + escapeHtml(r.client_name||"") + '</td>'
            + '<td class="col-tracker">' + escapeHtml(r.tracker||"") + '</td>'
            + '<td class="col-torrent">' + escapeHtml(r.name||"") + '</td>'
            + '<td class="error">' + escapeHtml(r.error||"") + '</td>'
            + '<td class="text-end">'
            +   ''  // future per-row actions
            + '</td>';
          const chk = tr.querySelector('.rowChk');
          if (chk) {
            chk.dataset.id = String(r.id || r.hash || r.info_hash || r.torrent_hash || r.name || '');
            chk.dataset.clientId = String(r.client_id || r.client || r.client_name || '');
            chk.addEventListener('change', onSelectionChanged);
          }
          rowsTbody.appendChild(tr);
        }
      }

      // initialize selection state once
      try { onSelectionChanged(); } catch(e) {}

      async function doScan() {
        try {
          startPerClientUI();
          const resp = await fetch("{{ url_for('scan_json') }}", { cache: "no-store" });
          if (!resp.ok) throw new Error("HTTP " + resp.status);
          const data = await resp.json();
          renderClientResults(data.per_client || []);
          allRows = data.rows || [];
          renderRows(allRows);
          const errs = (data.per_client || []).filter(p => p.status === 'error')
                                              .map(p => (p.name + ': ' + (p.error||"Unknown error")));
          renderErrors(errs);
        } catch (e) {
          renderErrors([String(e)]);
        } finally {
          endPerClientUI();
        }
      }

      // Sorting header handlers
      const thClient = document.getElementById('thClient');
      const thTracker = document.getElementById('thTracker');
      const thTorrent = document.getElementById('thTorrent');
      const thError = document.getElementById('thError');
      function toggleSortFor(key) {
        if (sortState.key === key) {
          sortState.dir = (sortState.dir === 'asc') ? 'desc' : 'asc';
        } else {
          sortState.key = key;
          sortState.dir = 'asc';
        }
        renderRows(allRows);
      }
      thClient && thClient.addEventListener('click', () => toggleSortFor('client'));
      thTracker && thTracker.addEventListener('click', () => toggleSortFor('tracker'));
      thTorrent && thTorrent.addEventListener('click', () => toggleSortFor('torrent'));
      thError && thError.addEventListener('click', () => toggleSortFor('error'));

      // Filter controls
      const filterInput = document.getElementById('filterInput');
      const filterField = document.getElementById('filterField');
      let filterText = '';
      let filterKey = 'client';
      const applyFilterAndRender = () => {
        filterText = (filterInput && typeof filterInput.value === 'string') ? filterInput.value.trim() : '';
        filterKey = (filterField && filterField.value) ? filterField.value : 'all';
        renderRows(allRows);
      };
      filterInput && filterInput.addEventListener('input', applyFilterAndRender);
      filterField && filterField.addEventListener('change', applyFilterAndRender);

      // Buttons
      scanBtn && scanBtn.addEventListener('click', doScan);
      toggleAdd && toggleAdd.addEventListener('click', () => {
        if (!addCard) return;
        addCard.classList.toggle('d-none');
        if (!addCard.classList.contains('d-none')) {
          closeAdd && closeAdd.classList.remove('d-none');
          addCard.scrollIntoView({behavior: 'smooth', block: 'center'});
        } else {
          closeAdd && closeAdd.classList.add('d-none');
        }
      });
      closeAdd && closeAdd.addEventListener('click', () => {
        if (!addCard) return;
        addCard.classList.add('d-none');
        closeAdd.classList.add('d-none');
      });

      // No auto-scan on load
    });
  </script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

INDEX_TEMPLATE = r"""
{% extends "base.html" %}
{% block content %}

  <div class="card mb-3">
    <div class="card-header"><strong>Clients</strong></div>
    <div class="card-body p-0">
      <div class="table-responsive">
        <table class="table table-sm table-striped align-middle mb-0" id="clientsTable">
          <thead>
            <tr>
              <th class="w-25">Name</th>
              <th class="w-15">Torrent Client</th>
              <th>URL</th>
              <th class="w-25">Progress / Results</th>
              <th class="text-end" style="width: 40px;">&nbsp;</th>
            </tr>
          </thead>
          <tbody id="clientsTbody">
            {% for c in clients %}
            <tr data-client-id="{{ c.id }}">
              <td>{{ c.name }}</td>
              <td>{{ c.type }}</td>
              <td><a href="{{ c.base_url }}" target="_blank" rel="noreferrer noopener">{{ c.base_url }}</a></td>
              <td>
                <div class="small text-muted" id="status-{{ c.id }}">Idle</div>
                <div class="progress progress-thin mt-1 d-none" id="bar-{{ c.id }}">
                  <div class="progress-bar progress-bar-striped progress-bar-animated" style="width: 100%"></div>
                </div>
              </td>
              <td class="text-end">
                
              </td>
            </tr>
            {% endfor %}
            {% if clients|length == 0 %}
            <tr><td colspan="5" class="text-muted">No clients configured yet. Add one below.</td></tr>
            {% endif %}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="resultsCard" class="card d-none">
    <div class="card-header">
      <strong>Failed / Unregistered Torrents</strong>
      <button id="deletePill" class="btn btn-sm btn-outline-danger d-none ms-2"></button>
      <div class="form-check form-switch d-inline-flex align-items-center ms-3">
        <input class="form-check-input" type="checkbox" id="deleteModeToggle">
        <label class="form-check-label ms-1" for="deleteModeToggle" title="If on, client will remove torrent AND data">Also delete files</label>
      </div>
    </div>
    <div class="card-body p-0">
      <div id="adapterErrors"></div>
      <div class="table-responsive">
        <table class="table table-sm table-striped align-middle mb-0 results-table">
          <thead>
            <tr>
              <th style="width:32px" class="text-center"><input id="selectAll" type="checkbox"></th>
              <th id="thClient" class="w-15 sortable" data-sort="client" role="button" aria-sort="none">Client <span class="sort-indicator"></span></th>
              <th id="thTracker" class="w-20 sortable" data-sort="tracker" role="button" aria-sort="none">Tracker <span class="sort-indicator"></span></th>
              <th id="thTorrent" class="w-25 sortable" data-sort="torrent" role="button" aria-sort="none">Torrent <span class="sort-indicator"></span></th>
              <th id="thError" class="sortable" data-sort="error" role="button" aria-sort="none">Error Message <span class="sort-indicator"></span></th>
              <th class="text-end" style="width: 40px;">&nbsp;</th>
            </tr>
          </thead>
          <tbody id="rowsTbody"></tbody>
        </table>
      </div>
    </div>
  </div>

{% endblock %}
"""

existing_loader = app.jinja_loader
if existing_loader:
    app.jinja_loader = ChoiceLoader([existing_loader, DictLoader({"base.html": BASE_TEMPLATE})])
else:
    app.jinja_loader = DictLoader({"base.html": BASE_TEMPLATE})

@app.get("/favicon.ico")
def favicon():
    return ("", 204)

@app.route("/")
def index():
    cfgs = parse_clients(load_settings())
    return render_template_string(INDEX_TEMPLATE, title=APP_TITLE, clients=cfgs)

@app.get("/scan_json")
def scan_json():
    settings = load_settings()
    adapters = get_adapters(settings)
    rows, per_client = scan_by_client(adapters)
    return jsonify({"rows": rows, "per_client": per_client})

@app.post("/clients/add")
def add_client():
    form = request.form
    ctype = (form.get("type") or "").strip().lower()
    cid = (form.get("id") or "").strip()
    name = (form.get("name") or "").strip()
    base_url = (form.get("base_url") or "").strip().rstrip("/")
    username = form.get("username") or None
    password = form.get("password") or None
    verify_ssl = (form.get("verify_ssl", "false").lower() == "true")

    if not cid or not name or not base_url or ctype not in ("qbittorrent", "deluge"):
        return redirect(url_for("index"))

    settings = load_settings()
    if any(c.get("id") == cid for c in settings.get("clients", [])):
        return redirect(url_for("index"))

    entry = {"id": cid, "type": ctype, "name": name, "base_url": base_url, "verify_ssl": verify_ssl}
    if ctype == "qbittorrent":
        entry["username"] = username or ""
        entry["password"] = password or ""
    else:
        entry["password"] = password or ""

    settings.setdefault("clients", []).append(entry)
    save_settings(settings)
    return redirect(url_for("index"))

@app.post("/api/torrents/delete")
def api_delete_torrent():
    data = request.get_json(silent=True) or {}
    cid = data.get("client_id")
    tid = data.get("torrent_id")
    delete_files = bool(data.get("delete_files", False))
    if not cid or not tid:
        return jsonify({"ok": False, "error": "client_id and torrent_id required"}), 400

    settings = load_settings()
    adapters = get_adapters(settings)
    adapter = adapters.get(cid)
    if not adapter:
        return jsonify({"ok": False, "error": "client not found"}), 404

    try:
        exists = getattr(adapter, "exists", None)
        if callable(exists) and not exists(tid):
            return jsonify({"ok": False, "error": f"Torrent not found on client '{cid}'."}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to verify torrent existence: {e}"}), 500

    ok, msg = adapter.delete([tid], delete_data=delete_files)
    status = 200 if ok else 500
    payload = {"ok": ok, "message": msg} if ok else {"ok": False, "error": msg}
    return jsonify(payload), status

@app.post("/delete_torrents")
def delete_torrents_batch():
    """Batch deletion endpoint used by the UI selection pill."""
    data = request.get_json(silent=True) or {}
    items = data.get("items") or []
    delete_files = bool(data.get("delete_files", False))

    if not isinstance(items, list) or not items:
        return jsonify({"deleted": [], "errors": ["No items provided"]}), 400

    settings = load_settings()
    adapters = get_adapters(settings)

    deleted = []
    errors = []
    by_client: Dict[str, List[str]] = {}

    # group by client
    for it in items:
        cid = str((it or {}).get("client_id") or "").strip()
        tid = str((it or {}).get("id") or "").strip()
        if not cid or not tid:
            errors.append(f"Invalid entry: {it}")
            continue
        by_client.setdefault(cid, []).append(tid)

    for cid, hashes in by_client.items():
        adapter = adapters.get(cid)
        if not adapter:
            errors.append(f"Client not found: {cid}")
            continue
        try:
            ok, msg = adapter.delete(hashes, delete_data=delete_files)
            if ok:
                deleted.extend([{"id": h, "client_id": cid} for h in hashes])
            else:
                errors.append(f"{cid}: {msg}")
        except Exception as e:
            errors.append(f"{cid}: {e}")

    return jsonify({"deleted": deleted, "errors": errors})

@app.get("/__ping")
def ping():
    return "ok"

if __name__ == "__main__":
    if not os.path.exists(SETTINGS_PATH):
        save_settings(DEFAULT_SETTINGS.copy())
    app.run(host="0.0.0.0", port=int(os.environ.get("TORRENT_UI_PORT", "5000")), debug=True)
