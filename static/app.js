function escapeHtml(s) {
  const map = {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
  return (s||"").toString().replace(/[&<>"']/g, c => map[c]);
}

document.addEventListener('DOMContentLoaded', () => {
  // State variables
  let allRows = [];
  let visibleRows = [];
  let selectedRows = new Set();
  let sortKey = 'client_name';
  let sortDir = 'asc';
  let scanData = null;
  let scanning = false;
  const clientProgress = new Map(); // Track progress per client: clientId -> percent
  const clientBasePaths = new Map(); // Track detected base paths: clientId -> basePath
  let selectedClients = new Set(); // Track selected clients for deletion
  let sharedOkTorrents = []; // Store OK torrents that share files with failed ones (for modal only)
  
  // DOM elements
  const scanBtn = document.getElementById('scanBtn');
  const hideSoftToggle = document.getElementById('hideSoftToggle');
  const lastScanEl = document.getElementById('lastScan');
  const resultsCard = document.getElementById('resultsCard');
  const rowsTbody = document.getElementById('rowsTbody');
  const selectAll = document.getElementById('selectAll');
  const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
  const deleteFilesToggle = document.getElementById('deleteFilesToggle');
  const clientsTbody = document.getElementById('clientsTbody');
  const addCard = document.getElementById('addClientCard');
  const toggleAddBtn = document.getElementById('toggleAddClientBtn');
  const addForm = document.getElementById('addClientForm');
  const densityBtn = document.getElementById('densityBtn');
  const typeSelect = document.querySelector('#addClientForm select[name="type"]');
  const userInput = document.getElementById('addClientUsername');
  const passInput = document.getElementById('addClientPassword');
  const userHelp = document.getElementById('usernameHelp');
  const passHelp = document.getElementById('passwordHelp');
  const scanProgressContainer = document.getElementById('scanProgressContainer');
  const scanProgressBar = document.getElementById('scanProgressBar');
  const scanProgressText = document.getElementById('scanProgressText');
  const selectAllClients = document.getElementById('selectAllClients');
  const deleteClientsBtn = document.getElementById('deleteClientsBtn');
  const obfuscateBtn = document.getElementById('obfuscateBtn');
  
  // Initialize modal after DOM is ready
  let torrentDetailsModal = null;
  let deleteConfirmModal = null;
  let helpModal = null;
  
  const modalElement = document.getElementById('torrentDetailsModal');
  if (modalElement) {
    torrentDetailsModal = new bootstrap.Modal(modalElement);
  }
  const modalTorrentsTbody = document.getElementById('modalTorrentsTbody');
  
  const deleteModalElement = document.getElementById('deleteConfirmModal');
  if (deleteModalElement) {
    deleteConfirmModal = new bootstrap.Modal(deleteModalElement);
  }
  
  const helpModalElement = document.getElementById('helpModal');
  if (helpModalElement) {
    helpModal = new bootstrap.Modal(helpModalElement);
  }

  // Type hints for add client form
  function applyClientFieldHints() {
    const t = (typeSelect?.value || '').toLowerCase();
    if (t === 'qbittorrent') {
      if (userInput) { 
        userInput.disabled = false; 
        userInput.placeholder = 'Ex. admin'; 
      }
      if (userHelp) { 
        userHelp.textContent = 'qBittorrent Web UI default username is usually "admin".'; 
      }
      if (passInput) { 
        passInput.placeholder = 'Ex. adminadmin'; 
      }
      if (passHelp) { 
        passHelp.textContent = 'Default password on first run is often "adminadmin".'; 
      }
    } else if (t === 'deluge') {
      if (userInput) { 
        userInput.value = ''; 
        userInput.disabled = true; 
        userInput.placeholder = 'N/A for Deluge Web'; 
      }
      if (userHelp) { 
        userHelp.textContent = 'Deluge Web UI does not use a username.'; 
      }
      if (passInput) { 
        passInput.placeholder = 'Ex. deluge'; 
      }
      if (passHelp) { 
        passHelp.textContent = 'Deluge Web UI default password is usually "deluge".'; 
      }
    }
  }
  
  typeSelect?.addEventListener('change', applyClientFieldHints);
  applyClientFieldHints();

  // Collapsible clients section
  const clientsHeader = document.getElementById('clientsHeader');
  const clientsTableContainer = document.getElementById('clientsTableContainer');
  
  clientsHeader?.addEventListener('click', (e) => {
    // Don't collapse if clicking the delete button
    if (e.target.closest('#deleteClientsBtn')) {
      return;
    }
    
    const isCollapsed = clientsTableContainer?.classList.contains('collapsed');
    
    if (isCollapsed) {
      clientsTableContainer?.classList.remove('collapsed');
      clientsHeader?.classList.remove('collapsed');
    } else {
      clientsTableContainer?.classList.add('collapsed');
      clientsHeader?.classList.add('collapsed');
    }
  });

  // Density toggle
  function applyDensityFromStorage() {
    const v = localStorage.getItem('torrent_ui_density') || 'normal';
    document.body.classList.toggle('compact', v === 'compact');
    if (densityBtn) { 
      densityBtn.textContent = (v === 'compact') ? 'Comfort' : 'Compact'; 
    }
  }
  
  applyDensityFromStorage();
  
  densityBtn?.addEventListener('click', () => {
    const nowCompact = !document.body.classList.contains('compact');
    document.body.classList.toggle('compact', nowCompact);
    localStorage.setItem('torrent_ui_density', nowCompact ? 'compact' : 'normal');
    if (densityBtn) { 
      densityBtn.textContent = nowCompact ? 'Comfort' : 'Compact'; 
    }
  });

  // URL obfuscation toggle
  function applyObfuscationFromStorage() {
    const obfuscated = localStorage.getItem('torrent_ui_obfuscate') === 'true';
    document.body.classList.toggle('obfuscate-urls', obfuscated);
    updateObfuscateButton(obfuscated);
  }
  
  function updateObfuscateButton(isObfuscated) {
    if (!obfuscateBtn) return;
    
    if (isObfuscated) {
      obfuscateBtn.classList.remove('btn-outline-secondary');
      obfuscateBtn.classList.add('btn-secondary');
      obfuscateBtn.title = 'Show URLs';
      obfuscateBtn.innerHTML = `
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 16 16">
          <path d="M13.359 11.238C15.06 9.72 16 8 16 8s-3-5.5-8-5.5a7.028 7.028 0 0 0-2.79.588l.77.771A5.944 5.944 0 0 1 8 3.5c2.12 0 3.879 1.168 5.168 2.457A13.134 13.134 0 0 1 14.828 8c-.058.087-.122.183-.195.288-.335.48-.83 1.12-1.465 1.755-.165.165-.337.328-.517.486l.708.709z"/>
          <path d="M11.297 9.176a3.5 3.5 0 0 0-4.474-4.474l.823.823a2.5 2.5 0 0 1 2.829 2.829l.822.822zm-2.943 1.299.822.822a3.5 3.5 0 0 1-4.474-4.474l.823.823a2.5 2.5 0 0 0 2.829 2.829z"/>
          <path d="M3.35 5.47c-.18.16-.353.322-.518.487A13.134 13.134 0 0 0 1.172 8l.195.288c.335.48.83 1.12 1.465 1.755C4.121 11.332 5.881 12.5 8 12.5c.716 0 1.39-.133 2.02-.36l.77.772A7.029 7.029 0 0 1 8 13.5C3 13.5 0 8 0 8s.939-1.721 2.641-3.238l.708.709zm10.296 8.884-12-12 .708-.708 12 12-.708.708z"/>
        </svg>
      `;
    } else {
      obfuscateBtn.classList.remove('btn-secondary');
      obfuscateBtn.classList.add('btn-outline-secondary');
      obfuscateBtn.title = 'Hide URLs';
      obfuscateBtn.innerHTML = `
        <svg width="14" height="14" fill="currentColor" viewBox="0 0 16 16">
          <path d="M10.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0z"/>
          <path d="M0 8s3-5.5 8-5.5S16 8 16 8s-3 5.5-8 5.5S0 8 0 8zm8 3.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z"/>
        </svg>
      `;
    }
  }
  
  applyObfuscationFromStorage();
  
  obfuscateBtn?.addEventListener('click', () => {
    const nowObfuscated = !document.body.classList.contains('obfuscate-urls');
    document.body.classList.toggle('obfuscate-urls', nowObfuscated);
    localStorage.setItem('torrent_ui_obfuscate', nowObfuscated ? 'true' : 'false');
    updateObfuscateButton(nowObfuscated);
  });

  // Add client toggle
  function showAddClient(show) {
    if (!addCard) return;
    addCard.classList.toggle('d-none', !show);
    if (toggleAddBtn) { 
      toggleAddBtn.textContent = show ? 'Close' : '+ Client'; 
    }
  }
  
  toggleAddBtn?.addEventListener('click', () => {
    const isHidden = addCard?.classList.contains('d-none');
    showAddClient(!!isHidden);
  });

  // Add client form submission
  addForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fd = new FormData(addForm);
    const payload = Object.fromEntries(fd.entries());
    payload.verify_ssl = (fd.get('verify_ssl') === 'on');
    
    try {
      const res = await fetch('/clients/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) { 
        throw new Error('HTTP ' + res.status); 
      }
      
      showAddClient(false);
      location.reload();
    } catch (err) {
      alert('Failed to save client: ' + err);
    }
  });

  // Load and render clients table
  async function loadClients() {
    try {
      const res = await fetch('/settings_json');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      return (data && data.clients) || [];
    } catch (err) {
      console.error('Failed to load settings:', err);
      return [];
    }
  }

  // Handle client deletion
  async function handleDeleteClient(clientId, clientName) {
    if (!confirm(`Are you sure you want to delete client "${clientName}"?\n\nThis action cannot be undone.`)) {
      return;
    }
    
    try {
      const res = await fetch('/clients/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId })
      });
      
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || 'HTTP ' + res.status);
      }
      
      location.reload();
    } catch (err) {
      alert('Failed to delete client: ' + err.message);
    }
  }
  
  // Update select all clients checkbox state
  function updateSelectAllClientsState() {
    if (!selectAllClients) return;
    
    const allClients = Array.from(document.querySelectorAll('.client-check'));
    const total = allClients.length;
    
    if (total === 0) {
      selectAllClients.checked = false;
      selectAllClients.indeterminate = false;
      selectAllClients.disabled = true;
      return;
    }
    
    selectAllClients.disabled = false;
    const selectedCount = selectedClients.size;
    
    if (selectedCount === 0) {
      selectAllClients.checked = false;
      selectAllClients.indeterminate = false;
    } else if (selectedCount === total) {
      selectAllClients.checked = true;
      selectAllClients.indeterminate = false;
    } else {
      selectAllClients.checked = false;
      selectAllClients.indeterminate = true;
    }
  }
  
  // Update delete clients button visibility
  function updateDeleteClientsButton() {
    if (!deleteClientsBtn) return;
    
    const count = selectedClients.size;
    if (count === 0) {
      deleteClientsBtn.classList.add('d-none');
    } else {
      deleteClientsBtn.classList.remove('d-none');
      deleteClientsBtn.textContent = count === 1 ? 'Delete (1)' : `Delete (${count})`;
    }
  }

  function renderClientsTable(clients, scanProgress = false) {
    if (!clientsTbody) return;
    
    clientsTbody.innerHTML = "";
    
    for (const c of (clients || [])) {
      const tr = document.createElement('tr');
      
      // Checkbox cell
      const checkCell = document.createElement('td');
      checkCell.className = 'select-client';
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.className = 'client-check';
      checkbox.dataset.clientId = c.id;
      checkbox.checked = selectedClients.has(c.id);
      checkCell.appendChild(checkbox);
      tr.appendChild(checkCell);
      
      // Name cell
      const nameCell = document.createElement('td');
      const clientName = c.name || c.id || "(unnamed)";
      nameCell.textContent = clientName;
      
      // Add tooltip with detected base path if available
      const basePath = clientBasePaths.get(c.id);
      if (basePath) {
        nameCell.title = `Detected base path: ${basePath}`;
        nameCell.style.cursor = 'help';
      }
      
      tr.appendChild(nameCell);

      const typeCell = document.createElement('td');
      typeCell.textContent = (c.type || '').toUpperCase();
      tr.appendChild(typeCell);

      const urlCell = document.createElement('td');
      urlCell.textContent = c.base_url || '';
      tr.appendChild(urlCell);

      clientsTbody.appendChild(tr);
    }
    
    updateSelectAllClientsState();
    updateDeleteClientsButton();
  }

  // Progress functions - unified progress bar in header
  function startClientProgress(clientId) {
    // Initialize client progress tracking
    if (clientProgress.size === 0 && scanProgressContainer) {
      scanProgressContainer.classList.remove('d-none');
    }
  }

  function updateClientProgress(clientId, percent) {
    // Update this client's progress
    clientProgress.set(clientId, percent);
    
    // Ensure progress bar is visible
    if (scanProgressContainer && scanProgressContainer.classList.contains('d-none')) {
      scanProgressContainer.classList.remove('d-none');
    }
    
    // Calculate overall progress as average of all clients
    let totalPercent = 0;
    let count = 0;
    clientProgress.forEach((p) => {
      totalPercent += p;
      count++;
    });
    
    const overallPercent = count > 0 ? Math.round(totalPercent / count) : 0;
    
    // Update the unified progress bar
    if (scanProgressBar) {
      scanProgressBar.style.width = overallPercent + '%';
      scanProgressBar.style.backgroundColor = 'var(--brand-accent)';
    }
    if (scanProgressText) {
      scanProgressText.textContent = overallPercent + '%';
    }
  }

  function finishClientProgress(clientId, success = true) {
    // Mark this client as 100% complete
    clientProgress.set(clientId, 100);
    updateClientProgress(clientId, 100);
  }

  function finishAllProgress(success = true) {
    if (scanProgressBar) {
      scanProgressBar.style.width = '100%';
      scanProgressBar.style.backgroundColor = success ? '#28a745' : '#dc3545';
    }
    if (scanProgressText) {
      scanProgressText.textContent = '100%';
    }
    
    // Hide after a delay
    setTimeout(() => {
      if (scanProgressContainer) {
        scanProgressContainer.classList.add('d-none');
      }
      clientProgress.clear();
    }, 2000);
  }

  // Show torrent details modal
  function showTorrentDetailsModal(clickedTorrent) {
    if (!modalTorrentsTbody || !torrentDetailsModal) {
      console.warn('Modal elements not found');
      return;
    }
    
    let relatedTorrents = [];
    
    if (clickedTorrent.shared && clickedTorrent.shared_group_id) {
      // Show all torrents in the same shared group (both failed and OK)
      const groupId = clickedTorrent.shared_group_id;
      
      // Get failed torrents in this group
      const failedInGroup = allRows.filter(row => row.shared_group_id === groupId);
      
      // Get OK torrents in this group
      const okInGroup = sharedOkTorrents.filter(row => row.shared_group_id === groupId);
      
      relatedTorrents = [...failedInGroup, ...okInGroup];
    } else {
      // Not shared - show only this torrent
      relatedTorrents = [clickedTorrent];
    }
    
    // Clear and populate modal table
    modalTorrentsTbody.innerHTML = '';
    
    relatedTorrents.forEach(torrent => {
      const tr = document.createElement('tr');
      
      // Highlight the clicked torrent
      if (torrent._key === clickedTorrent._key) {
        tr.classList.add('highlight');
      }
      
      // Client
      const clientCell = document.createElement('td');
      clientCell.textContent = torrent.client_name;
      tr.appendChild(clientCell);
      
      // Torrent Name
      const nameCell = document.createElement('td');
      const classLabel = torrent.class === 'ok' ? 
        '<span style="color: #28a745; font-weight: 600;">[OK]</span> ' : 
        `<span style="color: ${torrent.class === 'hard' ? '#dc3545' : '#ffc107'}; font-weight: 600;">[${torrent.class.toUpperCase()}]</span> `;
      nameCell.innerHTML = classLabel + escapeHtml(torrent.name);
      tr.appendChild(nameCell);
      
      // Save Path
      const pathCell = document.createElement('td');
      pathCell.textContent = torrent.save_path;
      tr.appendChild(pathCell);
      
      // Shared File indicator
      const sharedCell = document.createElement('td');
      const isShared = torrent.shared_group_id ? true : false;
      const sharedCount = torrent.shared_count || 1;
      sharedCell.innerHTML = `<span class="shared-indicator ${isShared ? 'yes' : 'no'}">${isShared ? `Yes (${sharedCount})` : 'No'}</span>`;
      sharedCell.style.textAlign = 'center';
      tr.appendChild(sharedCell);
      
      modalTorrentsTbody.appendChild(tr);
    });
    
    // Show the modal
    torrentDetailsModal.show();
  }
  
  // Normalize path for comparison (case-insensitive, consistent separators)
  function normalizePath(path) {
    if (!path) return '';
    return path.toLowerCase().replace(/\\/g, '/').replace(/\/+$/, '');
  }

  // Render results as table
  function renderResults(data) {
    if (!data || !data.clients || data.clients.length === 0) {
      resultsCard?.classList.add('d-none');
      return;
    }
    
    allRows = [];
    sharedOkTorrents = []; // Clear shared OK torrents
    
    for (const client of data.clients) {
      // Add failed torrents to allRows
      for (const item of (client.items || [])) {
        allRows.push({
          ...item,
          client_name: client.client_label || client.client_id,
          _key: `${item.client_id}|${item.hash}`
        });
      }
      
      // Store shared OK torrents separately (not displayed in main table)
      for (const item of (client.shared_ok_torrents || [])) {
        sharedOkTorrents.push({
          ...item,
          client_name: client.client_label || client.client_id,
          _key: `${item.client_id}|${item.hash}`
        });
      }
    }
    
    applyFilters();
    resultsCard?.classList.remove('d-none');
  }
  
  function applyFilters() {
    const hideSoft = hideSoftToggle?.checked || false;
    
    if (hideSoft) {
      visibleRows = allRows.filter(r => r.class === 'hard');
    } else {
      visibleRows = allRows;
    }
    
    renderTable();
  }
  
  function renderTable() {
    if (!rowsTbody) return;
    
    const sorted = [...visibleRows].sort((a, b) => {
      const va = (a[sortKey] || '').toString().toLowerCase();
      const vb = (b[sortKey] || '').toString().toLowerCase();
      if (va < vb) return sortDir === 'asc' ? -1 : 1;
      if (va > vb) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    
    let html = '';
    for (const row of sorted) {
      const checked = selectedRows.has(row._key) ? 'checked' : '';
      const classChip = `<span class="class-chip-inline ${row.class}">${row.class.toUpperCase()}</span>`;
      
      let sharedBadge = '';
      if (row.shared && row.shared_count > 1) {
        sharedBadge = `<span class="shared-badge-inline">Shared ×${row.shared_count}</span>`;
      }
      
      const errorMsg = row.reasons && row.reasons.length > 0 
        ? escapeHtml(row.reasons.join(', ')) 
        : escapeHtml(row.first_bad_tracker || 'Unknown error');
      
      html += `
        <tr title="Click to view torrent details">
          <td class="select">
            <input type="checkbox" class="row-check" data-key="${escapeHtml(row._key)}" ${checked}>
          </td>
          <td>${escapeHtml(row.client_name)}</td>
          <td>${escapeHtml(row.first_bad_tracker || '')}</td>
          <td>${classChip}${escapeHtml(row.name)}${sharedBadge}</td>
          <td>${errorMsg}</td>
        </tr>
      `;
    }
    
    rowsTbody.innerHTML = html;
    updateSelectAllState();
    updateDeleteButton();
  }
  
  function updateSelectAllState() {
    if (!selectAll) return;
    
    const total = visibleRows.length;
    if (total === 0) {
      selectAll.checked = false;
      selectAll.indeterminate = false;
      selectAll.disabled = true;
      return;
    }
    
    selectAll.disabled = false;
    const selectedCount = Array.from(selectedRows).filter(key => 
      visibleRows.some(r => r._key === key)
    ).length;
    
    if (selectedCount === 0) {
      selectAll.checked = false;
      selectAll.indeterminate = false;
    } else if (selectedCount === total) {
      selectAll.checked = true;
      selectAll.indeterminate = false;
    } else {
      selectAll.checked = false;
      selectAll.indeterminate = true;
    }
  }
  
  function updateDeleteButton() {
    if (!deleteSelectedBtn) return;
    
    const count = selectedRows.size;
    if (count === 0) {
      deleteSelectedBtn.classList.add('d-none');
    } else {
      deleteSelectedBtn.classList.remove('d-none');
      deleteSelectedBtn.textContent = count === 1 ? 'Delete (1)' : `Delete all (${count})`;
    }
  }
  
  // Sorting functions
  function toggleSort(key, thId) {
    if (sortKey === key) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      sortKey = key;
      sortDir = 'asc';
    }
    
    document.querySelectorAll('.results-table th').forEach(th => {
      const text = th.textContent || '';
      th.textContent = text.replace(/[▲▼]/g, '').trim();
    });
    
    const th = document.getElementById(thId);
    if (th) {
      const arrow = sortDir === 'asc' ? ' ▲' : ' ▼';
      th.textContent = th.textContent + arrow;
    }
    
    renderTable();
  }
  
  function setupSorting() {
    document.getElementById('thClient')?.addEventListener('click', () => {
      toggleSort('client_name', 'thClient');
    });
    
    document.getElementById('thTracker')?.addEventListener('click', () => {
      toggleSort('first_bad_tracker', 'thTracker');
    });
    
    document.getElementById('thTorrent')?.addEventListener('click', () => {
      toggleSort('name', 'thTorrent');
    });
    
    document.getElementById('thError')?.addEventListener('click', () => {
      toggleSort('reasons', 'thError');
    });
  }
  
  // Checkbox selection
  rowsTbody?.addEventListener('change', (e) => {
    if (e.target && e.target.classList.contains('row-check')) {
      const key = e.target.dataset.key;
      if (e.target.checked) {
        selectedRows.add(key);
      } else {
        selectedRows.delete(key);
      }
      updateSelectAllState();
      updateDeleteButton();
    }
  });
  
  // Click on torrent row to show details modal
  rowsTbody?.addEventListener('click', (e) => {
    // Ignore clicks on checkboxes and the checkbox column
    if (e.target.type === 'checkbox' || e.target.closest('.select')) {
      return;
    }
    
    // Find the clicked row
    const row = e.target.closest('tr');
    if (!row) return;
    
    // Get the checkbox to find the key
    const checkbox = row.querySelector('.row-check');
    if (!checkbox) return;
    
    const key = checkbox.dataset.key;
    const clickedTorrent = visibleRows.find(r => r._key === key);
    
    if (clickedTorrent && torrentDetailsModal) {
      showTorrentDetailsModal(clickedTorrent);
    }
  });
  
  selectAll?.addEventListener('change', () => {
    const checked = selectAll.checked;
    visibleRows.forEach(row => {
      if (checked) {
        selectedRows.add(row._key);
      } else {
        selectedRows.delete(row._key);
      }
    });
    
    rowsTbody?.querySelectorAll('.row-check').forEach(cb => {
      cb.checked = checked;
    });
    
    updateDeleteButton();
  });
  
  // Bulk delete - show confirmation modal
  deleteSelectedBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    const count = selectedRows.size;
    if (count === 0) return;
    
    const deleteFiles = deleteFilesToggle?.checked || false;
    
    // Check if any selected torrents are soft
    const hasSoftTorrents = Array.from(selectedRows).some(key => {
      const torrent = allRows.find(r => r._key === key);
      return torrent && torrent.class === 'soft';
    });
    
    // Check if any selected torrents are shared
    const sharedTorrents = [];
    selectedRows.forEach(key => {
      const torrent = allRows.find(r => r._key === key);
      if (torrent && torrent.shared && torrent.shared_count > 1) {
        sharedTorrents.push(torrent);
      }
    });
    
    // Set modal message
    const action = deleteFiles ? 'torrents and all files' : 'torrents only (files kept)';
    const deleteConfirmMessage = document.getElementById('deleteConfirmMessage');
    if (deleteConfirmMessage) {
      deleteConfirmMessage.textContent = `Delete ${count} ${action}? This action cannot be undone.`;
    }
    
    // Show/hide soft warning
    const softWarning = document.getElementById('softWarning');
    if (softWarning) {
      softWarning.classList.toggle('d-none', !hasSoftTorrents);
    }
    
    // Show/hide shared warning
    const sharedWarning = document.getElementById('sharedWarning');
    const sharedWarningText = document.getElementById('sharedWarningText');
    if (sharedWarning && sharedWarningText) {
      if (sharedTorrents.length > 0) {
        const totalSharedWith = sharedTorrents.reduce((sum, t) => sum + (t.shared_count - 1), 0);
        sharedWarningText.textContent = `${sharedTorrents.length} of the selected torrents share files with ${totalSharedWith} other torrent(s). Deleting may affect these other torrents.`;
        sharedWarning.classList.remove('d-none');
      } else {
        sharedWarning.classList.add('d-none');
      }
    }
    
    // Show modal
    if (deleteConfirmModal) {
      deleteConfirmModal.show();
    } else {
      console.error('Delete confirmation modal not initialized');
    }
  });
  
  // Confirm delete button in modal
  const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
  if (confirmDeleteBtn) {
    confirmDeleteBtn.addEventListener('click', async () => {
      const count = selectedRows.size;
      if (count === 0) return;
      
      const deleteFiles = deleteFilesToggle?.checked || false;
      
      // Hide the modal
      if (deleteConfirmModal) {
        deleteConfirmModal.hide();
      }
      
      const itemsToDelete = [];
      selectedRows.forEach(key => {
        const [client_id, hash] = key.split('|');
        itemsToDelete.push({ client_id, hash });
      });
      
      try {
        deleteSelectedBtn.disabled = true;
        deleteSelectedBtn.textContent = 'Deleting...';
        
        const errors = [];
        for (const item of itemsToDelete) {
          try {
            const res = await fetch('/api/torrents/delete', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                client_id: item.client_id,
                torrent_id: item.hash,
                delete_files: deleteFiles
              })
            });
            
            if (!res.ok) {
              const data = await res.json();
              errors.push(`${item.hash}: ${data.error}`);
            }
          } catch (err) {
            errors.push(`${item.hash}: ${err.message}`);
          }
        }
        
        if (errors.length > 0) {
          alert(`Some deletions failed:\n${errors.join('\n')}`);
        }
        
        await performScan();
        
      } catch (err) {
        alert('Delete failed: ' + err.message);
      } finally {
        deleteSelectedBtn.disabled = false;
        selectedRows.clear();
        updateDeleteButton();
      }
    });
  } else {
    console.error('Confirm delete button not found');
  }
  
  // Help button
  const helpBtn = document.getElementById('helpBtn');
  helpBtn?.addEventListener('click', () => {
    if (helpModal) {
      helpModal.show();
    }
  });
  
  // Client checkbox selection
  clientsTbody?.addEventListener('change', (e) => {
    if (e.target && e.target.classList.contains('client-check')) {
      const clientId = e.target.dataset.clientId;
      if (e.target.checked) {
        selectedClients.add(clientId);
      } else {
        selectedClients.delete(clientId);
      }
      updateSelectAllClientsState();
      updateDeleteClientsButton();
    }
  });
  
  // Select all clients
  selectAllClients?.addEventListener('change', () => {
    const checked = selectAllClients.checked;
    const allCheckboxes = document.querySelectorAll('.client-check');
    
    allCheckboxes.forEach(cb => {
      cb.checked = checked;
      const clientId = cb.dataset.clientId;
      if (checked) {
        selectedClients.add(clientId);
      } else {
        selectedClients.delete(clientId);
      }
    });
    
    updateDeleteClientsButton();
  });
  
  // Delete selected clients
  deleteClientsBtn?.addEventListener('click', async () => {
    const count = selectedClients.size;
    if (count === 0) return;
    
    const clientNames = [];
    selectedClients.forEach(clientId => {
      const checkbox = document.querySelector(`.client-check[data-client-id="${clientId}"]`);
      if (checkbox) {
        const row = checkbox.closest('tr');
        const nameCell = row?.querySelector('td:nth-child(2)');
        if (nameCell) {
          clientNames.push(nameCell.textContent);
        }
      }
    });
    
    const namesList = clientNames.join(', ');
    if (!confirm(`Are you sure you want to delete ${count} client(s)?\n\n${namesList}\n\nThis action cannot be undone.`)) {
      return;
    }
    
    try {
      deleteClientsBtn.disabled = true;
      deleteClientsBtn.textContent = 'Deleting...';
      
      const errors = [];
      for (const clientId of selectedClients) {
        try {
          const res = await fetch('/clients/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: clientId })
          });
          
          if (!res.ok) {
            const data = await res.json();
            errors.push(`${clientId}: ${data.error}`);
          }
        } catch (err) {
          errors.push(`${clientId}: ${err.message}`);
        }
      }
      
      if (errors.length > 0) {
        alert(`Some deletions failed:\n${errors.join('\n')}`);
      }
      
      location.reload();
      
    } catch (err) {
      alert('Delete failed: ' + err.message);
      deleteClientsBtn.disabled = false;
      updateDeleteClientsButton();
    }
  });

  // Scan functionality with SSE
  async function performScan() {
    if (scanning) return;
    
    scanning = true;
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    
    try {
      const clients = await loadClients();
      
      if (clients.length === 0) {
        alert('No clients configured. Add a client first.');
        scanning = false;
        scanBtn.disabled = false;
        scanBtn.textContent = 'Scan All';
        return;
      }
      
      renderClientsTable(clients, false);
      
      // Always fetch both hard and soft - filtering happens client-side with the toggle
      const levels = 'hard,soft';
      
      console.log('Starting SSE scan with levels:', levels);
      
      const eventSource = new EventSource(`/scan_stream?levels=${levels}`);
      let hasReceivedData = false;
      let scanCompleted = false;
      
      eventSource.onopen = () => {
        console.log('SSE connection opened');
      };
      
      eventSource.onmessage = (event) => {
        hasReceivedData = true;
        console.log('SSE message received:', event.data);
        
        try {
          const data = JSON.parse(event.data);
          console.log('Parsed SSE data:', data);
          
          switch (data.type) {
            case 'start':
              console.log(`Starting scan of ${data.total_clients} clients`);
              // Show progress bar and initialize
              if (scanProgressContainer) {
                scanProgressContainer.classList.remove('d-none');
              }
              if (scanProgressBar) {
                scanProgressBar.style.width = '0%';
                scanProgressBar.style.backgroundColor = 'var(--brand-accent)';
              }
              if (scanProgressText) {
                scanProgressText.textContent = '0%';
              }
              clientProgress.clear();
              break;
              
            case 'progress':
              console.log(`[SSE] Progress event: client_id="${data.client_id}", current=${data.current}, total=${data.total}, percent=${data.percent}`);
              updateClientProgress(data.client_id, data.percent);
              break;
              
            case 'client_complete':
              console.log(`Client ${data.client_id} completed (${data.completed}/${data.total})`);
              finishClientProgress(data.client_id, true);
              break;
              
            case 'complete':
              console.log('All clients completed, rendering results');
              scanCompleted = true;
              
              scanData = data;
              
              // Store detected base paths
              if (scanData.clients) {
                clientBasePaths.clear();
                scanData.clients.forEach(client => {
                  if (client.detected_base_path) {
                    clientBasePaths.set(client.client_id, client.detected_base_path);
                    console.log(`[${client.client_id}] Base path: ${client.detected_base_path}`);
                  }
                });
              }
              
              if (lastScanEl && scanData.completed_at) {
                const time = new Date(scanData.completed_at).toLocaleString();
                lastScanEl.textContent = `Last: ${time}`;
              }
              
              finishAllProgress(true);
              renderResults(scanData);
              renderClientsTable(clients, false);
              
              eventSource.close();
              
              scanning = false;
              scanBtn.disabled = false;
              scanBtn.textContent = 'Scan All';
              break;
              
            case 'error':
              console.error('Scan error:', data.message);
              alert('Scan failed: ' + data.message);
              finishAllProgress(false);
              eventSource.close();
              
              scanning = false;
              scanBtn.disabled = false;
              scanBtn.textContent = 'Scan All';
              break;
          }
        } catch (err) {
          console.error('Error parsing SSE data:', err, 'Raw data:', event.data);
        }
      };
      
      eventSource.onerror = (err) => {
        console.error('SSE connection error:', err);
        eventSource.close();
        
        if (scanning && !scanCompleted) {
          if (!hasReceivedData) {
            alert('Failed to connect to scan server. Check console for details.');
          } else {
            alert('Connection to server lost during scan');
          }
          finishAllProgress(false);
          
          scanning = false;
          scanBtn.disabled = false;
          scanBtn.textContent = 'Scan All';
        }
      };
      
    } catch (err) {
      console.error('Scan failed:', err);
      alert('Scan failed: ' + err.message);
      finishAllProgress(false);
      
      scanning = false;
      scanBtn.disabled = false;
      scanBtn.textContent = 'Scan All';
    }
  }

  // Event handlers
  hideSoftToggle?.addEventListener('change', () => {
    if (scanData) {
      applyFilters();
    }
  });

  scanBtn?.addEventListener('click', performScan);

  // Initial load
  (async () => {
    const clients = await loadClients();
    renderClientsTable(clients, false);
    setupSorting();
  })();
});
