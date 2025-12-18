// DOM Elements
const searchForm = document.getElementById('search-form');
const ipInput = document.getElementById('ip-input');
const searchBtn = document.getElementById('search-btn');
const btnText = searchBtn.querySelector('.btn-text');
const btnLoading = searchBtn.querySelector('.btn-loading');
const errorMessage = document.getElementById('error-message');
const resultsContainer = document.getElementById('results');

// Card elements
const cards = {
  virustotal: {
    status: document.getElementById('vt-status'),
    body: document.getElementById('vt-body')
  },
  ipinfo: {
    status: document.getElementById('ipinfo-status'),
    body: document.getElementById('ipinfo-body')
  },
  abuseipdb: {
    status: document.getElementById('abuseipdb-status'),
    body: document.getElementById('abuseipdb-body')
  }
};

// Validate IP address
function isValidIP(ip) {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
}

// Set loading state
function setLoading(loading) {
  searchBtn.disabled = loading;
  btnText.classList.toggle('hidden', loading);
  btnLoading.classList.toggle('hidden', !loading);
  ipInput.disabled = loading;
}

// Show error
function showError(message) {
  errorMessage.textContent = message;
  errorMessage.classList.remove('hidden');
}

// Hide error
function hideError() {
  errorMessage.classList.add('hidden');
}

// Reset cards to loading state
function resetCards() {
  Object.values(cards).forEach(card => {
    card.status.textContent = 'Loading';
    card.status.className = 'status-badge loading';
    card.body.innerHTML = `
      <div class="loading-placeholder">
        <span class="spinner"></span>
        <span>Fetching data...</span>
      </div>
    `;
  });
}

// Update card with data
function updateCard(source, data) {
  const card = cards[source];
  if (!card) return;

  if (data.error) {
    card.status.textContent = 'Error';
    card.status.className = 'status-badge error';
    card.body.innerHTML = `<div class="error-message">${data.error}</div>`;
    return;
  }

  card.status.textContent = 'Success';
  card.status.className = 'status-badge success';

  let html = '';

  if (source === 'virustotal') {
    html = renderVirusTotalData(data);
  } else if (source === 'ipinfo') {
    html = renderIPInfoData(data);
  } else if (source === 'abuseipdb') {
    html = renderAbuseIPDBData(data);
  }

  card.body.innerHTML = html;
}

// Render VirusTotal data
function renderVirusTotalData(data) {
  const detectionRatio = data.detections ? `${data.detections.malicious}/${data.detections.total}` : 'N/A';
  const reputationClass = getScoreClass(data.reputation, 'reputation');

  return `
    <div class="data-row">
      <span class="data-label">Detections</span>
      <span class="data-value ${data.detections?.malicious > 0 ? 'danger' : 'safe'}">${detectionRatio}</span>
    </div>
    <div class="data-row">
      <span class="data-label">Reputation</span>
      <span class="data-value ${reputationClass}">${data.reputation ?? 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">Last Analysis</span>
      <span class="data-value">${data.lastAnalysis || 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">AS Owner</span>
      <span class="data-value">${data.asOwner || 'N/A'}</span>
    </div>
  `;
}

// Render IPInfo data
function renderIPInfoData(data) {
  return `
    <div class="data-row">
      <span class="data-label">Location</span>
      <span class="data-value">${[data.city, data.region, data.country].filter(Boolean).join(', ') || 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">Organization</span>
      <span class="data-value">${data.org || 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">ASN</span>
      <span class="data-value">${data.asn || 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">Hostname</span>
      <span class="data-value">${data.hostname || 'N/A'}</span>
    </div>
  `;
}

// Render AbuseIPDB data
function renderAbuseIPDBData(data) {
  const confidenceClass = getScoreClass(data.confidenceScore, 'abuse');

  return `
    <div class="data-row">
      <span class="data-label">Confidence Score</span>
      <span class="data-value ${confidenceClass}">${data.confidenceScore !== undefined ? data.confidenceScore + '%' : 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">Total Reports</span>
      <span class="data-value ${data.totalReports > 0 ? 'warning' : ''}">${data.totalReports ?? 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">ISP</span>
      <span class="data-value">${data.isp || 'N/A'}</span>
    </div>
    <div class="data-row">
      <span class="data-label">Usage Type</span>
      <span class="data-value">${data.usageType || 'N/A'}</span>
    </div>
  `;
}

// Get class based on score
function getScoreClass(score, type) {
  if (score === undefined || score === null) return '';

  if (type === 'abuse') {
    if (score >= 50) return 'danger';
    if (score >= 20) return 'warning';
    return 'safe';
  }

  if (type === 'reputation') {
    if (score < -10) return 'danger';
    if (score < 0) return 'warning';
    return 'safe';
  }

  return '';
}

// Handle form submission
searchForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideError();

  const ip = ipInput.value.trim();

  if (!isValidIP(ip)) {
    showError('Please enter a valid IPv4 address');
    return;
  }

  setLoading(true);
  resultsContainer.classList.remove('hidden');
  resetCards();

  try {
    // Send message to background script
    const response = await chrome.runtime.sendMessage({
      action: 'lookup',
      ip: ip
    });

    if (response.error) {
      showError(response.error);
    } else {
      // Update each card with its data
      if (response.virustotal) updateCard('virustotal', response.virustotal);
      if (response.ipinfo) updateCard('ipinfo', response.ipinfo);
      if (response.abuseipdb) updateCard('abuseipdb', response.abuseipdb);
    }
  } catch (err) {
    showError('Failed to fetch data. Please try again.');
    console.error('Lookup error:', err);
  } finally {
    setLoading(false);
  }
});

// Load last search from storage
chrome.storage.local.get(['lastSearch', 'lastResults'], (data) => {
  if (data.lastSearch) {
    ipInput.value = data.lastSearch;
  }
  if (data.lastResults) {
    resultsContainer.classList.remove('hidden');
    if (data.lastResults.virustotal) updateCard('virustotal', data.lastResults.virustotal);
    if (data.lastResults.ipinfo) updateCard('ipinfo', data.lastResults.ipinfo);
    if (data.lastResults.abuseipdb) updateCard('abuseipdb', data.lastResults.abuseipdb);
  }
});
