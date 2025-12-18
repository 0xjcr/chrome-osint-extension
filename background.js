/**
 * Background Service Worker
 * Orchestrates the OSINT data collection from multiple sources
 */

import { scrapeVirusTotal } from './scrapers/virustotal.js';
import { scrapeIPInfo } from './scrapers/ipinfo.js';
import { scrapeAbuseIPDB } from './scrapers/abuseipdb.js';

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'lookup') {
    handleLookup(request.ip)
      .then(results => sendResponse(results))
      .catch(err => sendResponse({ error: err.message }));

    // Return true to indicate we'll send a response asynchronously
    return true;
  }
});

/**
 * Handle IP lookup request
 * Runs all scrapers in parallel and aggregates results
 * @param {string} ip - The IP address to look up
 * @returns {Promise<object>} Aggregated results from all sources
 */
async function handleLookup(ip) {
  console.log(`Starting OSINT lookup for IP: ${ip}`);

  // Store the search query
  await chrome.storage.local.set({ lastSearch: ip });

  // Run all scrapers in parallel
  const [virustotalResult, ipinfoResult, abuseipdbResult] = await Promise.allSettled([
    scrapeVirusTotal(ip),
    scrapeIPInfo(ip),
    scrapeAbuseIPDB(ip)
  ]);

  // Process results
  const results = {
    virustotal: processResult(virustotalResult, 'VirusTotal'),
    ipinfo: processResult(ipinfoResult, 'IPInfo'),
    abuseipdb: processResult(abuseipdbResult, 'AbuseIPDB')
  };

  // Store results
  await chrome.storage.local.set({ lastResults: results });

  console.log('OSINT lookup complete:', results);

  return results;
}

/**
 * Process a Promise.allSettled result
 * @param {PromiseSettledResult} result - The settled promise result
 * @param {string} source - Name of the source for error messages
 * @returns {object} The value or an error object
 */
function processResult(result, source) {
  if (result.status === 'fulfilled') {
    return result.value;
  } else {
    console.error(`${source} scraper failed:`, result.reason);
    return {
      error: `Failed to fetch data from ${source}: ${result.reason?.message || 'Unknown error'}`
    };
  }
}

// Log when the service worker starts
console.log('PostEvent OSINT background service worker initialized');
