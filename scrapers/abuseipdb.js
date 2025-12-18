/**
 * AbuseIPDB Scraper
 * Extracts abuse/threat intelligence data from AbuseIPDB
 */

import { createPage } from '../lib/cdp.js';

/**
 * Scrape AbuseIPDB for IP address information
 * @param {string} ip - The IP address to look up
 * @returns {Promise<object>} Scraped data
 */
export async function scrapeAbuseIPDB(ip) {
  let page = null;

  try {
    page = await createPage();

    // Navigate to AbuseIPDB check page
    const url = `https://www.abuseipdb.com/check/${ip}`;
    await page.goto(url, { timeout: 30000 });

    // Wait for content to load (AbuseIPDB may need more time)
    await page.sleep(3000);

    // Extract data from the page
    const data = await page.evaluate(`
      (function() {
        const result = {
          confidenceScore: null,
          totalReports: null,
          lastReported: null,
          isp: null,
          usageType: null,
          domain: null,
          countryCode: null,
          warning: null
        };

        const pageText = document.body.innerText;

        // Check for "not found" or "not reported" first
        const notReported = pageText.toLowerCase().includes('was not found') ||
                           pageText.toLowerCase().includes('has not been reported') ||
                           pageText.toLowerCase().includes('was found in our database');

        if (pageText.toLowerCase().includes('was not found in our database')) {
          result.confidenceScore = 0;
          result.totalReports = 0;
          result.warning = 'IP not found in AbuseIPDB database';
          return result;
        }

        // Look for confidence score - AbuseIPDB shows "X% Confidence of Abuse"
        // Try multiple patterns
        let confidenceFound = false;

        // Pattern 1: "X%" standalone in large text (the gauge shows just the number)
        const gaugeEl = document.querySelector('.gauge-text, [class*="gauge"] .text, .abuse-score');
        if (gaugeEl) {
          const gaugeMatch = gaugeEl.textContent.match(/(\\d+)/);
          if (gaugeMatch) {
            result.confidenceScore = parseInt(gaugeMatch[1]);
            confidenceFound = true;
          }
        }

        // Pattern 2: Look for percentage in prominent display
        if (!confidenceFound) {
          const percentMatch = pageText.match(/(\\d+)%\\s*(?:confidence|abuse)/i) ||
                              pageText.match(/confidence[^\\d]*(\\d+)%/i) ||
                              pageText.match(/abuse[^\\d]*(\\d+)%/i);
          if (percentMatch) {
            result.confidenceScore = parseInt(percentMatch[1]);
            confidenceFound = true;
          }
        }

        // Pattern 3: Look in the page for standalone percentage near "abuse"
        if (!confidenceFound) {
          const allText = pageText.replace(/\\s+/g, ' ');
          const abuseSection = allText.match(/abuse[^.]*?(\\d+)\\s*%/i);
          if (abuseSection) {
            result.confidenceScore = parseInt(abuseSection[1]);
          }
        }

        // Look for total reports - "reported X times"
        const reportsPatterns = [
          /reported\\s+(\\d+)\\s*times?/i,
          /been\\s+reported\\s+(\\d+)/i,
          /(\\d+)\\s+reports?/i,
          /total\\s+reports?[:\\s]*(\\d+)/i
        ];
        for (const pattern of reportsPatterns) {
          const match = pageText.match(pattern);
          if (match) {
            result.totalReports = parseInt(match[1]);
            break;
          }
        }

        // Extract from well-structured table elements
        // AbuseIPDB uses a table with th/td pairs
        const tableRows = document.querySelectorAll('table tr');
        tableRows.forEach(row => {
          const th = row.querySelector('th');
          const td = row.querySelector('td');
          if (th && td) {
            const label = th.textContent.trim().toLowerCase();
            const value = td.textContent.trim();

            if (label === 'isp' && !result.isp) {
              result.isp = value;
            }
            if (label === 'usage type' && !result.usageType) {
              result.usageType = value;
            }
            if (label === 'domain name' && !result.domain) {
              result.domain = value;
            }
            if (label === 'country' && !result.countryCode) {
              // Remove flag emoji and clean up
              result.countryCode = value.replace(/[\\u{1F1E0}-\\u{1F1FF}]/gu, '').trim();
            }
            if (label === 'hostname(s)' && !result.hostname) {
              result.hostname = value.split('\\n')[0].trim();
            }
          }
        });

        // Fallback: extract from page text using patterns
        function extractAfterLabel(label) {
          const regex = new RegExp(label + '[:\\\\s]+([^\\\\n]+)', 'i');
          const match = pageText.match(regex);
          if (match) {
            let value = match[1].trim();
            // Clean up - get first meaningful part
            value = value.split(/\\t|\\s{3,}/)[0].trim();
            return value || null;
          }
          return null;
        }

        if (!result.isp) result.isp = extractAfterLabel('ISP');
        if (!result.usageType) result.usageType = extractAfterLabel('Usage Type');
        if (!result.domain) result.domain = extractAfterLabel('Domain');

        // Look for country - often shown with flag
        const flagImg = document.querySelector('img[src*="flag"], img[alt*="flag"], .flag');
        if (flagImg) {
          const alt = flagImg.getAttribute('alt') || '';
          const title = flagImg.getAttribute('title') || '';
          if (alt) result.countryCode = alt.replace(/flag/i, '').trim();
          else if (title) result.countryCode = title;
        }

        // Fallback country extraction
        if (!result.countryCode) {
          const countryMatch = pageText.match(/Country[:\\s]+([A-Za-z\\s]+)/i);
          if (countryMatch) {
            result.countryCode = countryMatch[1].trim().split('\\n')[0];
          }
        }

        // Last reported date
        const lastReportMatch = pageText.match(/last\\s+reported[:\\s]+([^\\n]+)/i) ||
                               pageText.match(/most\\s+recent\\s+report[:\\s]+([^\\n]+)/i);
        if (lastReportMatch) {
          result.lastReported = lastReportMatch[1].trim().substring(0, 50);
        }

        // Check if we got minimal data
        const hasData = result.confidenceScore !== null || result.totalReports !== null || result.isp;
        if (!hasData) {
          result.warning = 'Limited data extracted - page may require interaction or structure changed';
        }

        return result;
      })()
    `);

    return data;

  } catch (err) {
    console.error('AbuseIPDB scraper error:', err);
    return {
      error: err.message || 'Failed to scrape AbuseIPDB'
    };
  } finally {
    if (page) {
      await page.close();
    }
  }
}
