/**
 * VirusTotal Scraper
 * Extracts threat intelligence data from VirusTotal IP address page
 */

import { createPage } from '../lib/cdp.js';

/**
 * Scrape VirusTotal for IP address information
 * @param {string} ip - The IP address to look up
 * @returns {Promise<object>} Scraped data
 */
export async function scrapeVirusTotal(ip) {
  let page = null;

  try {
    page = await createPage();

    // Navigate to VirusTotal IP page
    const url = `https://www.virustotal.com/gui/ip-address/${ip}`;
    await page.goto(url, { timeout: 30000 });

    // Wait for the page to load (VirusTotal is a heavy SPA, needs more time)
    await page.sleep(6000);

    // Try to extract data using various selectors
    // VirusTotal's DOM structure can vary, so we try multiple approaches
    const data = await page.evaluate(`
      (function() {
        const result = {
          detections: null,
          reputation: null,
          lastAnalysis: null,
          asOwner: null,
          country: null,
          warning: null
        };

        const pageText = document.body.innerText;

        // Check for CAPTCHA or challenge page
        if (pageText.toLowerCase().includes('captcha') ||
            pageText.toLowerCase().includes('verify you are human') ||
            pageText.toLowerCase().includes('unusual traffic') ||
            document.querySelector('.captchaContainer, [class*="captcha"]')) {
          result.warning = 'CAPTCHA or verification required - please visit VirusTotal directly';
          return result;
        }

        // Check if page loaded properly
        if (pageText.length < 500) {
          result.warning = 'Page did not load properly - VirusTotal may be blocking automated access';
          return result;
        }

        // Try to find detection stats using multiple patterns
        // Pattern 1: Look for "X / Y" format (malicious / total)
        const detectionPatterns = [
          /(\\d+)\\s*\\/\\s*(\\d+)\\s*(?:security\\s+vendors?|engines?)/i,
          /(\\d+)\\s+security\\s+vendors?.*(?:flagged|detected|malicious)/i,
          /flagged.*?(\\d+)\\s*\\/\\s*(\\d+)/i,
          /(\\d+)\\s*malicious/i
        ];

        for (const pattern of detectionPatterns) {
          const match = pageText.match(pattern);
          if (match) {
            if (match[2]) {
              result.detections = {
                malicious: parseInt(match[1]),
                total: parseInt(match[2])
              };
            } else {
              result.detections = {
                malicious: parseInt(match[1]),
                total: null
              };
            }
            break;
          }
        }

        // Look for detection in specific elements
        if (!result.detections) {
          const widgets = document.querySelectorAll('vt-ui-detections-widget, [class*="detection"], [class*="positives"], [class*="malicious"]');
          widgets.forEach(el => {
            if (!result.detections) {
              const text = el.textContent;
              const match = text.match(/(\\d+)\\s*\\/\\s*(\\d+)/);
              if (match) {
                result.detections = {
                  malicious: parseInt(match[1]),
                  total: parseInt(match[2])
                };
              }
            }
          });
        }

        // Try to find reputation score
        const repPatterns = [
          /reputation[:\\s]+(-?\\d+)/i,
          /community\\s+score[:\\s]+(-?\\d+)/i
        ];

        for (const pattern of repPatterns) {
          const match = pageText.match(pattern);
          if (match) {
            result.reputation = parseInt(match[1]);
            break;
          }
        }

        // Look for reputation in specific elements
        if (result.reputation === null) {
          const repElements = document.querySelectorAll('[class*="reputation"], [class*="score"], vt-ui-community-score');
          repElements.forEach(el => {
            if (result.reputation === null) {
              const text = el.textContent;
              const match = text.match(/(-?\\d+)/);
              if (match && text.toLowerCase().includes('reputation') || text.toLowerCase().includes('score')) {
                result.reputation = parseInt(match[1]);
              }
            }
          });
        }

        // Try to find last analysis date
        const datePatterns = [
          /last\\s+analysis[:\\s]+([\\d-]+)/i,
          /analyzed[:\\s]+([\\d-]+)/i,
          /(\\d{4}-\\d{2}-\\d{2})/
        ];

        for (const pattern of datePatterns) {
          const match = pageText.match(pattern);
          if (match) {
            result.lastAnalysis = match[1].substring(0, 10);
            break;
          }
        }

        // Look for time elements
        if (!result.lastAnalysis) {
          const timeEls = document.querySelectorAll('time, [datetime]');
          timeEls.forEach(el => {
            if (!result.lastAnalysis) {
              const datetime = el.getAttribute('datetime') || el.textContent;
              if (datetime && datetime.match(/\\d{4}/)) {
                result.lastAnalysis = datetime.trim().substring(0, 10);
              }
            }
          });
        }

        // Try to find AS owner
        const asPatterns = [
          /AS\\s*(\\d+)\\s+([A-Za-z][^\\n]{2,50})/,
          /autonomous\\s+system[:\\s]+([^\\n]+)/i,
          /ASN[:\\s]+([^\\n]+)/i
        ];

        for (const pattern of asPatterns) {
          const match = pageText.match(pattern);
          if (match) {
            result.asOwner = (match[2] || match[1]).trim();
            break;
          }
        }

        // Try to find country
        const countryPatterns = [
          /country[:\\s]+([A-Za-z\\s]+)/i,
          /located\\s+in[:\\s]+([A-Za-z\\s]+)/i
        ];

        for (const pattern of countryPatterns) {
          const match = pageText.match(pattern);
          if (match) {
            result.country = match[1].trim().split('\\n')[0];
            break;
          }
        }

        // Look for country flags
        if (!result.country) {
          const flagEl = document.querySelector('[class*="flag"], img[alt*="flag"]');
          if (flagEl) {
            const alt = flagEl.getAttribute('alt') || flagEl.getAttribute('title') || '';
            if (alt) result.country = alt.replace(/flag/i, '').trim();
          }
        }

        // Check if we got any useful data
        const hasData = result.detections || result.reputation !== null || result.asOwner || result.country;
        if (!hasData && !result.warning) {
          result.warning = 'Limited data extracted - VirusTotal may require login or page structure changed';
        }

        return result;
      })()
    `);

    return data;

  } catch (err) {
    console.error('VirusTotal scraper error:', err);
    return {
      error: err.message || 'Failed to scrape VirusTotal'
    };
  } finally {
    if (page) {
      await page.close();
    }
  }
}
