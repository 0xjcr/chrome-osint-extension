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

    // Inject stealth scripts BEFORE navigation to mask automation detection
    await page.injectStealthScripts();

    // Navigate to VirusTotal IP page
    const url = `https://www.virustotal.com/gui/ip-address/${ip}`;
    await page.goto(url, { timeout: 30000 });

    // VirusTotal is a heavy SPA - wait for content to actually render
    // First, wait a base amount for initial JS to load
    await page.sleep(3000);

    // Helper function to traverse shadow DOM and get all text content
    // VirusTotal uses Polymer web components with shadow DOM
    const getAllTextContent = `
      (function getAllTextContent(root = document.body) {
        let text = '';
        function traverse(node) {
          if (node.shadowRoot) {
            traverse(node.shadowRoot);
          }
          if (node.nodeType === Node.TEXT_NODE) {
            text += node.textContent + ' ';
          }
          if (node.childNodes) {
            for (const child of node.childNodes) {
              traverse(child);
            }
          }
        }
        traverse(root);
        return text;
      })()
    `;

    // Then poll for content to appear (up to 15 seconds total)
    // Must check shadow DOM since VirusTotal uses web components
    let attempts = 0;
    const maxAttempts = 12;
    while (attempts < maxAttempts) {
      const textLength = await page.evaluate(getAllTextContent + '.length');
      if (textLength > 100) break;
      await page.sleep(1000);
      attempts++;
    }

    // Try to extract data using various selectors
    // VirusTotal's DOM structure can vary, so we try multiple approaches
    const data = await page.evaluate(`
      (function() {
        // Helper to traverse shadow DOM
        function getAllTextContent(root = document.body) {
          let text = '';
          function traverse(node) {
            if (node.shadowRoot) {
              traverse(node.shadowRoot);
            }
            if (node.nodeType === Node.TEXT_NODE) {
              text += node.textContent + ' ';
            }
            if (node.childNodes) {
              for (const child of node.childNodes) {
                traverse(child);
              }
            }
          }
          traverse(root);
          return text;
        }

        const pageText = getAllTextContent();
        // Normalize whitespace for easier pattern matching
        const normalizedText = pageText.replace(/\\s+/g, ' ').trim();

        const result = {
          detections: null,
          reputation: null,
          lastAnalysis: null,
          asOwner: null,
          country: null,
          warning: null
        };

        // Check for CAPTCHA or challenge page (use normalized text for matching)
        // Be very specific to avoid false positives - only trigger on actual CAPTCHA pages
        const hasCaptcha = document.querySelector('.g-recaptcha[data-sitekey], #captcha-container');

        if (hasCaptcha) {
          result.warning = 'CAPTCHA or verification required - please visit VirusTotal directly';
          return result;
        }

        // Check if page loaded properly (use normalized length)
        if (normalizedText.length < 500) {
          result.warning = 'Page did not load properly - VirusTotal may be blocking automated access';
          return result;
        }

        // Try to find detection stats using multiple patterns
        // VT shows format like "0 / 94" or "1/94 security vendors"
        const detectionPatterns = [
          /(\\d+)\\s*\\/\\s*(\\d+)\\s*(?:security\\s+vendors?|engines?)/i,
          /(\\d+)\\s*\\/\\s*(\\d+)/,  // Simple X/Y format
          /(\\d+)\\s+security\\s+vendors?.*(?:flagged|detected|malicious)/i,
          /flagged.*?(\\d+)\\s*\\/\\s*(\\d+)/i,
          /(\\d+)\\s*malicious/i
        ];

        for (const pattern of detectionPatterns) {
          const match = normalizedText.match(pattern);
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
          const match = normalizedText.match(pattern);
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
          const match = normalizedText.match(pattern);
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

        // Try to find AS owner - VT format: "AS 15169 ( GOOGLE )"
        const asPatterns = [
          /AS\\s*(\\d+)\\s*\\(\\s*([^)]+)\\s*\\)/i,  // AS 15169 ( GOOGLE )
          /AS\\s*(\\d+)\\s+([A-Za-z][A-Za-z0-9\\s]{2,30})/,
          /autonomous\\s+system[:\\s]+([^\\n]+)/i,
          /ASN[:\\s]+([^\\n]+)/i
        ];

        for (const pattern of asPatterns) {
          const match = normalizedText.match(pattern);
          if (match) {
            // If we matched the parentheses format, use group 2 (name), otherwise group 1
            result.asOwner = (match[2] || match[1]).trim();
            break;
          }
        }

        // Try to find country - VT shows country code like "US" after AS info
        // Format: "AS 15169 ( GOOGLE ) US"
        const countryPatterns = [
          /\\(\\s*[A-Z]+\\s*\\)\\s+([A-Z]{2})\\s/,  // After AS owner in parens: ") US "
          /country[:\\s]+([A-Za-z\\s]+)/i,
          /located\\s+in[:\\s]+([A-Za-z\\s]+)/i
        ];

        for (const pattern of countryPatterns) {
          const match = normalizedText.match(pattern);
          if (match) {
            result.country = match[1].trim().split(' ')[0];
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
