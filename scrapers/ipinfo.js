/**
 * IPInfo Scraper
 * Extracts geolocation and network information from ipinfo.io
 */

import { createPage } from '../lib/cdp.js';

/**
 * Scrape IPInfo for IP address information
 * @param {string} ip - The IP address to look up
 * @returns {Promise<object>} Scraped data
 */
export async function scrapeIPInfo(ip) {
  let page = null;

  try {
    page = await createPage();

    // Navigate to IPInfo page
    const url = `https://ipinfo.io/${ip}`;
    await page.goto(url, { timeout: 30000 });

    // Wait for content to load
    await page.sleep(2000);

    // Extract data from the page
    const data = await page.evaluate(`
      (function() {
        const result = {
          city: null,
          region: null,
          country: null,
          org: null,
          asn: null,
          hostname: null,
          postal: null,
          timezone: null,
          loc: null,
          warning: null
        };

        // Primary method: Extract from JSON-LD structured data
        const jsonLdScripts = document.querySelectorAll('script[type="application/ld+json"]');
        for (const script of jsonLdScripts) {
          try {
            const json = JSON.parse(script.textContent);

            // Extract from contentLocation (address info)
            if (json.contentLocation) {
              const loc = json.contentLocation;
              if (loc.address) {
                // IPInfo uses non-standard field names
                // streetAddress contains "City, State" format
                const streetAddr = loc.address.streetAddress || '';
                if (streetAddr && streetAddr.includes(',')) {
                  const parts = streetAddr.split(',');
                  result.city = parts[0].trim();
                  if (parts[1]) result.region = parts[1].trim();
                }
                // addressRegion sometimes has the full "City, State"
                if (!result.region && loc.address.addressRegion) {
                  const regionParts = loc.address.addressRegion.split(',');
                  if (regionParts.length > 1) {
                    result.region = regionParts[1].trim();
                  } else {
                    result.region = loc.address.addressRegion;
                  }
                }
                result.country = loc.address.addressCountry || result.country;
                // Note: IPInfo uses "PostalCode" (capital P), not "postalCode"
                result.postal = loc.address.PostalCode || loc.address.postalCode || result.postal;
              }
              if (loc.geo) {
                result.loc = loc.geo.latitude + ',' + loc.geo.longitude;
              }
            }

            // Extract company/organization name from variableMeasured array
            // IPInfo stores company info as "Company Name (domain.com)" in variableMeasured
            if (json.variableMeasured && Array.isArray(json.variableMeasured)) {
              // Find entry with pattern "Company Name (domain.com)" - typically has .com, .net, etc
              const companyEntry = json.variableMeasured.find(v =>
                typeof v === 'string' && /\\([a-z0-9.-]+\\.[a-z]{2,}\\)$/i.test(v)
              );
              if (companyEntry) {
                // Extract "Google LLC" from "Google LLC (google.com)"
                result.org = companyEntry.split('(')[0].trim();
              }

              // Also extract ASN from variableMeasured - format "AS15169 Google LLC"
              const asnEntry = json.variableMeasured.find(v =>
                typeof v === 'string' && /^AS\\d+/.test(v)
              );
              if (asnEntry) {
                const asnMatch = asnEntry.match(/^(AS\\d+)/);
                if (asnMatch) result.asn = asnMatch[1];
              }

              // Extract hostname - first entry that looks like a domain
              const hostnameEntry = json.variableMeasured.find(v =>
                typeof v === 'string' && /^[a-z0-9.-]+\\.[a-z]{2,}$/i.test(v) && !v.includes('(')
              );
              if (hostnameEntry) {
                result.hostname = hostnameEntry;
              }
            }

            // Fallback: try company field or name
            if (!result.org && json.company && json.company.name) {
              result.org = json.company.name;
            }

            // Look for nested organization data
            if (json.provider && json.provider.name && !result.org) {
              result.org = json.provider.name;
            }
          } catch (e) {}
        }

        // Secondary method: Parse page text for remaining fields
        const pageText = document.body.innerText;

        // Helper to extract value after a label
        function findValue(label) {
          const regex = new RegExp(label + '[:\\\\s]+([^\\\\n]+)', 'i');
          const match = pageText.match(regex);
          if (match) {
            let value = match[1].trim();
            // Clean up - stop at common delimiters
            value = value.split(/\\t|\\s{2,}/)[0].trim();
            return value || null;
          }
          return null;
        }

        // Extract ASN (pattern like AS15169)
        if (!result.asn) {
          const asnMatch = pageText.match(/AS(\\d+)/);
          if (asnMatch) {
            result.asn = 'AS' + asnMatch[1];
          }
        }

        // Extract hostname
        if (!result.hostname) {
          const hostnameMatch = pageText.match(/Hostname[:\\s]+([a-zA-Z0-9.-]+)/i);
          if (hostnameMatch) {
            result.hostname = hostnameMatch[1];
          }
        }

        // Extract timezone
        if (!result.timezone) {
          const tzMatch = pageText.match(/Timezone[:\\s]+([A-Za-z_\\/]+)/i);
          if (tzMatch) {
            result.timezone = tzMatch[1];
          }
        }

        // Fallback text extraction for missing fields
        if (!result.city) result.city = findValue('City');
        if (!result.region) result.region = findValue('Region');
        if (!result.country) result.country = findValue('Country');
        if (!result.org) result.org = findValue('Company');
        if (!result.org) result.org = findValue('Org');
        if (!result.postal) result.postal = findValue('Postal');

        // Check if we got minimal data
        const hasData = result.city || result.country || result.org || result.asn;
        if (!hasData) {
          result.warning = 'Limited data extracted - page structure may have changed';
        }

        return result;
      })()
    `);

    return data;

  } catch (err) {
    console.error('IPInfo scraper error:', err);
    return {
      error: err.message || 'Failed to scrape IPInfo'
    };
  } finally {
    if (page) {
      await page.close();
    }
  }
}
