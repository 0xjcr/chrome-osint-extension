/**
 * CDP (Chrome DevTools Protocol) Library
 * A Playwright-like abstraction for browser automation via chrome.debugger
 */

/**
 * Creates a new page (tab) with CDP debugging attached
 * @returns {Promise<Page>} A Page instance for browser automation
 */
export async function createPage() {
  // Create a new tab
  const tab = await chrome.tabs.create({
    url: 'about:blank',
    active: false
  });

  const page = new Page(tab.id);
  await page._attach();
  return page;
}

/**
 * Page class - represents a browser tab with CDP capabilities
 */
export class Page {
  constructor(tabId) {
    this.tabId = tabId;
    this.target = { tabId };
    this._attached = false;
    this._eventListeners = new Map();
  }

  /**
   * Attach the debugger to this tab
   */
  async _attach() {
    if (this._attached) return;

    await chrome.debugger.attach(this.target, '1.3');
    this._attached = true;

    // Enable necessary domains
    await this._sendCommand('Page.enable');
    await this._sendCommand('Runtime.enable');
    await this._sendCommand('DOM.enable');
  }

  /**
   * Send a CDP command
   * @param {string} method - CDP method name
   * @param {object} params - Command parameters
   * @returns {Promise<any>} Command result
   */
  async _sendCommand(method, params = {}) {
    if (!this._attached) {
      throw new Error('Debugger not attached');
    }

    try {
      return await chrome.debugger.sendCommand(this.target, method, params);
    } catch (err) {
      console.error(`CDP command failed: ${method}`, err);
      throw err;
    }
  }

  /**
   * Navigate to a URL and wait for the page to load
   * @param {string} url - The URL to navigate to
   * @param {object} options - Navigation options
   * @returns {Promise<void>}
   */
  async goto(url, options = {}) {
    const { timeout = 30000, waitUntil = 'load' } = options;

    // Create a promise that resolves when the page loads
    const loadPromise = new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        chrome.debugger.onEvent.removeListener(listener);
        reject(new Error(`Navigation timeout after ${timeout}ms`));
      }, timeout);

      const listener = (source, method, params) => {
        if (source.tabId !== this.tabId) return;

        if (method === 'Page.loadEventFired' || method === 'Page.domContentEventFired') {
          clearTimeout(timeoutId);
          chrome.debugger.onEvent.removeListener(listener);
          resolve();
        }
      };

      chrome.debugger.onEvent.addListener(listener);
    });

    // Navigate to the URL
    await this._sendCommand('Page.navigate', { url });

    // Wait for load
    await loadPromise;

    // Give the page a moment to settle (for JS-rendered content)
    await this.sleep(500);
  }

  /**
   * Wait for a selector to appear in the DOM
   * @param {string} selector - CSS selector
   * @param {object} options - Wait options
   * @returns {Promise<void>}
   */
  async waitForSelector(selector, options = {}) {
    const { timeout = 10000, interval = 100 } = options;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const exists = await this.evaluate(`!!document.querySelector('${selector.replace(/'/g, "\\'")}')`);
      if (exists) return;
      await this.sleep(interval);
    }

    throw new Error(`Timeout waiting for selector: ${selector}`);
  }

  /**
   * Execute JavaScript in the page context
   * @param {string} expression - JavaScript expression to evaluate
   * @returns {Promise<any>} The result of the expression
   */
  async evaluate(expression) {
    const result = await this._sendCommand('Runtime.evaluate', {
      expression: expression,
      returnByValue: true,
      awaitPromise: true
    });

    if (result.exceptionDetails) {
      throw new Error(`Evaluation failed: ${result.exceptionDetails.text}`);
    }

    return result.result?.value;
  }

  /**
   * Get text content of an element
   * @param {string} selector - CSS selector
   * @returns {Promise<string|null>} Text content or null if not found
   */
  async getText(selector) {
    const escapedSelector = selector.replace(/'/g, "\\'");
    return await this.evaluate(`
      (function() {
        const el = document.querySelector('${escapedSelector}');
        return el ? el.textContent.trim() : null;
      })()
    `);
  }

  /**
   * Get multiple text contents
   * @param {string} selector - CSS selector
   * @returns {Promise<string[]>} Array of text contents
   */
  async getTextAll(selector) {
    const escapedSelector = selector.replace(/'/g, "\\'");
    return await this.evaluate(`
      (function() {
        const els = document.querySelectorAll('${escapedSelector}');
        return Array.from(els).map(el => el.textContent.trim());
      })()
    `);
  }

  /**
   * Get an attribute value from an element
   * @param {string} selector - CSS selector
   * @param {string} attribute - Attribute name
   * @returns {Promise<string|null>} Attribute value or null
   */
  async getAttribute(selector, attribute) {
    const escapedSelector = selector.replace(/'/g, "\\'");
    return await this.evaluate(`
      (function() {
        const el = document.querySelector('${escapedSelector}');
        return el ? el.getAttribute('${attribute}') : null;
      })()
    `);
  }

  /**
   * Check if an element exists
   * @param {string} selector - CSS selector
   * @returns {Promise<boolean>}
   */
  async exists(selector) {
    const escapedSelector = selector.replace(/'/g, "\\'");
    return await this.evaluate(`!!document.querySelector('${escapedSelector}')`);
  }

  /**
   * Click on an element
   * @param {string} selector - CSS selector
   * @returns {Promise<void>}
   */
  async click(selector) {
    const escapedSelector = selector.replace(/'/g, "\\'");
    await this.evaluate(`
      (function() {
        const el = document.querySelector('${escapedSelector}');
        if (el) el.click();
      })()
    `);
  }

  /**
   * Type text into an input
   * @param {string} selector - CSS selector
   * @param {string} text - Text to type
   * @returns {Promise<void>}
   */
  async type(selector, text) {
    const escapedSelector = selector.replace(/'/g, "\\'");
    const escapedText = text.replace(/'/g, "\\'");
    await this.evaluate(`
      (function() {
        const el = document.querySelector('${escapedSelector}');
        if (el) {
          el.value = '${escapedText}';
          el.dispatchEvent(new Event('input', { bubbles: true }));
        }
      })()
    `);
  }

  /**
   * Get the page HTML
   * @returns {Promise<string>}
   */
  async content() {
    return await this.evaluate('document.documentElement.outerHTML');
  }

  /**
   * Get the page URL
   * @returns {Promise<string>}
   */
  async url() {
    return await this.evaluate('window.location.href');
  }

  /**
   * Sleep for a specified duration
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<void>}
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Detach debugger and close the tab
   * @returns {Promise<void>}
   */
  async close() {
    if (this._attached) {
      try {
        await chrome.debugger.detach(this.target);
      } catch (err) {
        // Ignore detach errors (tab may already be closed)
      }
      this._attached = false;
    }

    try {
      await chrome.tabs.remove(this.tabId);
    } catch (err) {
      // Ignore remove errors (tab may already be closed)
    }
  }
}
