/**
 * Error Types and Classification
 * Provides consistent error handling across the extension
 */

export const ErrorTypes = {
  TIMEOUT: 'TIMEOUT',
  NETWORK: 'NETWORK',
  BLOCKED: 'BLOCKED',
  PARSE: 'PARSE',
  DEBUGGER: 'DEBUGGER',
  UNKNOWN: 'UNKNOWN'
};

/**
 * Classify an error based on its message
 * @param {Error} error - The error to classify
 * @returns {string} The error type
 */
export function classifyError(error) {
  const message = error.message?.toLowerCase() || '';

  if (message.includes('timeout')) return ErrorTypes.TIMEOUT;
  if (message.includes('net::') || message.includes('network')) return ErrorTypes.NETWORK;
  if (message.includes('captcha') || message.includes('blocked') || message.includes('403')) return ErrorTypes.BLOCKED;
  if (message.includes('parse') || message.includes('json')) return ErrorTypes.PARSE;
  if (message.includes('debugger') || message.includes('attach')) return ErrorTypes.DEBUGGER;

  return ErrorTypes.UNKNOWN;
}

/**
 * Get a user-friendly error message based on error type and source
 * @param {string} errorType - The classified error type
 * @param {string} source - The source name (e.g., 'VirusTotal')
 * @returns {string} A user-friendly message
 */
export function getUserFriendlyMessage(errorType, source) {
  const messages = {
    TIMEOUT: `${source} took too long to respond`,
    NETWORK: `Could not connect to ${source}`,
    BLOCKED: `${source} is blocking automated access`,
    PARSE: `Failed to read ${source} data`,
    DEBUGGER: 'Browser automation failed - try reloading the extension',
    UNKNOWN: `${source} lookup failed`
  };
  return messages[errorType] || messages.UNKNOWN;
}
