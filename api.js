/**
 * AGENTIX Client-Side API Key Validation
 *
 * Usage:
 *   import { validateKey } from './api.js';
 *   const result = await validateKey('ak_xxx');
 *   // { valid: true, user: { id, name, email }, createdAt }
 *   // { valid: false, error: 'Invalid API key' }
 *
 * Or use directly in browser console:
 *   AGENTIX_API.validate('ak_xxx').then(console.log)
 */

(function (root) {
  function getUsers() {
    return JSON.parse(localStorage.getItem('agentix_users') || '[]');
  }

  function validateKey(apiKey) {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (!apiKey || typeof apiKey !== 'string') {
          resolve({ valid: false, error: 'API key is required' });
          return;
        }
        const users = getUsers();
        const user = users.find((u) => u.apiKey === apiKey);
        if (!user) {
          resolve({ valid: false, error: 'Invalid API key' });
          return;
        }
        resolve({
          valid: true,
          user: { id: user.id, name: user.name, email: user.email },
          createdAt: user.createdAt,
        });
      }, 50);
    });
  }

  const api = { validateKey, validate: validateKey };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.AGENTIX_API = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
