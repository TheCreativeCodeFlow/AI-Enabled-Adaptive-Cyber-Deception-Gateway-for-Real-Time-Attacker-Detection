/**
 * Cyber Deception Gateway — Preserved Auth State Helper
 */

const TOKEN_KEY = 'operator_token';
const OPERATOR_KEY = 'operator_data';

export const auth = {
  getToken() {
    return localStorage.getItem(TOKEN_KEY) || '';
  },

  getOperator() {
    try {
      const data = localStorage.getItem(OPERATOR_KEY);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  },

  setSession(token, operator) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(OPERATOR_KEY, JSON.stringify(operator));
  },

  clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(OPERATOR_KEY);
  },

  isAuthenticated() {
    return !!this.getToken();
  },

  isAdmin() {
    const op = this.getOperator();
    return op?.role === 'admin';
  },
};
