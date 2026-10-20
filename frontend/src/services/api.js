/**
 * Cyber Deception Gateway — Preserved API Client
 *
 * Centralizes all backend REST and gateway communications.
 * Preserves all routes, types, and integration methods for subsequent stages.
 */

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:4000';
const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';

/**
 * Standard HTTP request wrapper with authorization and JSON parsing.
 */
async function request(url, options = {}) {
  const token = localStorage.getItem('operator_token');
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await fetch(url, { ...options, headers });
  const isJson = response.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const errorMsg = (data && data.error) || (data && data.message) || response.statusText;
    const error = new Error(errorMsg);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

export const api = {
  // Service health checks
  async getBackendHealth() {
    return request(`${BACKEND_URL}/health`);
  },

  async getGatewayHealth() {
    return request(`${GATEWAY_URL}/health`);
  },

  // Authentication
  async login(username, password) {
    return request(`${BACKEND_URL}/api/auth/login`, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  },

  async register(username, email, password, role = 'analyst') {
    return request(`${BACKEND_URL}/api/auth/register`, {
      method: 'POST',
      body: JSON.stringify({ username, email, password, role }),
    });
  },

  async getCurrentOperator() {
    return request(`${BACKEND_URL}/api/auth/me`);
  },

  async logout() {
    return request(`${BACKEND_URL}/api/auth/logout`, { method: 'POST' });
  },

  // Multi-tenant Organization management
  async getOrganisations() {
    return request(`${BACKEND_URL}/api/orgs`);
  },

  async createOrganisation(name, slug) {
    return request(`${BACKEND_URL}/api/orgs`, {
      method: 'POST',
      body: JSON.stringify({ name, slug }),
    });
  },

  // Protected Application management
  async getApplications(orgId) {
    return request(`${BACKEND_URL}/api/orgs/${orgId}/apps`);
  },

  async registerApplication(orgId, payload) {
    return request(`${BACKEND_URL}/api/orgs/${orgId}/apps`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async verifyDomain(orgId, appId) {
    return request(`${BACKEND_URL}/api/orgs/${orgId}/apps/${appId}/verify`, {
      method: 'POST',
    });
  },

  async activateApplication(orgId, appId) {
    return request(`${BACKEND_URL}/api/orgs/${orgId}/apps/${appId}/activate`, {
      method: 'POST',
    });
  },

  async updateProtection(orgId, appId, settings) {
    return request(`${BACKEND_URL}/api/orgs/${orgId}/apps/${appId}/protection`, {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
  },

  // Security Events & Telemetry
  async getEvents(orgId, params = {}) {
    const qs = new URLSearchParams(params).toString();
    return request(`${BACKEND_URL}/api/orgs/${orgId}/events${qs ? `?${qs}` : ''}`);
  },

  async getEventsSummary(orgId) {
    return request(`${BACKEND_URL}/api/orgs/${orgId}/events/summary`);
  },

  async getAuditLogs(orgId) {
    return request(`${BACKEND_URL}/api/audit${orgId ? `?orgId=${orgId}` : ''}`);
  },

  // Platform Administration (Cross-tenant)
  async getAdminOverview() {
    return request(`${BACKEND_URL}/api/admin/overview`);
  },

  async getAdminOrganisations() {
    return request(`${BACKEND_URL}/api/admin/organisations`);
  },

  async getAdminApplications() {
    return request(`${BACKEND_URL}/api/admin/applications`);
  },

  async getAdminUsers() {
    return request(`${BACKEND_URL}/api/admin/users`);
  },

  async updateAdminUserRole(userId, role) {
    return request(`${BACKEND_URL}/api/admin/users/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role }),
    });
  },

  async getAdminAuditLogs() {
    return request(`${BACKEND_URL}/api/admin/audit`);
  },

  async getAdminSystemHealth() {
    return request(`${BACKEND_URL}/api/admin/system/health`);
  },

  // Gateway Controls
  async toggleEmergencyBypass(enabled) {
    return request(`${GATEWAY_URL}/api/gateway/emergency-bypass`, {
      method: 'POST',
      body: JSON.stringify({ enabled }),
    });
  },

  async getGatewayMetrics() {
    return request(`${GATEWAY_URL}/api/gateway/metrics`);
  },
};

export { BACKEND_URL, GATEWAY_URL };
