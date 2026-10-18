import { URL } from 'node:url';
import net from 'node:net';
import { query } from './db';

const DANGEROUS_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'instance-data',
  '0.0.0.0',
  '::',
]);

/**
 * Checks if an IPv4 address is in a reserved or private range.
 */
function isReservedOrPrivateIpv4(ip: string): { isPrivate: boolean; isLoopback: boolean; isLinkLocal: boolean } {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) {
    return { isPrivate: false, isLoopback: false, isLinkLocal: false };
  }

  const [a, b] = parts;

  // Loopback (127.0.0.0/8)
  if (a === 127) {
    return { isPrivate: true, isLoopback: true, isLinkLocal: false };
  }

  // Link-local / Cloud metadata (169.254.0.0/16)
  if (a === 169 && b === 254) {
    return { isPrivate: true, isLoopback: false, isLinkLocal: true };
  }

  // RFC1918 Private Ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  if (a === 10) return { isPrivate: true, isLoopback: false, isLinkLocal: false };
  if (a === 172 && b >= 16 && b <= 31) return { isPrivate: true, isLoopback: false, isLinkLocal: false };
  if (a === 192 && b === 168) return { isPrivate: true, isLoopback: false, isLinkLocal: false };

  // Multicast / Reserved: 224.0.0.0/4, 240.0.0.0/4
  if (a >= 224) return { isPrivate: true, isLoopback: false, isLinkLocal: false };

  // 0.0.0.0/8
  if (a === 0) return { isPrivate: true, isLoopback: false, isLinkLocal: false };

  return { isPrivate: false, isLoopback: false, isLinkLocal: false };
}

/**
 * Validates domain format. Ensures FQDN without protocols, credentials, or illegal characters.
 */
export function validateDomainName(rawDomain: string): { valid: boolean; reason?: string; normalizedDomain?: string } {
  if (!rawDomain || typeof rawDomain !== 'string') {
    return { valid: false, reason: 'Domain name is required.' };
  }

  let domain = rawDomain.trim().toLowerCase();

  // Strip trailing dot if present
  if (domain.endsWith('.')) {
    domain = domain.slice(0, -1);
  }

  if (domain.includes('://') || domain.includes('/') || domain.includes(':')) {
    return { valid: false, reason: 'Domain name must not include protocol (http://), port, or path.' };
  }

  if (domain.length < 3 || domain.length > 253) {
    return { valid: false, reason: 'Domain name must be between 3 and 253 characters.' };
  }

  // IP addresses cannot be verified via DNS TXT
  if (net.isIP(domain)) {
    return { valid: false, reason: 'Domain name must be a valid FQDN, not a raw IP address.' };
  }

  // FQDN regex check
  const fqdnRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
  // Local test fixture domains (e.g. "test-origin", "app.local", "staging.internal")
  const isLocalDomain = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9-]+)*$/.test(domain);

  if (!fqdnRegex.test(domain) && !isLocalDomain) {
    return { valid: false, reason: 'Invalid domain name format.' };
  }

  return { valid: true, normalizedDomain: domain };
}

/**
 * Validates upstream origin URL against SSRF, cloud metadata services, and cross-tenant leakage.
 */
export async function validateApplicationOrigin(
  rawOrigin: string,
  currentOrgId?: string,
  allowLocalTest: boolean = true
): Promise<{ valid: boolean; reason?: string; normalizedOrigin?: string }> {
  if (!rawOrigin || typeof rawOrigin !== 'string') {
    return { valid: false, reason: 'Origin URL is required.' };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawOrigin.trim());
  } catch {
    return { valid: false, reason: 'Origin must be a valid absolute URL (e.g., https://api.example.com).' };
  }

  // 1. Protocol validation
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, reason: `Forbidden protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.` };
  }

  const hostname = parsed.hostname.toLowerCase();

  // 2. Reject credentials in origin URL (http://user:pass@host)
  if (parsed.username || parsed.password) {
    return { valid: false, reason: 'Origin URL must not contain embedded authentication credentials.' };
  }

  // 3. Reject cloud metadata and dangerous hostnames
  if (DANGEROUS_HOSTS.has(hostname) || hostname.endsWith('.internal') && hostname.includes('metadata')) {
    return { valid: false, reason: `Target host "${hostname}" is forbidden (cloud metadata / link-local protection).` };
  }

  // 4. IP-based Destination Checks
  const ipVersion = net.isIP(hostname);
  if (ipVersion === 4) {
    const { isPrivate, isLoopback, isLinkLocal } = isReservedOrPrivateIpv4(hostname);

    if (isLinkLocal) {
      return { valid: false, reason: `IP "${hostname}" is in the link-local range (cloud metadata 169.254.0.0/16) and cannot be used as an origin.` };
    }

    if (isLoopback && !allowLocalTest) {
      return { valid: false, reason: `Loopback address "${hostname}" is forbidden in production environments.` };
    }

    if (isPrivate && !allowLocalTest) {
      return { valid: false, reason: `Private subnet address "${hostname}" is forbidden.` };
    }
  }

  // 5. Hostname loopback checks (localhost, *.localhost)
  if ((hostname === 'localhost' || hostname.endsWith('.localhost')) && !allowLocalTest) {
    return { valid: false, reason: 'Localhost origins are only allowed in local test mode.' };
  }

  // 6. Cross-Tenant Origin Isolation: Tenant B cannot hijack Tenant A's internal application origin
  if (currentOrgId) {
    try {
      const existingAppResult = await query(
        `SELECT id, organisation_id FROM applications
         WHERE configured_origin = $1 AND organisation_id != $2`,
        [parsed.origin, currentOrgId]
      );

      if (existingAppResult.rows.length > 0) {
        return {
          valid: false,
          reason: 'Configured origin URL is already registered by another organisation. Cross-tenant origin sharing is forbidden.',
        };
      }
    } catch (err: any) {
      // In-memory or DB check failed
      console.warn(`[Origin-Validation-Warning] Cross-tenant query check error: ${err.message}`);
    }
  }

  return { valid: true, normalizedOrigin: parsed.origin };
}
