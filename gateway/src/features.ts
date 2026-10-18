import { Request } from 'express';

// In-memory sliding window frequency tracker
// Tracks client request timestamps within a 10-second rolling window
const IP_REQUEST_TIMESTAMPS = new Map<string, number[]>();
const WINDOW_MS = 10000;

export interface ExtractedFeatures {
  request_id: string;
  method: string;
  path: string;
  path_depth: number;
  path_length: number;
  path_entropy: number;
  has_suspicious_keywords: boolean;
  suspicious_keyword_count: number;
  query_param_count: number;
  query_entropy: number;
  header_count: number;
  missing_expected_headers: string[];
  suspicious_header_patterns: string[];
  body_size: number;
  content_type?: string;
  request_frequency: number;
  auth_failure_count: number;
  decoy_interactions: number;
  client_ip: string;
}

const SUSPICIOUS_PATH_KEYWORDS = [
  'admin',
  'union',
  'select',
  'eval',
  'cmd',
  'passwd',
  '.env',
  'wp-',
  'shell',
  'exec',
  'php',
  'actuator',
  'root',
  'shadow',
  'install',
  'setup',
];

const SCANNER_TOOL_PATTERNS = [
  'sqlmap',
  'nikto',
  'gobuster',
  'dirbuster',
  'nmap',
  'masscan',
  'wpscan',
  'hydra',
  'metasploit',
];

/**
 * Computes Shannon entropy of an ASCII string.
 */
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0.0;
  const len = str.length;
  const frequencies = new Map<string, number>();

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0.0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 100) / 100;
}

/**
 * Updates in-memory sliding window and computes request frequency for client IP.
 */
function recordAndCalculateFrequency(clientIp: string): number {
  const now = Date.now();
  let timestamps = IP_REQUEST_TIMESTAMPS.get(clientIp) || [];

  // Evict timestamps older than rolling window
  timestamps = timestamps.filter((t) => now - t <= WINDOW_MS);
  timestamps.push(now);
  IP_REQUEST_TIMESTAMPS.set(clientIp, timestamps);

  // Return requests per second in window
  const windowSeconds = Math.max(WINDOW_MS / 1000, 1);
  return Math.round((timestamps.length / windowSeconds) * 100) / 100;
}

/**
 * Extracts derived security metadata features from an incoming HTTP request.
 * Guaranteed zero leakage of raw bodies, cookies, or authorization tokens.
 */
export function extractFeatures(
  req: Request,
  requestId: string,
  bodySize: number = 0
): ExtractedFeatures {
  const cleanPath = req.path || '/';
  const rawQuery = req.url.includes('?') ? req.url.split('?')[1] : '';
  const clientIp =
    (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  // 1. Path metrics
  const segments = cleanPath.split('/').filter(Boolean);
  const pathDepth = segments.length;
  const pathLength = cleanPath.length;
  const pathEntropy = calculateEntropy(cleanPath);

  // 2. Suspicious keywords
  const lowerPath = cleanPath.toLowerCase();
  let keywordCount = 0;
  for (const kw of SUSPICIOUS_PATH_KEYWORDS) {
    if (lowerPath.includes(kw)) {
      keywordCount++;
    }
  }

  // 3. Query metrics
  const queryParamCount = Object.keys(req.query || {}).length;
  const queryEntropy = calculateEntropy(rawQuery);

  // 4. Header inspection (Presence & Patterns, NOT values)
  const headerKeys = Object.keys(req.headers).map((k) => k.toLowerCase());
  const headerCount = headerKeys.length;

  const expectedHeaders = ['host', 'user-agent', 'accept'];
  const missingExpectedHeaders = expectedHeaders.filter((h) => !headerKeys.includes(h));

  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const suspiciousHeaderPatterns: string[] = [];
  for (const tool of SCANNER_TOOL_PATTERNS) {
    if (userAgent.includes(tool)) {
      suspiciousHeaderPatterns.push(tool);
    }
  }

  // 5. Frequency
  const requestFrequency = recordAndCalculateFrequency(clientIp);

  // 6. Content metadata
  const contentType = req.headers['content-type'];

  return {
    request_id: requestId,
    method: req.method.toUpperCase(),
    path: cleanPath,
    path_depth: pathDepth,
    path_length: pathLength,
    path_entropy: pathEntropy,
    has_suspicious_keywords: keywordCount > 0,
    suspicious_keyword_count: keywordCount,
    query_param_count: queryParamCount,
    query_entropy: queryEntropy,
    header_count: headerCount,
    missing_expected_headers: missingExpectedHeaders,
    suspicious_header_patterns: suspiciousHeaderPatterns,
    body_size: bodySize,
    content_type: typeof contentType === 'string' ? contentType : undefined,
    request_frequency: requestFrequency,
    auth_failure_count: 0,
    decoy_interactions: 0,
    client_ip: clientIp,
  };
}
