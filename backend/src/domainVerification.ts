import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { query, DomainVerificationRecord } from './db';

export type DnsTxtResolver = (hostname: string) => Promise<string[][]>;

let customDnsResolver: DnsTxtResolver | null = null;

/**
 * Injects a mock/test DNS resolver for local testing fixtures without accessing public DNS.
 */
export function setMockDnsResolver(resolver: DnsTxtResolver | null): void {
  customDnsResolver = resolver;
}

/**
 * Resolves DNS TXT records with a bounded response timeout.
 */
async function resolveTxtBounded(hostname: string, timeoutMs = 4000): Promise<string[][]> {
  if (customDnsResolver) {
    return customDnsResolver(hostname);
  }

  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('DNS query timed out')), timeoutMs)
  );

  return Promise.race([dns.resolveTxt(hostname), timeoutPromise]);
}

/**
 * Generates an expiring, cryptographically random DNS TXT verification challenge.
 */
export async function createDomainChallenge(
  applicationId: string,
  organisationId: string,
  domain: string,
  ttlHours = 24
): Promise<DomainVerificationRecord> {
  // 160 bits of cryptographic randomness
  const token = `deception-verify-${crypto.randomBytes(20).toString('hex')}`;
  const recordName = `_deception-challenge.${domain.toLowerCase().trim()}`;
  const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000).toISOString();

  const result = await query(
    `INSERT INTO domain_verifications (
      application_id, organisation_id, domain, token, record_name, record_type, expires_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    RETURNING *`,
    [applicationId, organisationId, domain.toLowerCase().trim(), token, recordName, 'TXT', expiresAt]
  );

  return result.rows[0];
}

/**
 * Retrieves the latest active domain verification challenge for an application.
 */
export async function getLatestChallenge(
  applicationId: string,
  organisationId: string
): Promise<DomainVerificationRecord | null> {
  const result = await query(
    `SELECT * FROM domain_verifications
     WHERE application_id = $1 AND organisation_id = $2
     ORDER BY created_at DESC
     LIMIT 1`,
    [applicationId, organisationId]
  );

  return result.rows[0] || null;
}

export interface VerificationCheckResult {
  verified: boolean;
  status: 'pending' | 'verified' | 'expired' | 'failed';
  reason?: string;
  attemptsCount: number;
  verifiedAt?: string;
  foundRecords?: string[];
}

/**
 * Executes server-side DNS TXT resolution to verify domain ownership.
 * Strictly checks the exact registered domain, handles expiration, and rate-limits attempts.
 */
export async function checkDomainOwnership(
  challengeId: string,
  applicationId: string,
  organisationId: string
): Promise<VerificationCheckResult> {
  const result = await query(
    `SELECT * FROM domain_verifications
     WHERE id = $1 AND application_id = $2 AND organisation_id = $3`,
    [challengeId, applicationId, organisationId]
  );

  const challenge: DomainVerificationRecord | undefined = result.rows[0];

  if (!challenge) {
    return {
      verified: false,
      status: 'failed',
      reason: 'Verification challenge record not found.',
      attemptsCount: 0,
    };
  }

  // Already verified check
  if (challenge.status === 'verified') {
    return {
      verified: true,
      status: 'verified',
      verifiedAt: challenge.verified_at,
      attemptsCount: challenge.attempts_count,
    };
  }

  // Check expiration
  const now = Date.now();
  if (now > new Date(challenge.expires_at).getTime()) {
    await query(
      `UPDATE domain_verifications
       SET status = 'expired', last_error = 'Challenge expired before successful verification', updated_at = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [challenge.id]
    );

    return {
      verified: false,
      status: 'expired',
      reason: 'Verification challenge has expired. Please generate a new verification challenge.',
      attemptsCount: challenge.attempts_count,
    };
  }

  // Rate-limiting verification attempts per challenge (max 5)
  if (challenge.attempts_count >= 5) {
    await query(
      `UPDATE domain_verifications
       SET status = 'failed', last_error = 'Maximum verification attempts exceeded', updated_at = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [challenge.id]
    );

    return {
      verified: false,
      status: 'failed',
      reason: 'Maximum verification attempts (5) exceeded. Please regenerate a new verification challenge.',
      attemptsCount: challenge.attempts_count,
    };
  }

  // Perform bounded DNS TXT query
  let txtRecords: string[][] = [];
  try {
    txtRecords = await resolveTxtBounded(challenge.record_name);
  } catch (err: any) {
    const errorMsg = `DNS resolution failed: ${err.message || 'No TXT records'}`;
    await query(
      `UPDATE domain_verifications
       SET attempts_count = attempts_count + 1, last_error = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [errorMsg, challenge.id]
    );

    return {
      verified: false,
      status: 'pending',
      reason: `DNS TXT record "${challenge.record_name}" not found or failed to resolve. Ensure your DNS record has propagated.`,
      attemptsCount: challenge.attempts_count + 1,
    };
  }

  // Flatten and normalize TXT entries
  const flatRecords = txtRecords.map((chunkArr) => chunkArr.join('').trim());
  const matchFound = flatRecords.some((val) => val === challenge.token);

  if (!matchFound) {
    const mismatchMsg = `TXT record found, but expected token did not match.`;
    await query(
      `UPDATE domain_verifications
       SET attempts_count = attempts_count + 1, last_error = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [mismatchMsg, challenge.id]
    );

    return {
      verified: false,
      status: 'pending',
      reason: 'DNS TXT record was found, but the value did not match the expected verification token.',
      attemptsCount: challenge.attempts_count + 1,
      foundRecords: flatRecords,
    };
  }

  // Verification successful! Update challenge and application status
  const verifiedAt = new Date().toISOString();

  await query(
    `UPDATE domain_verifications
     SET status = 'verified', verified_at = $1, last_error = null, updated_at = CURRENT_TIMESTAMP
     WHERE id = $2`,
    [verifiedAt, challenge.id]
  );

  await query(
    `UPDATE applications
     SET verification_status = 'verified', updated_at = CURRENT_TIMESTAMP
     WHERE id = $1 AND organisation_id = $2`,
    [applicationId, organisationId]
  );

  return {
    verified: true,
    status: 'verified',
    verifiedAt,
    attemptsCount: challenge.attempts_count + 1,
  };
}
