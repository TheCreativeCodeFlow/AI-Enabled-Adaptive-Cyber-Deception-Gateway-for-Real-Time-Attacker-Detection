import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth';
import { requireOrgMembership, logOrgAuditEvent } from '../orgAuth';
import { validateDomainName, validateApplicationOrigin } from '../originValidation';
import { createDomainChallenge, getLatestChallenge, checkDomainOwnership } from '../domainVerification';
import { query, ApplicationRecord } from '../db';

export const appRouter = Router({ mergeParams: true });

/**
 * POST /api/orgs/:orgId/apps
 * Registers a new application under an organisation.
 * Validates domain and origin, initialises protection and domain challenge.
 */
appRouter.post('/', requireAuth, requireOrgMembership('apps:create'), async (req: Request, res: Response) => {
  const { orgId } = req.params;
  const { displayName, environment = 'production', approvedDomain, configuredOrigin } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  // 1. Display name validation
  if (!displayName || typeof displayName !== 'string' || displayName.trim().length < 2 || displayName.trim().length > 128) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Application display name must be between 2 and 128 characters.',
    });
    return;
  }

  // 2. Environment validation
  const validEnvironments = ['production', 'staging', 'development'];
  if (!validEnvironments.includes(environment)) {
    res.status(400).json({
      error: 'Bad Request',
      message: `Environment must be one of: ${validEnvironments.join(', ')}.`,
    });
    return;
  }

  // 3. Domain validation
  const domainValidation = validateDomainName(approvedDomain);
  if (!domainValidation.valid) {
    res.status(400).json({
      error: 'Bad Request',
      message: domainValidation.reason || 'Invalid approved domain.',
    });
    return;
  }
  const cleanDomain = domainValidation.normalizedDomain!;

  // 4. Origin validation & SSRF protection
  const originValidation = await validateApplicationOrigin(configuredOrigin, orgId, true);
  if (!originValidation.valid) {
    res.status(400).json({
      error: 'Bad Request',
      message: originValidation.reason || 'Invalid configured origin URL.',
    });
    return;
  }
  const cleanOrigin = originValidation.normalizedOrigin!;

  try {
    // 5. Insert application record
    const appResult = await query(
      `INSERT INTO applications (
        organisation_id, display_name, environment, approved_domain, configured_origin, created_by
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *`,
      [orgId, displayName.trim(), environment, cleanDomain, cleanOrigin, operator.sub]
    );

    const appRecord: ApplicationRecord = appResult.rows[0];

    // 6. Initialize default protection configuration
    await query(
      `INSERT INTO application_protections (
        application_id, organisation_id, routing_mode, deception_threshold, emergency_disable, quarantine_on_failure
      ) VALUES ($1, $2, $3, $4, $5, $6)`,
      [appRecord.id, orgId, 'shadow', 0.70, false, true]
    );

    // 7. Initialize first DNS TXT verification challenge
    const challenge = await createDomainChallenge(appRecord.id, orgId, cleanDomain);

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'APPLICATION_REGISTERED',
      'application',
      appRecord.id,
      'SUCCESS',
      clientIp,
      {
        displayName: appRecord.display_name,
        approvedDomain: appRecord.approved_domain,
        configuredOrigin: appRecord.configured_origin,
        environment: appRecord.environment,
      }
    );

    res.status(201).json({
      status: 'created',
      message: 'Application registered successfully. Domain ownership verification required before activation.',
      application: appRecord,
      verificationChallenge: {
        id: challenge.id,
        recordName: challenge.record_name,
        recordType: challenge.record_type,
        token: challenge.token,
        status: challenge.status,
        expiresAt: challenge.expires_at,
      },
    });
  } catch (err: any) {
    if (err.code === '23505' || err.message?.includes('duplicate key')) {
      res.status(409).json({
        error: 'Conflict',
        message: `Domain "${cleanDomain}" is already registered within this organisation.`,
      });
      return;
    }

    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to register application.',
    });
  }
});

/**
 * GET /api/orgs/:orgId/apps
 * Lists all applications registered under an organisation.
 */
appRouter.get('/', requireAuth, requireOrgMembership('apps:read'), async (req: Request, res: Response) => {
  const { orgId } = req.params;

  try {
    const result = await query(
      `SELECT * FROM applications WHERE organisation_id = $1 ORDER BY created_at DESC`,
      [orgId]
    );

    res.status(200).json({
      status: 'success',
      applications: result.rows,
      count: result.rows.length,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve applications.',
    });
  }
});

/**
 * GET /api/orgs/:orgId/apps/:appId
 * Retrieves detailed application information including verification challenge and protection settings.
 */
appRouter.get('/:appId', requireAuth, requireOrgMembership('apps:read'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;

  try {
    const appRes = await query(
      `SELECT * FROM applications WHERE id = $1 AND organisation_id = $2`,
      [appId, orgId]
    );

    const appRecord: ApplicationRecord | undefined = appRes.rows[0];
    if (!appRecord) {
      res.status(404).json({
        error: 'Not Found',
        message: 'Application not found.',
      });
      return;
    }

    const [challenge, protRes] = await Promise.all([
      getLatestChallenge(appId, orgId),
      query(
        `SELECT * FROM application_protections WHERE application_id = $1 AND organisation_id = $2`,
        [appId, orgId]
      ),
    ]);

    res.status(200).json({
      status: 'success',
      application: appRecord,
      verificationChallenge: challenge,
      protection: protRes.rows[0] || null,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve application details.',
    });
  }
});

const updateAppHandler = async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;
  const { displayName, environment, configuredOrigin } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    // 1. Fetch current application
    const curRes = await query(
      `SELECT * FROM applications WHERE id = $1 AND organisation_id = $2`,
      [appId, orgId]
    );
    const currentApp: ApplicationRecord | undefined = curRes.rows[0];
    if (!currentApp) {
      res.status(404).json({ error: 'Not Found', message: 'Application not found.' });
      return;
    }

    // 2. Validate updates
    const newDisplayName = typeof displayName === 'string' && displayName.trim().length >= 2 ? displayName.trim() : currentApp.display_name;
    const newEnvironment = ['production', 'staging', 'development'].includes(environment) ? environment : currentApp.environment;

    let newOrigin = currentApp.configured_origin;
    if (configuredOrigin && typeof configuredOrigin === 'string') {
      const originValidation = await validateApplicationOrigin(configuredOrigin, orgId, true);
      if (!originValidation.valid) {
        res.status(400).json({
          error: 'Bad Request',
          message: originValidation.reason || 'Invalid origin URL.',
        });
        return;
      }
      newOrigin = originValidation.normalizedOrigin!;
    }

    // 3. Update application record
    const updateRes = await query(
      `UPDATE applications
       SET display_name = $1, environment = $2, configured_origin = $3, updated_at = CURRENT_TIMESTAMP
       WHERE id = $4 AND organisation_id = $5
       RETURNING *`,
      [newDisplayName, newEnvironment, newOrigin, appId, orgId]
    );

    const updated = updateRes.rows[0];

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'APPLICATION_UPDATED',
      'application',
      appId,
      'SUCCESS',
      clientIp,
      { displayName: updated.display_name, origin: updated.configured_origin, environment: updated.environment }
    );

    res.status(200).json({
      status: 'updated',
      application: updated,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update application.',
    });
  }
};

appRouter.put('/:appId', requireAuth, requireOrgMembership('apps:update'), updateAppHandler);
appRouter.patch('/:appId', requireAuth, requireOrgMembership('apps:update'), updateAppHandler);

/**
 * DELETE /api/orgs/:orgId/apps/:appId
 * Removes an application registration.
 */
appRouter.delete('/:appId', requireAuth, requireOrgMembership('apps:delete'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    const result = await query(
      `DELETE FROM applications WHERE id = $1 AND organisation_id = $2 RETURNING id`,
      [appId, orgId]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Not Found', message: 'Application not found.' });
      return;
    }

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'APPLICATION_DELETED',
      'application',
      appId,
      'SUCCESS',
      clientIp
    );

    res.status(200).json({
      status: 'deleted',
      message: 'Application registration deleted successfully.',
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to delete application.',
    });
  }
});

/**
 * POST /api/orgs/:orgId/apps/:appId/verify/challenge
 * POST /api/orgs/:orgId/apps/:appId/verification-challenges
 * Generates a fresh DNS TXT verification challenge or retrieves active challenge.
 */
appRouter.post(['/:appId/verify/challenge', '/:appId/verification-challenges'], requireAuth, requireOrgMembership('domains:verify'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;
  const { forceRegenerate = false } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    const appRes = await query(
      `SELECT * FROM applications WHERE id = $1 AND organisation_id = $2`,
      [appId, orgId]
    );
    const app = appRes.rows[0];
    if (!app) {
      res.status(404).json({ error: 'Not Found', message: 'Application not found.' });
      return;
    }

    // Check existing challenge
    const existing = await getLatestChallenge(appId, orgId);
    const now = Date.now();
    const isExpired = existing ? now > new Date(existing.expires_at).getTime() : true;
    const isExhausted = existing ? existing.attempts_count >= 5 : false;

    let challenge = existing;
    if (!existing || isExpired || isExhausted || forceRegenerate) {
      challenge = await createDomainChallenge(appId, orgId, app.approved_domain);

      await logOrgAuditEvent(
        orgId,
        { id: operator.sub, username: operator.username },
        'DOMAIN_CHALLENGE_GENERATED',
        'domain_verification',
        challenge.id,
        'SUCCESS',
        clientIp,
        { domain: challenge.domain, recordName: challenge.record_name }
      );
    }

    if (!challenge) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Failed to create or retrieve verification challenge.',
      });
      return;
    }

    res.status(200).json({
      status: 'success',
      verificationChallenge: {
        id: challenge.id,
        recordName: challenge.record_name,
        recordType: challenge.record_type,
        token: challenge.token,
        status: challenge.status,
        expiresAt: challenge.expires_at,
        attemptsCount: challenge.attempts_count,
      },
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to create verification challenge.',
    });
  }
});

/**
 * GET /api/orgs/:orgId/apps/:appId/verification-challenges/latest
 * GET /api/orgs/:orgId/apps/:appId/verify/challenge
 * Retrieves latest active domain verification challenge.
 */
appRouter.get(['/:appId/verification-challenges/latest', '/:appId/verify/challenge'], requireAuth, requireOrgMembership('apps:read'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;

  try {
    const challenge = await getLatestChallenge(appId, orgId);
    if (!challenge) {
      res.status(404).json({ error: 'Not Found', message: 'No verification challenge found.' });
      return;
    }

    res.status(200).json({
      status: 'success',
      challenge,
      verificationChallenge: {
        id: challenge.id,
        recordName: challenge.record_name,
        recordType: challenge.record_type,
        token: challenge.token,
        status: challenge.status,
        expiresAt: challenge.expires_at,
        attemptsCount: challenge.attempts_count,
      },
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve verification challenge.',
    });
  }
});

/**
 * POST /api/orgs/:orgId/apps/:appId/verify/check
 * Resolves server-side DNS TXT records to verify domain ownership.
 */
appRouter.post(['/:appId/verify', '/:appId/verify/check'], requireAuth, requireOrgMembership('domains:verify'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    const challenge = await getLatestChallenge(appId, orgId);
    if (!challenge) {
      res.status(404).json({
        error: 'Not Found',
        message: 'No verification challenge found for this application. Please generate a challenge first.',
      });
      return;
    }

    const result = await checkDomainOwnership(challenge.id, appId, orgId);

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'DOMAIN_VERIFICATION_CHECK',
      'domain_verification',
      challenge.id,
      result.verified ? 'SUCCESS' : 'FAILED',
      clientIp,
      {
        domain: challenge.domain,
        verified: result.verified,
        status: result.status,
        reason: result.reason,
        attemptsCount: result.attemptsCount,
      }
    );

    const appRes = await query('SELECT * FROM applications WHERE id = $1 AND organisation_id = $2', [appId, orgId]);
    const currentApp = appRes.rows[0];

    if (!result.verified) {
      res.status(200).json({
        status: 'verification_failed',
        verified: false,
        message: result.reason || 'Verification check failed. TXT record missing or mismatched.',
        verificationStatus: result.status,
        application: currentApp,
        attemptsRemaining: Math.max(0, 5 - result.attemptsCount),
      });
      return;
    }

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'DOMAIN_VERIFIED',
      'application',
      appId,
      'SUCCESS',
      clientIp,
      { domain: challenge.domain, verifiedAt: result.verifiedAt }
    );

    res.status(200).json({
      status: 'verified',
      verified: true,
      message: 'Domain ownership successfully verified.',
      domain: challenge.domain,
      application: currentApp,
      verifiedAt: result.verifiedAt,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Error verifying domain ownership.',
    });
  }
});

/**
 * POST /api/orgs/:orgId/apps/:appId/activate
 * Activates application interception. Fails if unverified.
 */
appRouter.post('/:appId/activate', requireAuth, requireOrgMembership('protection:update'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    const appRes = await query(
      `SELECT * FROM applications WHERE id = $1 AND organisation_id = $2`,
      [appId, orgId]
    );

    const app: ApplicationRecord | undefined = appRes.rows[0];
    if (!app) {
      res.status(404).json({ error: 'Not Found', message: 'Application not found.' });
      return;
    }

    // CRITICAL GATEWAY SAFETY INVARIANT: Unverified applications cannot be activated
    if (app.verification_status !== 'verified') {
      await logOrgAuditEvent(
        orgId,
        { id: operator.sub, username: operator.username },
        'ACTIVATION_REJECTED_UNVERIFIED',
        'application',
        appId,
        'FAILED',
        clientIp,
        { verificationStatus: app.verification_status }
      );

      res.status(400).json({
        error: 'Bad Request',
        message: `Cannot activate unverified application (domain is not verified). Current verification status is "${app.verification_status}". Domain ownership verification must be completed first.`,
        verificationStatus: app.verification_status,
      });
      return;
    }

    const updateRes = await query(
      `UPDATE applications
       SET activation_status = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2 AND organisation_id = $3
       RETURNING *`,
      ['active', appId, orgId]
    );

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'APPLICATION_ACTIVATED',
      'application',
      appId,
      'SUCCESS',
      clientIp
    );

    res.status(200).json({
      status: 'active',
      message: 'Application successfully activated.',
      application: updateRes.rows[0],
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to activate application.',
    });
  }
});

/**
 * POST /api/orgs/:orgId/apps/:appId/disable
 * Disables application interception.
 */
appRouter.post('/:appId/disable', requireAuth, requireOrgMembership('protection:update'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    const updateRes = await query(
      `UPDATE applications
       SET activation_status = $1, updated_at = CURRENT_TIMESTAMP
       WHERE id = $2 AND organisation_id = $3
       RETURNING *`,
      ['disabled', appId, orgId]
    );

    if (updateRes.rows.length === 0) {
      res.status(404).json({ error: 'Not Found', message: 'Application not found.' });
      return;
    }

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'APPLICATION_DISABLED',
      'application',
      appId,
      'SUCCESS',
      clientIp
    );

    res.status(200).json({
      status: 'disabled',
      message: 'Application interception disabled.',
      application: updateRes.rows[0],
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to disable application.',
    });
  }
});

/**
 * GET /api/orgs/:orgId/apps/:appId/protection
 * Retrieves application protection settings.
 */
appRouter.get('/:appId/protection', requireAuth, requireOrgMembership('apps:read'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;

  try {
    const result = await query(
      `SELECT * FROM application_protections WHERE application_id = $1 AND organisation_id = $2`,
      [appId, orgId]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'Not Found', message: 'Protection settings not found.' });
      return;
    }

    const row = result.rows[0];
    res.status(200).json({
      status: 'success',
      protection: {
        ...row,
        diversion_mode: row.routing_mode === 'active' ? 'DYNAMIC' : 'OFF',
        deception_sensitivity: row.deception_threshold,
      },
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve protection configuration.',
    });
  }
});

/**
 * PUT /api/orgs/:orgId/apps/:appId/protection
 * Updates application protection configuration.
 */
appRouter.put('/:appId/protection', requireAuth, requireOrgMembership('protection:update'), async (req: Request, res: Response) => {
  const { orgId, appId } = req.params;
  const { routingMode, diversionMode, deceptionThreshold, deceptionSensitivity, emergencyDisable, quarantineOnFailure, allowedPaths, excludedPaths, rateLimitRpm } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  const rawMode = routingMode || diversionMode;
  let normalizedRoutingMode = 'shadow';
  if (rawMode) {
    if (rawMode === 'active' || rawMode === 'DYNAMIC' || rawMode === 'ALL_SUSPICIOUS') {
      normalizedRoutingMode = 'active';
    } else if (rawMode === 'shadow' || rawMode === 'OFF' || rawMode === 'OBSERVE_ONLY') {
      normalizedRoutingMode = 'shadow';
    } else {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Routing mode must be one of: shadow, active (or OFF, DYNAMIC, ALL_SUSPICIOUS).',
      });
      return;
    }
  }

  const rawThreshold = deceptionThreshold !== undefined ? deceptionThreshold : deceptionSensitivity;
  const threshold = rawThreshold !== undefined ? parseFloat(rawThreshold) : 0.70;
  if (isNaN(threshold) || threshold < 0 || threshold > 1) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Deception threshold must be a number between 0.0 and 1.0.',
    });
    return;
  }

  try {
    const updateRes = await query(
      `UPDATE application_protections
       SET routing_mode = $1, deception_threshold = $2, emergency_disable = $3, quarantine_on_failure = $4, updated_at = CURRENT_TIMESTAMP
       WHERE application_id = $5 AND organisation_id = $6
       RETURNING *`,
      [
        normalizedRoutingMode,
        threshold,
        Boolean(emergencyDisable),
        quarantineOnFailure !== undefined ? Boolean(quarantineOnFailure) : true,
        appId,
        orgId,
      ]
    );

    if (updateRes.rows.length === 0) {
      res.status(404).json({ error: 'Not Found', message: 'Application protection not found.' });
      return;
    }

    const updated = updateRes.rows[0];

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'PROTECTION_CONFIG_UPDATED',
      'application_protection',
      appId,
      'SUCCESS',
      clientIp,
      { routingMode: normalizedRoutingMode, deceptionThreshold: threshold, emergencyDisable }
    );

    res.status(200).json({
      status: 'updated',
      protection: {
        ...updated,
        diversion_mode: updated.routing_mode === 'active' ? 'DYNAMIC' : 'OFF',
        deception_sensitivity: updated.deception_threshold,
        allowed_paths: allowedPaths || [],
        excluded_paths: excludedPaths || [],
        rate_limit_rpm: rateLimitRpm !== undefined ? rateLimitRpm : 120,
      },
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update protection configuration.',
    });
  }
});
