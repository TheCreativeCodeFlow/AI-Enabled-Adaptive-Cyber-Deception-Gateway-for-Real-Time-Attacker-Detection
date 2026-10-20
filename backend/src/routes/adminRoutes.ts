import { Router, Request, Response } from 'express';
import { requireAuth, requirePermission, logAuditEvent } from '../auth';
import { query } from '../db';
import { getConfig } from '../config';

export const adminRouter = Router();

// Protect ALL admin routes: Must be authenticated AND have 'operators:manage' permission (admin role only)
adminRouter.use(requireAuth);
adminRouter.use(requirePermission('operators:manage'));

/**
 * GET /api/admin/overview
 * Platform-wide telemetry and entity counts.
 */
adminRouter.get('/overview', async (req: Request, res: Response) => {
  try {
    const [
      orgsRes,
      appsRes,
      activeAppsRes,
      verifiedAppsRes,
      operatorsRes,
      eventsRes,
    ] = await Promise.all([
      query(`SELECT COUNT(*) as count FROM organisations`),
      query(`SELECT COUNT(*) as count FROM applications`),
      query(`SELECT COUNT(*) as count FROM applications WHERE activation_status = 'active'`),
      query(`SELECT COUNT(*) as count FROM applications WHERE verification_status = 'verified'`),
      query(`SELECT COUNT(*) as count FROM operators`),
      query(`SELECT COUNT(*) as count FROM security_events`),
    ]);

    const totalOrgs = parseInt(orgsRes.rows[0]?.count || '0', 10);
    const totalApps = parseInt(appsRes.rows[0]?.count || '0', 10);
    const activeApps = parseInt(activeAppsRes.rows[0]?.count || '0', 10);
    const verifiedApps = parseInt(verifiedAppsRes.rows[0]?.count || '0', 10);
    const totalOperators = parseInt(operatorsRes.rows[0]?.count || '0', 10);
    const totalSecurityEvents = parseInt(eventsRes.rows[0]?.count || '0', 10);

    // Fetch recent 10 security events across platform
    const recentEventsRes = await query(
      `SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10`
    );

    res.status(200).json({
      status: 'success',
      platformOverview: {
        totalOrganisations: totalOrgs,
        totalApplications: totalApps,
        activeApplications: activeApps,
        verifiedApplications: verifiedApps,
        totalOperators,
        totalSecurityEvents,
        recentSecurityEvents: recentEventsRes.rows || [],
        systemUptimeSeconds: Math.round(process.uptime()),
        timestamp: new Date().toISOString(),
      },
    });
  } catch (err: any) {
    console.error(`[Admin-Overview-Error] ${err.message}`);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve platform overview metrics.',
    });
  }
});

/**
 * GET /api/admin/organisations
 * Lists all organisations across the platform with application and member counts.
 */
adminRouter.get('/organisations', async (req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT o.id, o.name, o.slug, o.description, o.created_at, o.created_by,
              (SELECT COUNT(*) FROM applications a WHERE a.organisation_id = o.id) AS applications_count,
              (SELECT COUNT(*) FROM organisation_memberships m WHERE m.organisation_id = o.id) AS members_count
       FROM organisations o
       ORDER BY o.created_at DESC`
    );

    res.status(200).json({
      status: 'success',
      organisations: result.rows || [],
      count: result.rows?.length || 0,
    });
  } catch (err: any) {
    console.error(`[Admin-Orgs-Error] ${err.message}`);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve platform organisations.',
    });
  }
});

/**
 * GET /api/admin/applications
 * Lists all registered applications across all tenants.
 */
adminRouter.get('/applications', async (req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT a.id, a.organisation_id, a.display_name, a.environment,
              a.approved_domain, a.configured_origin, a.verification_status,
              a.activation_status, a.created_at, a.updated_at,
              o.name AS organisation_name
       FROM applications a
       LEFT JOIN organisations o ON a.organisation_id = o.id
       ORDER BY a.created_at DESC`
    );

    res.status(200).json({
      status: 'success',
      applications: result.rows || [],
      count: result.rows?.length || 0,
    });
  } catch (err: any) {
    console.error(`[Admin-Apps-Error] ${err.message}`);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve platform applications.',
    });
  }
});

/**
 * GET /api/admin/users
 * Lists all registered platform operators.
 */
adminRouter.get('/users', async (req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT op.id, op.username, op.email, op.role, op.is_active, op.created_at,
              (SELECT COUNT(*) FROM organisation_memberships m WHERE m.operator_id = op.id) AS organisations_count
       FROM operators op
       ORDER BY op.created_at DESC`
    );

    res.status(200).json({
      status: 'success',
      users: result.rows || [],
      count: result.rows?.length || 0,
    });
  } catch (err: any) {
    console.error(`[Admin-Users-Error] ${err.message}`);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve platform operators.',
    });
  }
});

/**
 * PUT /api/admin/users/:userId/role
 * Updates an operator's platform role.
 */
adminRouter.put('/users/:userId/role', async (req: Request, res: Response) => {
  const { userId } = req.params;
  const { role } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  if (!role || !['admin', 'analyst'].includes(role)) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Role must be either "admin" or "analyst".',
    });
    return;
  }

  // Prevent admin from demoting themselves to avoid lockouts
  if (userId === operator.sub && role !== 'admin') {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Platform administrators cannot demote their own account.',
    });
    return;
  }

  try {
    const result = await query(
      `UPDATE operators SET role = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING id, username, email, role, is_active, updated_at`,
      [role, userId]
    );

    if (result.rows.length === 0) {
      res.status(404).json({
        error: 'Not Found',
        message: 'Operator not found.',
      });
      return;
    }

    const updated = result.rows[0];

    await logAuditEvent(
      'OPERATOR_ROLE_UPDATED',
      'SUCCESS',
      clientIp,
      { id: operator.sub, username: operator.username },
      { targetUserId: userId, newRole: role }
    );

    res.status(200).json({
      status: 'success',
      message: `Operator role updated to ${role}.`,
      operator: updated,
    });
  } catch (err: any) {
    console.error(`[Admin-Role-Update-Error] ${err.message}`);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update operator role.',
    });
  }
});

/**
 * GET /api/admin/audit
 * Consolidated system audit log across operators and organizations.
 */
adminRouter.get('/audit', async (req: Request, res: Response) => {
  const limit = Math.min(Math.max(parseInt((req.query.limit as string) || '50', 10), 1), 200);

  try {
    const [opLogsRes, orgEventsRes] = await Promise.all([
      query(`SELECT id, operator_username, action, status, ip_address, details, created_at, 'SYSTEM' as scope FROM audit_logs ORDER BY created_at DESC LIMIT $1`, [limit]),
      query(`SELECT id, actor_username, action, status, ip_address, details, created_at, 'ORGANISATION' as scope FROM organisation_audit_events ORDER BY created_at DESC LIMIT $1`, [limit]),
    ]);

    const combined = [
      ...(opLogsRes.rows || []),
      ...(orgEventsRes.rows || []),
    ].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()).slice(0, limit);

    res.status(200).json({
      status: 'success',
      logs: combined,
      count: combined.length,
    });
  } catch (err: any) {
    console.error(`[Admin-Audit-Error] ${err.message}`);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve system audit events.',
    });
  }
});

/**
 * GET /api/admin/system/health
 * Comprehensive infrastructure readiness status.
 */
adminRouter.get('/system/health', async (req: Request, res: Response) => {
  try {
    let dbStatus = 'healthy';
    try {
      await query('SELECT 1');
    } catch {
      dbStatus = 'degraded';
    }

    res.status(200).json({
      status: 'healthy',
      database: dbStatus,
      backend: 'healthy',
      nodeEnv: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to check system health.',
    });
  }
});
