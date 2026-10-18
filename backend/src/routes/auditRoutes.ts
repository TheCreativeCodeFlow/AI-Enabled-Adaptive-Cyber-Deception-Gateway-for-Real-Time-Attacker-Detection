import { Router, Request, Response } from 'express';
import { requireAuth, requirePermission } from '../auth';
import { query } from '../db';

export const auditRouter = Router();

/**
 * GET /api/audit/logs
 * Retrieves security and operator audit trail.
 * Requires 'audit:read' permission (granted to admin and analyst).
 */
auditRouter.get('/logs', requireAuth, requirePermission('audit:read'), async (_req: Request, res: Response) => {
  try {
    const result = await query(
      `SELECT id, operator_id, operator_username, action, status, ip_address, details, created_at
       FROM audit_logs
       ORDER BY created_at DESC
       LIMIT 100`
    );

    res.status(200).json({
      status: 'success',
      count: result.rows.length,
      logs: result.rows,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve audit records.',
    });
  }
});
