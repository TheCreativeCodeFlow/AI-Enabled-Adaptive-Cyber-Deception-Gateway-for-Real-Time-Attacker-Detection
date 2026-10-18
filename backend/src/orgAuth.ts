import { Request, Response, NextFunction } from 'express';
import { query, OrgRole, OrgMembershipRecord } from './db';

export type OrgPermission =
  | 'org:read'
  | 'org:update'
  | 'org:delete'
  | 'members:read'
  | 'members:manage'
  | 'apps:read'
  | 'apps:create'
  | 'apps:update'
  | 'apps:delete'
  | 'domains:verify'
  | 'protection:update'
  | 'audit:read';

export const ORG_ROLE_PERMISSIONS: Record<OrgRole, OrgPermission[]> = {
  org_owner: [
    'org:read',
    'org:update',
    'org:delete',
    'members:read',
    'members:manage',
    'apps:read',
    'apps:create',
    'apps:update',
    'apps:delete',
    'domains:verify',
    'protection:update',
    'audit:read',
  ],
  security_admin: [
    'org:read',
    'members:read',
    'apps:read',
    'apps:create',
    'apps:update',
    'apps:delete',
    'domains:verify',
    'protection:update',
    'audit:read',
  ],
  security_analyst: ['org:read', 'members:read', 'apps:read', 'audit:read'],
};

export interface OrgMembershipContext {
  organisationId: string;
  operatorId: string;
  role: OrgRole;
  permissions: OrgPermission[];
}

declare global {
  namespace Express {
    interface Request {
      orgMembership?: OrgMembershipContext;
    }
  }
}

/**
 * Persists an organisation-scoped audit event without sensitive information.
 */
export async function logOrgAuditEvent(
  organisationId: string,
  actor: { id?: string; username?: string },
  action: string,
  resourceType: string,
  resourceId?: string,
  status: 'SUCCESS' | 'FAILED' | 'FORBIDDEN' = 'SUCCESS',
  ipAddress: string = 'unknown',
  details: Record<string, any> = {}
): Promise<void> {
  const sanitizedDetails = { ...details };
  delete sanitizedDetails.password;
  delete sanitizedDetails.token;
  delete sanitizedDetails.authorization;
  delete sanitizedDetails.cookie;
  delete sanitizedDetails.secret;

  try {
    await query(
      `INSERT INTO organisation_audit_events (
        organisation_id, actor_id, actor_username, action, resource_type, resource_id, status, ip_address, details
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        organisationId,
        actor.id || null,
        actor.username || 'unknown',
        action,
        resourceType,
        resourceId || null,
        status,
        ipAddress,
        JSON.stringify(sanitizedDetails),
      ]
    );
  } catch (err: any) {
    console.error(`[Org-Audit-Error] Failed to log organisation audit event: ${err.message}`);
  }
}

/**
 * Middleware: Enforces tenant isolation and organisation-scoped RBAC permissions.
 * Prevents IDOR and cross-tenant access.
 */
export function requireOrgMembership(requiredPermission?: OrgPermission) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const operator = req.operator;
    const orgId = req.params.orgId;
    const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

    if (!operator) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Operator authentication required.',
      });
      return;
    }

    if (!orgId) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Organisation ID is required.',
      });
      return;
    }

    try {
      // 1. Check if user is an explicit member of the organisation
      const memResult = await query(
        `SELECT id, organisation_id, operator_id, role
         FROM organisation_memberships
         WHERE organisation_id = $1 AND operator_id = $2`,
        [orgId, operator.sub]
      );

      let membership: OrgMembershipRecord | undefined = memResult.rows[0];

      // 2. Platform Admin Fallback: Global admins can manage or inspect all orgs
      if (!membership && operator.role === 'admin') {
        const orgCheck = await query(`SELECT id FROM organisations WHERE id = $1`, [orgId]);
        if (orgCheck.rows.length > 0) {
          membership = {
            id: 'platform-admin-override',
            organisation_id: orgId,
            operator_id: operator.sub,
            role: 'org_owner',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          };
        }
      }

      // 3. IDOR Protection: Return 404/Access Denied if user is not a member of this tenant
      if (!membership) {
        await logOrgAuditEvent(
          orgId,
          { id: operator.sub, username: operator.username },
          'UNAUTHORIZED_ORG_ACCESS',
          'organisation',
          orgId,
          'FORBIDDEN',
          clientIp,
          { path: req.originalUrl }
        );

        res.status(404).json({
          error: 'Not Found',
          message: 'Organisation not found or access denied.',
        });
        return;
      }

      // 4. Role Permission Check
      const permissions = ORG_ROLE_PERMISSIONS[membership.role] || [];
      if (requiredPermission && !permissions.includes(requiredPermission)) {
        await logOrgAuditEvent(
          orgId,
          { id: operator.sub, username: operator.username },
          'PERMISSION_DENIED',
          'organisation',
          orgId,
          'FORBIDDEN',
          clientIp,
          { requiredPermission, userRole: membership.role, path: req.originalUrl }
        );

        res.status(403).json({
          error: 'Forbidden',
          message: `Insufficient organisation permissions. Action requires "${requiredPermission}".`,
          requiredPermission,
          role: membership.role,
        });
        return;
      }

      req.orgMembership = {
        organisationId: orgId,
        operatorId: operator.sub,
        role: membership.role,
        permissions,
      };

      next();
    } catch (err: any) {
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Error verifying organisation membership.',
      });
    }
  };
}
