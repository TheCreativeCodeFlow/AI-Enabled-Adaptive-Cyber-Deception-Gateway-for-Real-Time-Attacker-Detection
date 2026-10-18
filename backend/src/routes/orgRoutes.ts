import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth';
import { requireOrgMembership, logOrgAuditEvent } from '../orgAuth';
import { query, OrganisationRecord } from '../db';

export const orgRouter = Router();

// Organization slug regex (alphanumeric, dashes)
const SLUG_REGEX = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * POST /api/orgs
 * Creates a new organisation and assigns caller as org_owner.
 */
orgRouter.post('/', requireAuth, async (req: Request, res: Response) => {
  const { name, slug, description = '' } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  if (!name || typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 128) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Organisation name must be between 2 and 128 characters.',
    });
    return;
  }

  const normalizedSlug = (slug || name)
    .toString()
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '');

  if (!normalizedSlug || !SLUG_REGEX.test(normalizedSlug) || normalizedSlug.length > 128) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Organisation slug must be URL-safe (lowercase alphanumeric and hyphens).',
    });
    return;
  }

  try {
    // 1. Create organisation record
    const orgResult = await query(
      `INSERT INTO organisations (name, slug, description, created_by)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name.trim(), normalizedSlug, typeof description === 'string' ? description.trim() : '', operator.sub]
    );

    const org: OrganisationRecord = orgResult.rows[0];

    // 2. Assign creator as org_owner
    await query(
      `INSERT INTO organisation_memberships (organisation_id, operator_id, role)
       VALUES ($1, $2, $3)`,
      [org.id, operator.sub, 'org_owner']
    );

    await logOrgAuditEvent(
      org.id,
      { id: operator.sub, username: operator.username },
      'ORGANISATION_CREATED',
      'organisation',
      org.id,
      'SUCCESS',
      clientIp,
      { name: org.name, slug: org.slug }
    );

    res.status(201).json({
      status: 'created',
      message: 'Organisation created successfully.',
      organisation: {
        id: org.id,
        name: org.name,
        slug: org.slug,
        description: org.description,
        role: 'org_owner',
        createdAt: org.created_at,
      },
    });
  } catch (err: any) {
    if (err.code === '23505' || err.message?.includes('duplicate key')) {
      res.status(409).json({
        error: 'Conflict',
        message: `Organisation with slug "${normalizedSlug}" already exists. Please choose a different name or slug.`,
      });
      return;
    }

    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to create organisation.',
    });
  }
});

/**
 * GET /api/orgs
 * Lists all organisations the authenticated user is a member of.
 */
orgRouter.get('/', requireAuth, async (req: Request, res: Response) => {
  const operator = req.operator!;

  try {
    const result = await query(
      `SELECT o.id, o.name, o.slug, o.description, o.created_at, m.role
       FROM organisations o
       JOIN organisation_memberships m ON o.id = m.organisation_id
       WHERE m.operator_id = $1
       ORDER BY o.created_at DESC`,
      [operator.sub]
    );

    res.status(200).json({
      status: 'success',
      organisations: result.rows,
      count: result.rows.length,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve organisations.',
    });
  }
});

/**
 * GET /api/orgs/:orgId
 * Retrieves organisation details for an authorized member.
 */
orgRouter.get('/:orgId', requireAuth, requireOrgMembership('org:read'), async (req: Request, res: Response) => {
  const orgId = req.params.orgId;
  const membership = req.orgMembership!;

  try {
    const result = await query(`SELECT * FROM organisations WHERE id = $1`, [orgId]);
    const org = result.rows[0];

    if (!org) {
      res.status(404).json({
        error: 'Not Found',
        message: 'Organisation not found.',
      });
      return;
    }

    res.status(200).json({
      status: 'success',
      organisation: {
        id: org.id,
        name: org.name,
        slug: org.slug,
        description: org.description,
        role: membership.role,
        permissions: membership.permissions,
        createdAt: org.created_at,
        updatedAt: org.updated_at,
      },
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve organisation details.',
    });
  }
});

/**
 * PUT /api/orgs/:orgId
 * Updates organisation name and description.
 */
orgRouter.put('/:orgId', requireAuth, requireOrgMembership('org:update'), async (req: Request, res: Response) => {
  const orgId = req.params.orgId;
  const { name, description = '' } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    res.status(400).json({
      error: 'Bad Request',
      message: 'Organisation name is required.',
    });
    return;
  }

  try {
    const result = await query(
      `UPDATE organisations
       SET name = $1, description = $2, updated_at = CURRENT_TIMESTAMP
       WHERE id = $3
       RETURNING *`,
      [name.trim(), typeof description === 'string' ? description.trim() : '', orgId]
    );

    const updated = result.rows[0];
    if (!updated) {
      res.status(404).json({ error: 'Not Found', message: 'Organisation not found.' });
      return;
    }

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'ORGANISATION_UPDATED',
      'organisation',
      orgId,
      'SUCCESS',
      clientIp,
      { name: updated.name }
    );

    res.status(200).json({
      status: 'updated',
      organisation: updated,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to update organisation.',
    });
  }
});

/**
 * DELETE /api/orgs/:orgId
 * Deletes an organisation (org_owner only).
 */
orgRouter.delete('/:orgId', requireAuth, requireOrgMembership('org:delete'), async (req: Request, res: Response) => {
  const orgId = req.params.orgId;
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    await query(`DELETE FROM organisations WHERE id = $1`, [orgId]);

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'ORGANISATION_DELETED',
      'organisation',
      orgId,
      'SUCCESS',
      clientIp
    );

    res.status(200).json({
      status: 'deleted',
      message: 'Organisation deleted successfully.',
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to delete organisation.',
    });
  }
});

/**
 * GET /api/orgs/:orgId/members
 * Lists all members of an organisation.
 */
orgRouter.get('/:orgId/members', requireAuth, requireOrgMembership('members:read'), async (req: Request, res: Response) => {
  const orgId = req.params.orgId;

  try {
    const result = await query(
      `SELECT m.id, m.organisation_id, m.operator_id, m.role, m.created_at, op.username, op.email
       FROM organisation_memberships m
       JOIN operators op ON m.operator_id = op.id
       WHERE m.organisation_id = $1
       ORDER BY m.created_at ASC`,
      [orgId]
    );

    res.status(200).json({
      status: 'success',
      members: result.rows,
      count: result.rows.length,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to list organisation members.',
    });
  }
});

/**
 * POST /api/orgs/:orgId/members
 * Adds a new member to the organisation.
 */
orgRouter.post('/:orgId/members', requireAuth, requireOrgMembership('members:manage'), async (req: Request, res: Response) => {
  const orgId = req.params.orgId;
  const { username, operatorId, role = 'security_analyst' } = req.body || {};
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  const validRoles = ['org_owner', 'security_admin', 'security_analyst'];
  if (!validRoles.includes(role)) {
    res.status(400).json({
      error: 'Bad Request',
      message: `Role must be one of: ${validRoles.join(', ')}`,
    });
    return;
  }

  try {
    // 1. Locate target operator
    let targetOp: any;
    if (operatorId) {
      const opRes = await query(`SELECT id, username, email FROM operators WHERE id = $1`, [operatorId]);
      targetOp = opRes.rows[0];
    } else if (username) {
      const opRes = await query(`SELECT id, username, email FROM operators WHERE username = $1`, [
        String(username).toLowerCase().trim(),
      ]);
      targetOp = opRes.rows[0];
    }

    if (!targetOp) {
      res.status(404).json({
        error: 'Not Found',
        message: 'Target operator account does not exist.',
      });
      return;
    }

    // 2. Add membership
    const memRes = await query(
      `INSERT INTO organisation_memberships (organisation_id, operator_id, role)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [orgId, targetOp.id, role]
    );

    const membership = memRes.rows[0];

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'MEMBER_ADDED',
      'membership',
      membership.id,
      'SUCCESS',
      clientIp,
      { targetOperator: targetOp.username, role }
    );

    res.status(201).json({
      status: 'created',
      message: 'Member added successfully.',
      member: {
        id: membership.id,
        organisationId: orgId,
        operatorId: targetOp.id,
        username: targetOp.username,
        email: targetOp.email,
        role: membership.role,
        createdAt: membership.created_at,
      },
    });
  } catch (err: any) {
    if (err.code === '23505' || err.message?.includes('duplicate key')) {
      res.status(409).json({
        error: 'Conflict',
        message: 'Operator is already a member of this organisation.',
      });
      return;
    }

    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to add organisation member.',
    });
  }
});

/**
 * DELETE /api/orgs/:orgId/members/:memberId
 * Removes a member from the organisation.
 */
orgRouter.delete('/:orgId/members/:memberId', requireAuth, requireOrgMembership('members:manage'), async (req: Request, res: Response) => {
  const { orgId, memberId } = req.params;
  const operator = req.operator!;
  const clientIp = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';

  try {
    const result = await query(
      `DELETE FROM organisation_memberships WHERE organisation_id = $1 AND (id = $2 OR operator_id = $2)`,
      [orgId, memberId]
    );

    await logOrgAuditEvent(
      orgId,
      { id: operator.sub, username: operator.username },
      'MEMBER_REMOVED',
      'membership',
      memberId,
      'SUCCESS',
      clientIp
    );

    res.status(200).json({
      status: 'deleted',
      message: 'Member removed successfully.',
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to remove member.',
    });
  }
});

/**
 * GET /api/orgs/:orgId/audit
 * Retrieves organisation-scoped audit event trail.
 */
orgRouter.get('/:orgId/audit', requireAuth, requireOrgMembership('audit:read'), async (req: Request, res: Response) => {
  const orgId = req.params.orgId;

  try {
    const result = await query(
      `SELECT * FROM organisation_audit_events
       WHERE organisation_id = $1
       ORDER BY created_at DESC`,
      [orgId]
    );

    res.status(200).json({
      status: 'success',
      events: result.rows,
      auditEvents: result.rows,
      count: result.rows.length,
    });
  } catch (err: any) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to retrieve audit events.',
    });
  }
});
