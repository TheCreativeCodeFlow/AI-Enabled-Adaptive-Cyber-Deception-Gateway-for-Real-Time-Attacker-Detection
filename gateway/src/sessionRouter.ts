export interface SessionRoutingRecord {
  sessionId: string;
  target: 'DECEPTION';
  assignedAt: number;
  lastActiveAt: number;
  expiresAt: number;
  reason: string;
  initialScore: number;
}

export class SessionRoutingStore {
  private assignments = new Map<string, SessionRoutingRecord>();
  private readonly ttlMs: number;
  private readonly maxCapacity: number;

  constructor(ttlMs = 1800000, maxCapacity = 5000) {
    this.ttlMs = ttlMs;
    this.maxCapacity = maxCapacity;
  }

  /**
   * Checks whether a session has an active, non-expired deception assignment.
   */
  public isSessionAssignedToDeception(sessionId: string): boolean {
    if (!sessionId || typeof sessionId !== 'string') {
      return false;
    }

    const record = this.assignments.get(sessionId);
    if (!record) {
      return false;
    }

    const now = Date.now();
    if (now > record.expiresAt) {
      this.assignments.delete(sessionId);
      return false;
    }

    // Refresh sliding window
    record.lastActiveAt = now;
    record.expiresAt = now + this.ttlMs;
    return true;
  }

  /**
   * Records a sticky deception assignment for a session.
   */
  public assignSessionToDeception(sessionId: string, reason: string, score: number): void {
    if (!sessionId || typeof sessionId !== 'string') {
      return;
    }

    this.enforceCapacity();

    const now = Date.now();
    this.assignments.set(sessionId, {
      sessionId,
      target: 'DECEPTION',
      assignedAt: now,
      lastActiveAt: now,
      expiresAt: now + this.ttlMs,
      reason,
      initialScore: score,
    });
  }

  /**
   * Resets / clears a session's deception assignment (e.g., manual operator override or reset).
   */
  public resetSessionAssignment(sessionId: string): boolean {
    return this.assignments.delete(sessionId);
  }

  /**
   * Purges expired session assignments from memory.
   */
  public cleanupExpiredAssignments(): number {
    const now = Date.now();
    let count = 0;
    for (const [id, record] of this.assignments.entries()) {
      if (now > record.expiresAt) {
        this.assignments.delete(id);
        count++;
      }
    }
    return count;
  }

  /**
   * Enforces max capacity using LRU eviction.
   */
  private enforceCapacity(): void {
    if (this.assignments.size < this.maxCapacity) {
      return;
    }

    this.cleanupExpiredAssignments();
    if (this.assignments.size < this.maxCapacity) {
      return;
    }

    // Evict oldest by lastActiveAt
    let oldestId: string | null = null;
    let oldestTime = Infinity;

    for (const [id, rec] of this.assignments.entries()) {
      if (rec.lastActiveAt < oldestTime) {
        oldestTime = rec.lastActiveAt;
        oldestId = id;
      }
    }

    if (oldestId) {
      this.assignments.delete(oldestId);
    }
  }

  public getActiveDeceptionCount(): number {
    return this.assignments.size;
  }

  /**
   * Returns true if a session assignment exists in store.
   */
  public hasSession(sessionId: string): boolean {
    if (!sessionId) return false;
    return this.assignments.has(sessionId);
  }

  public clearAllAssignments(): void {
    this.assignments.clear();
  }
}

// Global default singleton for gateway process
export const defaultSessionRouter = new SessionRoutingStore();

