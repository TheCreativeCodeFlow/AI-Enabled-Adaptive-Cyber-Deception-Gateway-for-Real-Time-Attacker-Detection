import crypto from 'crypto';
import {
  INITIAL_SYNTHETIC_FILES,
  INITIAL_SYNTHETIC_SERVICES,
  INITIAL_SYNTHETIC_USERS,
} from './syntheticData';
import { DeceptionSession } from './types';

export interface SessionStore {
  getSession(sessionId: string): DeceptionSession | null;
  createSession(customSessionId?: string): DeceptionSession;
  saveSession(session: DeceptionSession): void;
  deleteSession(sessionId: string): boolean;
  cleanupExpired(): number;
  getActiveCount(): number;
  clear(): void;
}

export class InMemorySessionStore implements SessionStore {
  private sessions = new Map<string, DeceptionSession>();
  private readonly maxSessions: number;
  private readonly sessionTtlMs: number;

  constructor(maxSessions = 1000, sessionTtlMs = 1800000) {
    this.maxSessions = maxSessions;
    this.sessionTtlMs = sessionTtlMs;
  }

  /**
   * Retrieves an active session, verifying expiration and refreshing sliding TTL.
   */
  public getSession(sessionId: string): DeceptionSession | null {
    if (!sessionId || typeof sessionId !== 'string') {
      return null;
    }

    const session = this.sessions.get(sessionId);
    if (!session) {
      return null;
    }

    const now = Date.now();
    if (now > session.expiresAt) {
      this.sessions.delete(sessionId);
      return null;
    }

    // Refresh sliding window
    session.lastActiveAt = new Date(now).toISOString();
    session.expiresAt = now + this.sessionTtlMs;
    return session;
  }

  /**
   * Creates an isolated new deception session with deep-cloned synthetic initial state.
   */
  public createSession(customSessionId?: string): DeceptionSession {
    this.enforceCapacity();

    const sessionId =
      customSessionId && customSessionId.trim().length >= 8
        ? customSessionId.trim()
        : `sess_${crypto.randomUUID().replace(/-/g, '')}`;

    const now = Date.now();
    const nowIso = new Date(now).toISOString();

    const newSession: DeceptionSession = {
      sessionId,
      createdAt: nowIso,
      lastActiveAt: nowIso,
      expiresAt: now + this.sessionTtlMs,
      authenticatedUser: null,
      observationLevel: 'standard',
      deceptionEnabled: true,
      currentNode: 'entrypoint',
      visitedNodes: ['entrypoint'],
      interactions: [],
      // Deep clone initial synthetic datasets to guarantee session isolation
      dynamicUsers: JSON.parse(JSON.stringify(INITIAL_SYNTHETIC_USERS)),
      dynamicFiles: JSON.parse(JSON.stringify(INITIAL_SYNTHETIC_FILES)),
      dynamicServices: JSON.parse(JSON.stringify(INITIAL_SYNTHETIC_SERVICES)),
    };

    this.sessions.set(sessionId, newSession);
    return newSession;
  }

  /**
   * Persists or updates the session.
   */
  public saveSession(session: DeceptionSession): void {
    this.sessions.set(session.sessionId, session);
  }

  /**
   * Removes a session.
   */
  public deleteSession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /**
   * Evicts expired sessions from memory.
   */
  public cleanupExpired(): number {
    const now = Date.now();
    let evictedCount = 0;

    for (const [id, session] of this.sessions.entries()) {
      if (now > session.expiresAt) {
        this.sessions.delete(id);
        evictedCount++;
      }
    }

    return evictedCount;
  }

  /**
   * Enforces maxSessions limit by first purging expired sessions,
   * then evicting least-recently active sessions if still at capacity.
   */
  private enforceCapacity(): void {
    if (this.sessions.size < this.maxSessions) {
      return;
    }

    this.cleanupExpired();
    if (this.sessions.size < this.maxSessions) {
      return;
    }

    // LRU eviction: remove session with oldest lastActiveAt
    let oldestId: string | null = null;
    let oldestTime = Infinity;

    for (const [id, s] of this.sessions.entries()) {
      const time = new Date(s.lastActiveAt).getTime();
      if (time < oldestTime) {
        oldestTime = time;
        oldestId = id;
      }
    }

    if (oldestId) {
      this.sessions.delete(oldestId);
    }
  }

  public getActiveCount(): number {
    return this.sessions.size;
  }

  public clear(): void {
    this.sessions.clear();
  }
}
