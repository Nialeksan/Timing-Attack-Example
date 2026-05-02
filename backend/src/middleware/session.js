// =============================================================
// Session Middleware: Token lifecycle and auth gate.
//
// Sessions live in the `sessions` table. The browser holds an HttpOnly
// cookie containing only the random token; the user_id and expiration
// are looked up server-side on every request.
//
// JWT build not important for these demonstration
// =============================================================
import crypto from 'node:crypto';
import { pool } from '../db.js';

const SESSION_COOKIE = 'pia_session';
const TTL_HOURS = parseInt(process.env.SESSION_TTL_HOURS ?? '24', 10);

const cookieOptions = {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: TTL_HOURS * 60 * 60 * 1000,
    path: '/',
};

export async function createSession(userID) {
    const token = crypto.randomBytes(64).toString('hex');
    const expiresAt = new Date(Date.now() + TTL_HOURS * 60 * 60 * 1000);

    await pool.query(
        'INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [userID, token, expiresAt]
    );

    return token;
}

export function setSessionCookie(res, token) {
    res.cookie(SESSION_COOKIE, token, cookieOptions);
}

export function clearSessionCookie(res) {
    res.clearCookie(SESSION_COOKIE, cookieOptions);
}

export async function destroySession(token) {
    if (!token) return;
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
}

// Express middleware: looks up session, attaches req.user if valid.
// Does NOT block, for that, use requireAuth below.
export async function loadSession(req, _res, next) {
    const token = req.cookies?.[SESSION_COOKIE];
    if (!token) return next();

    try {
        const { rows } = await pool.query(
            `SELECT u.id, u.email, u.full_name, u.role, u.curp, u.rfc, u.nss, u.phone, u.date_of_birth, s.expires_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = $1`,
            [token]
        );

        if (rows.length === 0) return next();

        const session = rows[0];
        if (new Date(session.expires_at) < new Date()) {
            // Session expired. Clean it up and ignore
            await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
            return next();
        }

        req.user = {
            id: session.id,
            email: session.email,
            full_name: session.full_name,
            role: session.role,
            curp: session.curp,
            rfc: session.rfc,
            nss: session.nss,
            phone: session.phone,
            date_of_birth: session.date_of_birth,
        };
        req.sessionToken = token;
    } catch (err) {
        console.error('[session] load error:', err);
    }

    next();
}

// Gate that returns 401 if loadSession did not populate req.user
export function requireAuth(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    next();
}

// Gate that returns 403 if the authenticated user is not admin
// Alwais chain after requireAuth
export function requireAdmin(req, res, next) {
    if (req.user?.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden' });
    }
    next();
}

