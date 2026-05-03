// ===================================================================
// auth.js: The show star, with VULNERABLE authentication for the
// timing-leak demo
//
// /api/auth/login is intentionally vulnerable:
//      - Returns IMMEDIATELY when the email is not found (no bcrypt run)
//      - Runs bcrytp only when the email exists
//      - Time difference (~2ms vs ~60ms) leaks user existence
//
// /api/auth/forgot-password is the secondary vector (Vector 2)
//
// This dile is the centrepiece of the live demo. Do NOT clean up the timing
// leak, that defeats the educational purpose. The patched equivalents
// live in auth.secure.js
// ===================================================================
import { Router } from 'express';
import bcrypt from 'bcrypt';
import crypto from 'node:crypto';
import {
    createSession,
    setSessionCookie,
    clearSessionCookie,
    destroySession,
    requireAuth,
} from '../middleware/session.js';
import { pool, query } from '../db.js';

const router = Router();
const BCRYPT_ROUNDS = 10;
const RESET_TTL_MINUTES = 30;

// -----------------------------------------------------
// POST /api/auth/register
// -----------------------------------------------------
router.post('/register', async (req, res) => {
    // For production level, better use Zod validation library
    const requiredFields = [
        'email', 'password', 'full_name', 'date_of_birth',
        'phone', 'curp', 'rfc', 'nss', 'security_question', 'security_answer'
    ];

    const missingFields = requiredFields.filter(field => !req.body[field]);

    if (missingFields.length > 0) {
        return res.status(400).json({ message: `Missing required fields: ${missingFields.join(', ')}` });
    }

    const {
        email,
        password,
        full_name,
        date_of_birth,
        phone,
        curp,
        rfc,
        nss,
        security_question,
        security_answer,
    } = req.body ?? {};

    try {
        const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const answerHash = await bcrypt.hash(security_answer.toLowerCase(), BCRYPT_ROUNDS);

        const { rows } = await query(
            `INSERT INTO users (
                email, password_hash, full_name, date_of_birth, phone,
                curp, rfc, nss, security_question, security_answer_hash, role
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'user')
            RETURNING id`,
            [email, passwordHash, full_name, date_of_birth, phone, curp, rfc, nss, security_question, answerHash]
        );

        // If the following throws error, user will be created without token. Important note, but this system is for demonstrations purposes
        const token = await createSession(rows[0].id);
        setSessionCookie(res, token);

        res.status(201).json({ message: 'Account created successfully!!!' });
    } catch (err) {
        if (err.code === '23505') {
            // Unique violation: email, CURP, RFC, or NSS duplicated
            return res.status(409).json({ message: 'An account already exists with that information' });
        }
        console.error('[register] error:', err);
        res.status(500).json({ message: 'Error creating the account' });
    }
});

// -----------------------------------------------------
// POST /api/auth/forgot-password <- VULNERABLE
//
// Same enumeration pattern as /login: if the user does not
// exist, return immediately without doing the db write or generating
// a token.
//
// Real-rorld systems would always respond identically and send the
// reset token via email. The patched version (auth.secure.js) does exactly
// that structurally.
// -----------------------------------------------------
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body ?? {};

    if (!email) {
        return res.status(400).json({ message: 'Email required' });
    }

    const { rows } = await query(
        'SELECT id, security_question FROM users WHERE email = $1',
        [email]
    );

    // The BUG!!!
    // Early return when user not found. No token created, no DB write.
    if (rows.length === 0) {
        return res.status(404).json({ message: 'No account found' });
    }

    const user = rows[0];
    const resetToken = crypto.randomBytes(64).toString('hex');
    const expiresAt = new Date(Date.now() + RESET_TTL_MINUTES * 60 * 1000);

    await query(
        'INSERT INTO password_resets (token, user_id, expires_at) VALUES ($1, $2, $3)',
        [resetToken, user.id, expiresAt]
    );

    res.json({
        reset_token: resetToken,
        security_question: user.security_question,
    });
});

// -----------------------------------------------------
// POST /api/auth/forgot-password/answer <- VULNERABLE
//
// Verifies the security answer against the stored hash. Two timing
// leaks here:
//  1. Early return if the reset_token does not exist (no JOIN, no bcrypt)
//  2. Early return if the token expired (check before bcrypt.compare)
// Both leak wether the previous step is succeded for a given email
// -----------------------------------------------------
router.post('/forgot-password/answer', async (req, res) => {
    const { reset_token, answer } = req.body ?? {};

    if (!reset_token || !answer) {
        return res.status(400).json({ message: 'Token and answer required' });
    }

    const { rows } = await query(
        `SELECT pr.token, pr.expires_at, u.security_answer_hash
        FROM password_resets pr
        JOIN users u ON u.id = pr.user_id
        WHERE pr.token = $1`,
        [reset_token]
    );

    // The BUG!!!
    // Early return if token unknown or expired. No bcrypt.compare runs.
    if (rows.length === 0 || new Date(rows[0].expires_at) < new Date()) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }

    const matches = await bcrypt.compare(
        answer.toLowerCase(),
        rows[0].security_answer_hash
    );

    if (!matches) {
        return res.status(401).json({ message: 'Incorrect answer' });
    }

    await query(
        'UPDATE password_resets SET answer_verified = TRUE WHERE token = $1',
        [reset_token]
    );

    res.json({ message: 'Answer verified successfully!' });
});

// -----------------------------------------------------
// POST /api/auth/forgot-password/reset
// 
// Final step. Requires a verified reset_token (answer_verified = TRUE)
// Update the user's password_hash and consumes the reset row
//
// Not a timing-attack vector itself, but by this point the attacker has
// already crleared steps 1 and 2. No need for early-return obfuscation.
// -----------------------------------------------------
router.post('/forgot-password/reset', async (req, res) => {
    const { reset_token, new_password } = req.body ?? {};

    if (!reset_token || !new_password) {
        return res.status(400).json({ message: 'Token and new password required' });
    }

    const { rows } = await query(
        `SELECT user_id, answer_verified, expires_at
        FROM password_resets
        WHERE token = $1`,
        [reset_token]
    );

    if (
        rows.length === 0 ||
        rows[0].answer_verified !== true ||
        new Date(rows[0].expires_at) < new Date()
    ) {
        return res.status(401).json({ message: 'Invalid, unverified or expired token' });
    }

    const newHash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);

    // Update the password and consume the tokenin a single transaction
    // so a crash mid-flow does not leave a stale token usable
    const client = await pool.connect(); // We need to tie the entire transaction to a single connection. If we use query, BEGIN and UPDATE might be in different pool connections, breaking database logic
    try {
        // BEGIN, UPDATE, DELETE, and COMMIT travels through the same connection tunel
        // To avoid idle in transaction in case something breaks, we separate sql instructions into different awaits
        await client.query('BEGIN');
        await client.query(
            `UPDATE users SET password_hash = $1
            WHERE id = $2`,
            [newHash, rows[0].user_id]
        );
        await client.query(
            `DELETE FROM password_resets WHERE token = $1`,
            [reset_token]
        );
        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[forgotten-password/reset] transaction failed:', err);
        return res.status(500).json({ message: 'Could not reset password' });
    } finally {
        client.release();
    }

    res.json({ message: 'Password reset successfully!' });
});

// -----------------------------------------------------
// POST /api/auth/login <- VULNERABLE
//
// Time leak: if the user does not exisr, we return immediately
// without ever calling bcrypt.compare. This produces a 
// measurable time difference an attacker can use to enumerate 
// valid emails.
// -----------------------------------------------------
router.post('/login', async (req, res) => {
    const { email, password } = req.body ?? {};

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password required' });
    }

    const { rows } = await query(
        'SELECT id, password_hash FROM users WHERE email = $1',
        [email]
    );

    // The BUG!!!
    // Early return when user not found. Bcrypt never runs.
    if (rows.length === 0) {
        return res.status(401).json({ message: 'Email or password incorrect' });
    }

    const user = rows[0];
    const matches = await bcrypt.compare(password, user.password_hash);

    if (!matches) {
        return res.status(401).json({ message: 'Email or password incorrect' });
    }

    const token = await createSession(user.id);
    setSessionCookie(res, token);

    res.json({ message: 'Logged in successfully!' });
});

// -----------------------------------------------------
// POST /api/auth/logout
// -----------------------------------------------------
router.post('/logout', async (req, res) => {
    await destroySession(req.sessionToken);
    clearSessionCookie(res);
    res.json({ message: 'Session closed' });
});

// -----------------------------------------------------
// POST /api/auth/me
// -----------------------------------------------------
router.get('/me', requireAuth, (req, res) => {
    res.json({ user: req.user });
});

export default router;