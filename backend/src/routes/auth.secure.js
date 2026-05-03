// ===================================================================
// auth.secure.js: Patch equivalents of the vulnerable auth routes
//
// Techniques applied:
//  1. DUMMY_HASH: bcrypt always runs regardless of user existance,
//     closing the ~60 ms timing gap that leaks valid emails.
//  2. crypto.timingSafeEqual: final boolean check uses no branch instruction,
//     closing sub-nanosecond branch-prediction leaks.
//  3. Bitwaise & instead of &&: both operands are always evaluated, no
//     short-circuit that a speculative execution attack could observe.
//  4. Always HTTP 200 on /forgot-password-secure: status code alone
//     was leaking user existance in the vulnerable version.
//
// Patched routes mirror the vulnerable ones with a -secure suffix:
//  POST /api/auth/login-secure
//  POST /api/auth/forgot-password-secure
//  POST /api/auth/forgot-password-secure/answer
//  POST /api/auth/forgot-password-secure/reset
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

const BCRYPT_ROUNDS = 10;
const RESET_TTL_MINUTES = 30;
// Computed once at module load (top level await valid in ESM).
// Used as the comparison target when the user or token does not exist,
// so bcrypt always pays its full ~60ms cost regardless of the lookup result.
// The salt is random per server restart. This is intentional, thus hash is never 
// stored or compared against a known value.
const DUMMY_HASH = await bcrypt.hash('__timming_dumy__', BCRYPT_ROUNDS);

const router = Router();

// -----------------------------------------------------
// POST /api/auth/login-secure
//
// Fix for Vector 1: bcrypt.compare always runs.
// DUMMY_HASH is used when the email is not found so the 
// response time is identical for valid and invalid emails.
// timingSafeEqual closes the sub-nanosecond branch-prediction leak
// that a plain === or && comparison leave open.
// -----------------------------------------------------
router.post('/login-secure', async (req, res) => {
    const { email, password } = req.body ?? {};

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password required' });
    }

    const { rows } = await query(
        'SELECT id, password_hash FROM users WHERE email = $1',
        [email]
    );

    const user = rows[0] ?? null;

    // Always compare against a real bcrypt hash.
    // If the user does not exist, DUMMY_HASH keeps bcrypt running
    const hashToCompare = user?.password_hash ?? DUMMY_HASH;
    const passwordMatches = await bcrypt.compare(password, hashToCompare);

    // Bitwise & (no short-circuit) + timingSafeEqual (no branch on result).
    // Both booleans are already computed before this line so no evaluation skipped
    const valid = crypto.timingSafeEqual(
        Buffer.from([Number(user !== null) & Number(passwordMatches)]),
        Buffer.from([1])
    );

    if (!valid) {
        // Same message as the vulnerable route. Different messages are also an observable discrepancy
        return res.status(401).json({ message: 'Email or password incorrect' });
    }

    const token = await createSession(user.id);
    setSessionCookie(res, token);

    res.json({ message: 'Logged in successfully!' });
});

// -----------------------------------------------------
// POST /api/auth/forgot-password-secure
//
// Fix for Vector 2 Step 1: always HTTP 200, regardless of
// wether the email is registered. The vulnerable version returned
// 404 for unknown emails, leaking user existance via status code alone.
//
// The missing DB INSERT for none-existent users creates a <1ms
// timming difference which, within normal network jitter, not exploitable 
// -----------------------------------------------------
router.post('/forgot-password-secure', async (req, res) => {
    const { email } = req.body ?? {};

    if (!email) {
        return res.status(400).json({ message: 'Email required' });
    }

    const { rows } = await query(
        'SELECT id, security_question FROM users WHERE email = $1',
        [email]
    );

    if (rows.length === 0) {
        // User not found responds identically to the success case.
        // In a real system with SMTP implementation, the reset link would arrive
        // by email, so this response is indistinguishable to the requester
        return res.json({ message: 'Check your email for reset instructions' });
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
        message: 'Check your email for reset instructions',
    });
});

// -----------------------------------------------------
// POST /api/auth/forgot-password-secure/answer
//
// Fix for Vector 2 Step 2: bcrypt.compare always runs.
// The vulnerable version early-returned when the token was missing
// or expired, skipping bcrypt and leaking wether Step 1 succeded.
//
// Critical ordering: hashToUse must be resolved BEFORE tokenValid
// is checked, otherwise a branch on tokenValid could skip bcrypt 
// reproducing the original vulnerability.
// -----------------------------------------------------
router.post('/forgot-password-secure/answer', async (req, res) => {
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

    const record = rows[0] ?? null;

    // Resolve the hash first before any branch that could skip bcrypt
    const hashToUse = record?.security_answer_hash ?? DUMMY_HASH;

    // bcrypt always runs here
    const matches = await bcrypt.compare(answer.toLowerCase(), hashToUse);

    // Only now check token validity
    const tokenValid = record !== null && new Date(record.expires_at) >= new Date();

    const valid = crypto.timingSafeEqual(
        Buffer.from([Number(tokenValid) & Number(matches)]),
        Buffer.from([1])
    );

    if (!valid) {
        return res.status(401).json({ message: 'Invalid or expired token' });
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
// Not a timing vector. No bcrypt skipped and the response time is
// uniform regardless of outcome. Implementations is identical to
// vulnerable version. No patch needed because we need the reset_token.
// These token has 512 entropy bits, meaning it cannot be guessed by 
// brute force. If the attacker has it, it was obtained in Step 1 
// (confirmed that email exists) and succesfully passed Step 2
// (confirmed right answer). At this point timing in this enpoint
// does not filter anything new.
// -----------------------------------------------------
router.post('/forgot-password-secure/reset', async (req, res) => {
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
            WHERE ID = $2`,
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


export default router;