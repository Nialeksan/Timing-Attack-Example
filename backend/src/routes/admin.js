import { Router } from 'express';
import { query } from '../db.js';
import { requireAdmin, requireAuth } from '../middleware/session.js';

const router = Router();

router.get('/users', requireAuth, requireAdmin, async (req, res) => {
    const { rows } = await query(
        `SELECT id, full_name, email, date_of_birth, phone, curp, rfc, nss, role, created_at
        FROM users
        ORDER BY created_at ASC`
    );
    res.json(rows);
});

export default router;