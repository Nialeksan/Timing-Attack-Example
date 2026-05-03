// =================================================================
// timing-attack-pia: Express server entry point
// Loads env vars, wires defensive middleware (helmet, rate limit, CORS),
// mounts routes, starts listening.
// =================================================================
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import { pool } from './db.js';

import { loadSession } from './middleware/session.js';
// When you export default, you can bring it with a local alias. 
import authRouter from './routes/auth.js';
import authSecureRouter from './routes/auth.secure.js';
import adminRouter from './routes/admin.js';

const app = express();

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN ?? 'http://localhost:5173';

// -------------------------------------------------------------------
// Security headers
// Helmet hardens the app against XSS, clickjacking, MIME sniffing, etc.
// These headers DO NOT MITIGATE TIMING ATTACKS.
// Header hardening and timing safety are orthogonal concerns.
// -------------------------------------------------------------------
app.disable('x-powered-by'); // This hides the fact that we are using Express to the client xd
app.use(helmet());

// -------------------------------------------------------------------
// Rate limiting per IP
// Calibrated high on purpose so the timming-attack exploit can run during
// the live demo. Rate limiting dows NOT defend against timming attacks.
// An attacker only needs ~50 measurements, which fit comfortably under
// any reasonable production limit.
// -------------------------------------------------------------------
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 200,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: {
        message: 'Too many requests, try again later'
    },
});
app.use('/api', apiLimiter);

// -------------------------------------------------------------------
// CORS: Frontend origin only, with credentials for session cookies
// -------------------------------------------------------------------
app.use(cors({
    origin: CORS_ORIGIN,
    credentials: true,
}));

// -------------------------------------------------------------------
// Body and cookie parsing
// -------------------------------------------------------------------
app.use(express.json());
app.use(cookieParser());
app.use(loadSession); // Reads the cookie

// -------------------------------------------------------------------
// Lightweight request logger: Useful for the live demo to show the attacker's
// burst of requests in real time.
// -------------------------------------------------------------------
app.use((req, _res, next) => {
    // res is unused variable, but we need to declare it to use next.
    // Once middleware is over, we use next() to continue to next middleware or final route
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
    next();
});

// -------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------
app.use('/api/auth', authRouter);
app.use('/api/auth', authSecureRouter);
app.use('/api/admin', adminRouter);

app.get('/api/health', async (_req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok' });
    } catch (err) {
        console.error('[health] db error', err);
        res.status(500).json({ status: 'error', message: "Can't connect to database" });
    }
});

// 404 fallback for unmatched API routes
app.use('/api', (_req, res) => {
    res.status(404).json({ status: 'error', message: 'Not found' });
});

// ------------------------------------------------------------
// Start
// ------------------------------------------------------------
app.listen(PORT, () => {
    console.log(`[backend] listening on port ${PORT}`);
    console.log(`[backend] CORS allowing origin ${CORS_ORIGIN}`);
});

// Graceful shutdown: close pool on SIGTERM (docker stop sends this SIGnal TERMination)
process.on('SIGTERM', async () => {
    console.log('[backend] SIGTERM received, closing pool...');
    await pool.end();
    process.exit(0);
});