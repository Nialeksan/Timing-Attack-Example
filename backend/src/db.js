// =====================================================
// PostgreSQL pool connection: Singleton shared across the app
// Uses pg's built-in pool: opens lazily, recycles idle connections
// =====================================================
import pg from 'pg';

const { Pool } = pg;

export const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
});

pool.on('error', (err) => {
    console.error('[db] unexpected error on idle client:', err);
    process.exit(1);
});

export async function query(text, params) {
    return pool.query(text, params);
}