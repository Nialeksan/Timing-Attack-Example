// ====================================================
// timing-attack-pia: Idempotent database seeder
// Runs once on `docker compose up` after the db service is healthy
// Inserts 1 admin + 4 users only when the users table is empty
// On subsequent runs, detects exiting data and exits without changes
// ====================================================
import bcrypt from 'bycrypt';
import pg from 'pg';

const { Client } = pg;

const ROUNDS = parseInt(process.env.BCRYPT_ROUNDS ?? '10', 10);

const accounts = [
    {
        email: 'admin@pia.mx',
        password: 'Admin1234!',
        full_name: 'Administrador del Sistema',
        date_of_birth: '1985-03-12',
        phone: '8112345678',
        curp: 'AOSA850312HNLLRD09',
        rfc: 'AOSA850312H7A',
        nss: '12345678901',
        security_question: '¿Cuál es tu película favorita?',
        security_answer: 'matrix',
        role: 'admin',
    },
    {
        email: 'juan.garcia@correo.mx',
        password: 'Password1!',
        full_name: 'Juan Carlos García Hernández',
        date_of_birth: '1992-07-21',
        phone: '8113345678',
        curp: 'GAHJ920721HNLNRR05',
        rfc: 'GAHJ920721JK2',
        nss: '23456789012',
        security_question: '¿Cómo se llamaba tu primera mascota?',
        security_answer: 'rex',
        role: 'user',
    },
    {
        email: 'maria.lopez@correo.mx',
        password: 'Password1!',
        full_name: 'María Fernanda López Ruiz',
        date_of_birth: '1990-11-03',
        phone: '8114456789',
        curp: 'LORM901103MNLPZR04',
        rfc: 'LORM901103M52',
        nss: '34567890123',
        security_question: '¿Cómo se llamaba tu primera mascota?',
        security_answer: 'luna',
        role: 'user',
    },
    {
        email: 'carlos.ramos@correo.mx',
        password: 'Password1!',
        full_name: 'Carlos Eduardo Ramos Vega',
        date_of_birth: '1988-01-15',
        phone: '8115567890',
        curp: 'RAVC880115HNLMGR07',
        rfc: 'RAVC880115AB1',
        nss: '45678901234',
        security_question: '¿En qué ciudad naciste?',
        security_answer: 'monterrey',
        role: 'user',
    },
    {
        email: 'sofia.mendez@correo.mx',
        password: 'Password1!',
        full_name: 'Sofía Alejandra Méndez Torres',
        date_of_birth: '1995-09-28',
        phone: '8116678901',
        curp: 'METS950928MNLNRR03',
        rfc: 'METS950928XY9',
        nss: '56789012345',
        security_question: '¿Cuál es el nombre de tu mejor amigo de la infancia?',
        security_answer: 'michi',
        role: 'user',
    },
];

// ESM: top-leve await. No need for an async main() wrapper
const client = new Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
console.log('[seeder] connected to database');

try {
    const { rows } = await client.query('SELECT COUNT(*)::int AS count FROM users');
    if (rows[0].count > 0) {
        console.log(`[seeder] users table already has ${rows[0].count} rows. Skipping seeding.`);
    } else {
        console.log('[seeder] users table empty. Seeding...');

        for (const acc of accounts) {
            const passwordHash = await bcrypt.hash(acc.password, ROUNDS);
            const answerHash = await bcrypt.hash(acc.security_answer.toLowerCase(), ROUNDS);

            await client.query(
                `INSERT INTO users (email, password_hash, full_name, date_of_birth, phone, curp, rfc, nss, security_question, security_answer_hash, role)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                [
                    acc.email,
                    passwordHash,
                    acc.full_name,
                    acc.date_of_birth,
                    acc.phone,
                    acc.curp,
                    acc.rfc,
                    acc.nss,
                    acc.security_question,
                    answerHash,
                    acc.role,
                ]
            );

            console.log(`[seeder] seeded ${acc.email.padEnd(5)} ${acc.role}`);
        }

        console.log(`[seeder] done. Seeded ${accounts.length} users.`);
    }
} catch (err) {
    console.log('[seeder] failed:', err);
    process.exit(1);
} finally {
    await client.end();
}