-- Executes once, when docker creates postgres volume pgdata empty.
-- Will create extensions
-- Will create tables

-- ==================================================
-- timing-attack-pia
-- Initial schema and seed data
-- Runs automatically on first DB startup (empty pgdata volume)
-- To re-run: docker compose down -v && docker compose up
-- ==================================================

-- Enable UUID generation function (gen_random_uuid)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -------------------------------------------------------
-- Table: users
-- Stores fictional Mexican government identifiers (CURP, RFC, NSS)
-- All sensitive fields are intentional co-located to maximiza
-- demo impact when an attacker enumerates valid accounts
-- -------------------------------------------------------
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    date_of_birth DATE NOT NULL,
    phone VARCHAR(20) NOT NULL,
    curp CHAR(18) UNIQUE NOT NULL,
    rfc CHAR(13) UNIQUE NOT NULL,
    nss CHAR(11) UNIQUE NOT NULL,
    security_question VARCHAR(255) NOT NULL,
    security_answer_hash VARCHAR(255) NOT NULL,
    role VARCHAR(10) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users (email);

-- -------------------------------------------------------
-- Table: sessions
-- Simple session store. One row per active login
-- Sessions expire by checking expires_at on each request
-- -------------------------------------------------------
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token VARCHAR(128) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sessions_token ON sessions (token);
CREATE INDEX idx_sessions_user_id ON sessions (user_id);

-- -------------------------------------------------------
-- Table: password_resets
-- One row per active passwrod reset flow. Created by /forgot-password,
-- marked verified by /forgot-password/answer, consumed by
-- /forgot-password/reset (wi=hich deletes the row).
-- -------------------------------------------------------
CREATE TABLE password_resets (
    token VARCHAR(128) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    answer_verified BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_resets_user_id ON password_resets (user_id);