-- 資格取るぞー！アプリ — DDL
-- Run this against your Supabase (PostgreSQL) database.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- TBL_USER  (prefix: use)
-- ============================================================
CREATE TABLE IF NOT EXISTS TBL_USER (
    useid UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    usenm VARCHAR(100) NOT NULL,
    useml VARCHAR(255) NOT NULL,
    usepw VARCHAR(255) NOT NULL,          -- argon2id hash
    usetm TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    useup TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_useml UNIQUE (useml)
);

CREATE INDEX IF NOT EXISTS idx_user_useml ON TBL_USER (useml);

-- ============================================================
-- TBL_CERMAS  (certification master, prefix: cer)
-- ============================================================
CREATE TABLE IF NOT EXISTS TBL_CERMAS (
    cerid UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cernm VARCHAR(255) NOT NULL,
    cerct VARCHAR(100) NOT NULL DEFAULT '',   -- category
    certm TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_cernm UNIQUE (cernm)
);

CREATE INDEX IF NOT EXISTS idx_cermas_cernm ON TBL_CERMAS (cernm);

-- ============================================================
-- TBL_OWNCER  (user's own certifications, prefix: own)
-- ============================================================
CREATE TABLE IF NOT EXISTS TBL_OWNCER (
    ownid UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    ownus UUID          NOT NULL REFERENCES TBL_USER (useid) ON DELETE CASCADE,
    ownnm VARCHAR(255)  NOT NULL,                    -- cert name (denormalized for flexibility)
    ownce UUID          REFERENCES TBL_CERMAS (cerid) ON DELETE SET NULL,  -- master link (nullable)
    ownst VARCHAR(20)   NOT NULL DEFAULT 'studying'  -- studying | passed | failed | abandoned
        CHECK (ownst IN ('studying','passed','failed','abandoned')),
    owntg DATE          ,                            -- target date (nullable)
    ownhr NUMERIC(6,1)  NOT NULL DEFAULT 0           -- study hours (0.5 step)
        CHECK (ownhr >= 0),
    ownfl BOOLEAN       NOT NULL DEFAULT FALSE,      -- TRUE = physically deleted (hidden)
    owntm TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    ownup TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_owncer_ownus ON TBL_OWNCER (ownus);
CREATE INDEX IF NOT EXISTS idx_owncer_ownst ON TBL_OWNCER (ownst);

-- ============================================================
-- TBL_FAVORI  (favorites, prefix: fav)
-- ============================================================
CREATE TABLE IF NOT EXISTS TBL_FAVORI (
    favid UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    favus UUID        NOT NULL REFERENCES TBL_USER (useid) ON DELETE CASCADE,  -- who favorited
    favtg UUID        NOT NULL REFERENCES TBL_USER (useid) ON DELETE CASCADE,  -- target user
    favtm TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_fav_pair UNIQUE (favus, favtg),
    CONSTRAINT chk_fav_self CHECK (favus <> favtg)
);

CREATE INDEX IF NOT EXISTS idx_favori_favus ON TBL_FAVORI (favus);
CREATE INDEX IF NOT EXISTS idx_favori_favtg ON TBL_FAVORI (favtg);

-- ============================================================
-- TBL_SESSION  (sessions, prefix: ses)
-- ============================================================
CREATE TABLE IF NOT EXISTS TBL_SESSION (
    sesid UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    sesus UUID         NOT NULL REFERENCES TBL_USER (useid) ON DELETE CASCADE,
    sestk VARCHAR(512) NOT NULL,     -- JWT token (for revocation lookup)
    sesex TIMESTAMPTZ  NOT NULL,     -- expires_at
    sestm TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_sestk UNIQUE (sestk)
);

CREATE INDEX IF NOT EXISTS idx_session_sesus ON TBL_SESSION (sesus);
CREATE INDEX IF NOT EXISTS idx_session_sestk ON TBL_SESSION (sestk);

-- Auto-update useup on TBL_USER row change
CREATE OR REPLACE FUNCTION fn_set_useup()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.useup = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_user_useup ON TBL_USER;
CREATE TRIGGER trg_user_useup
    BEFORE UPDATE ON TBL_USER
    FOR EACH ROW EXECUTE FUNCTION fn_set_useup();

-- Auto-update ownup on TBL_OWNCER row change
CREATE OR REPLACE FUNCTION fn_set_ownup()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.ownup = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_owncer_ownup ON TBL_OWNCER;
CREATE TRIGGER trg_owncer_ownup
    BEFORE UPDATE ON TBL_OWNCER
    FOR EACH ROW EXECUTE FUNCTION fn_set_ownup();
