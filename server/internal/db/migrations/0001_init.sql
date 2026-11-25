-- Users are created on first authenticated request; sub is the sso.moonl.cloud subject.
CREATE TABLE IF NOT EXISTS users (
    sub VARCHAR(255) NOT NULL PRIMARY KEY,
    display_name VARCHAR(255) NOT NULL,
    created_at DATETIME(3) NOT NULL,
    updated_at DATETIME(3) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One row per registered installation. The device token is stored only as its SHA-256.
-- et_host is the device's host number inside the owner's EasyTier /24 (2..254).
CREATE TABLE IF NOT EXISTS devices (
    id CHAR(32) CHARACTER SET ascii NOT NULL PRIMARY KEY,
    user_sub VARCHAR(255) NOT NULL,
    name VARCHAR(64) NOT NULL,
    kind VARCHAR(16) CHARACTER SET ascii NOT NULL,
    public_key BINARY(32) NOT NULL,
    token_hash BINARY(32) NOT NULL,
    et_host SMALLINT UNSIGNED NULL,
    created_at DATETIME(3) NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    UNIQUE KEY uq_devices_token_hash (token_hash),
    UNIQUE KEY uq_devices_user_public_key (user_sub, public_key),
    UNIQUE KEY uq_devices_user_et_host (user_sub, et_host),
    CONSTRAINT fk_devices_user FOREIGN KEY (user_sub) REFERENCES users (sub) ON DELETE CASCADE,
    CONSTRAINT ck_devices_kind CHECK (kind IN ('host', 'viewer')),
    CONSTRAINT ck_devices_et_host CHECK (et_host IS NULL OR et_host BETWEEN 2 AND 254)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- One EasyTier network per user. The network secret never leaves the server; it is
-- stored sealed with the server master key (AES-256-GCM).
CREATE TABLE IF NOT EXISTS et_networks (
    user_sub VARCHAR(255) NOT NULL PRIMARY KEY,
    network_name VARCHAR(64) CHARACTER SET ascii NOT NULL,
    secret_sealed VARBINARY(256) NOT NULL,
    cidr VARCHAR(18) CHARACTER SET ascii NOT NULL,
    created_at DATETIME(3) NOT NULL,
    UNIQUE KEY uq_et_networks_name (network_name),
    CONSTRAINT fk_et_networks_user FOREIGN KEY (user_sub) REFERENCES users (sub) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
