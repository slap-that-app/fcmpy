<?php
declare(strict_types=1);

/*
Suggested table layout (matches fcmpy daemon):

CREATE TABLE `fcm_tokens` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(64) NOT NULL COLLATE 'utf8mb4_general_ci',
    `token` VARCHAR(255) NOT NULL COLLATE 'utf8mb4_general_ci',
    `device_id` VARCHAR(64) NULL DEFAULT NULL COLLATE 'utf8mb4_general_ci',
    `platform` ENUM('android','ios','web') NULL DEFAULT 'android' COLLATE 'utf8mb4_general_ci',
    `active` TINYINT(1) NULL DEFAULT '1',
    `keepalive_last` DATETIME NULL DEFAULT NULL,
    `keepalive_next` DATETIME NULL DEFAULT NULL,
    `keepalive_replay` DATETIME NULL DEFAULT NULL,
    `updated` TIMESTAMP NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
    PRIMARY KEY (`id`) USING BTREE,
    UNIQUE INDEX `uniq_user_token` (`username`, `token`) USING BTREE,
    INDEX `idx_keepalive_next` (`keepalive_next`)
)
ENGINE=InnoDB
COLLATE='utf8mb4_general_ci';

Usage:

    $mgr = new FcmTokenManager($pdo);

    // register or update token (optionally deactivating other tokens for this user)
    $mgr->save('user1', 'AAAA12345', 'device123', 'android', true, true);

    // get all active tokens for user
    $list = $mgr->getByUsername('user1');

    // deactivate a token
    $mgr->deactivate('AAAA12345');

    // record a keepalive reply from client
    $mgr->markKeepaliveReplyByToken('AAAA12345');

    // cleanup inactive tokens older than 30 days
    $removed = $mgr->cleanupInactive();
*/

class FcmTokenManager
{
    private \PDO $pdo;

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /* ---------- Insert or update ---------- */

    /**
     * Save or update a token.
     *
     * @param string      $username
     * @param string      $token
     * @param string|null $deviceId
     * @param string      $platform
     * @param bool        $active
     * @param bool        $deactivateUserTokens  if true, all tokens for this user are deactivated first
     */
    public function save(
        string $username,
        string $token,
        ?string $deviceId = null,
        string $platform = 'android',
        bool $active = true,
        bool $deactivateUserTokens = true
    ): bool {
        if ($deactivateUserTokens) {
            $this->deactivateUser($username);
        }
        $stmt = $this->pdo->prepare("
            INSERT INTO fcm_tokens (username, token, device_id, platform, active)
            VALUES (:u, :t, :d, :p, :a)
            ON DUPLICATE KEY UPDATE
                device_id = VALUES(device_id),
                platform  = VALUES(platform),
                active    = VALUES(active),
                updated   = CURRENT_TIMESTAMP
        ");
        return $stmt->execute([
            ':u' => $username,
            ':t' => $token,
            ':d' => $deviceId,
            ':p' => $platform,
            ':a' => $active ? 1 : 0
        ]);
    }

    /* ---------- Queries ---------- */

    public function getByUsername(string $username, bool $onlyActive = true): array
    {
        $sql = "SELECT * FROM fcm_tokens WHERE username = :u";
        if ($onlyActive) {
            $sql .= " AND active = 1";
        }
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':u' => $username]);
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    public function getByToken(string $token): ?array
    {
        $stmt = $this->pdo->prepare("SELECT * FROM fcm_tokens WHERE token = :t LIMIT 1");
        $stmt->execute([':t' => $token]);
        $row = $stmt->fetch(\PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    public function listActive(?string $platform = null): array
    {
        $sql = "SELECT * FROM fcm_tokens WHERE active = 1";
        $params = [];
        if ($platform) {
            $sql .= " AND platform = :p";
            $params[':p'] = $platform;
        }
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    /* ---------- State change ---------- */

    public function activate(string $token): bool
    {
        $stmt = $this->pdo->prepare("UPDATE fcm_tokens SET active = 1 WHERE token = :t");
        return $stmt->execute([':t' => $token]);
    }

    public function deactivate(string $token): bool
    {
        $stmt = $this->pdo->prepare("UPDATE fcm_tokens SET active = 0 WHERE token = :t");
        return $stmt->execute([':t' => $token]);
    }

    public function deactivateUser(string $username): bool
    {
        $stmt = $this->pdo->prepare("UPDATE fcm_tokens SET active = 0 WHERE username = :u");
        return $stmt->execute([':u' => $username]);
    }

    public function delete(string $token): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM fcm_tokens WHERE token = :t");
        return $stmt->execute([':t' => $token]);
    }

    public function deleteUser(string $username): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM fcm_tokens WHERE username = :u");
        return $stmt->execute([':u' => $username]);
    }

    /* ---------- Keepalive reply helpers ---------- */

    /**
     * Mark that client replied to keepalive for a specific token.
     * This updates keepalive_replay to NOW().
     */
    public function markKeepaliveReplyByToken(string $token): bool
    {
        $stmt = $this->pdo->prepare("
            UPDATE fcm_tokens
               SET keepalive_replay = NOW()
             WHERE token = :t
        ");
        return $stmt->execute([':t' => $token]);
    }

    /**
     * Mark keepalive reply for all active tokens of a user.
     * Useful if you only know username at PHP level.
     */
    public function markKeepaliveReplyByUser(string $username): bool
    {
        $stmt = $this->pdo->prepare("
            UPDATE fcm_tokens
               SET keepalive_replay = NOW()
             WHERE username = :u
               AND active = 1
        ");
        return $stmt->execute([':u' => $username]);
    }

    /* ---------- Utility ---------- */

    public function countActive(string $username): int
    {
        $stmt = $this->pdo->prepare("SELECT COUNT(*) FROM fcm_tokens WHERE username = :u AND active = 1");
        $stmt->execute([':u' => $username]);
        return (int)$stmt->fetchColumn();
    }

    public function cleanupInactive(int $days = 30): int
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM fcm_tokens
             WHERE active = 0
               AND updated < (NOW() - INTERVAL :d DAY)
        ");
        $stmt->bindValue(':d', $days, \PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }
}
