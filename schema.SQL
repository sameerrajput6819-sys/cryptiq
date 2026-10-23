-- CRYPTIQ database schema (MySQL 8.0.16+ or MariaDB 10.2+; CHECK constraints need these versions).
-- Safe to re-run: tables use IF NOT EXISTS and seed rows are upserted by name/title.
--
--   mysql -u root -p < schema.sql
--
-- NOTE: this file contains NO passwords. Create the application's database user separately (see README).

CREATE DATABASE IF NOT EXISTS cryptiq
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cryptiq;

-- ---------------------------------------------------------------------------
-- 1. users: registered accounts. Only a salted password HASH is stored.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  user_id       INT          NOT NULL AUTO_INCREMENT,
  username      VARCHAR(100) NOT NULL,
  email         VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 2. analysis_history: optional, user-saved report NUMBERS only.
--    Never stores the tested password, or any hash of it.
--    ON DELETE RESTRICT: a user row cannot be removed while reports exist.
--    Deleting an account is an explicit, deliberate operation (DELETE /api/account
--    removes the child rows and the user inside one transaction).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analysis_history (
  analysis_id       INT           NOT NULL AUTO_INCREMENT,
  user_id           INT           NOT NULL,
  password_length   INT           NOT NULL,
  estimated_entropy DECIMAL(10,2) NOT NULL,
  strength_category VARCHAR(50)   NOT NULL,
  analysis_date     TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (analysis_id),
  KEY idx_analysis_user_date (user_id, analysis_date),
  CONSTRAINT fk_analysis_user FOREIGN KEY (user_id)
    REFERENCES users (user_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT chk_analysis_length  CHECK (password_length > 0),
  CONSTRAINT chk_analysis_entropy CHECK (estimated_entropy >= 0)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 3. attack_scenarios: predefined, ILLUSTRATIVE guessing-speed assumptions.
--    Public: readable without an account.
--    guesses_per_second is a whole number, so sub-1/s rates cannot be stored exactly.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_scenarios (
  scenario_id        INT             NOT NULL AUTO_INCREMENT,
  scenario_name      VARCHAR(100)    NOT NULL,
  guesses_per_second BIGINT UNSIGNED NOT NULL,
  description        TEXT            NULL,
  created_at         TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (scenario_id),
  UNIQUE KEY uq_scenario_name (scenario_name)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 4. security_tips: educational lessons. Public: readable without an account.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_tips (
  tip_id           INT          NOT NULL AUTO_INCREMENT,
  title            VARCHAR(200) NOT NULL,
  content          TEXT         NOT NULL,
  category         VARCHAR(100) NULL,
  difficulty_level VARCHAR(50)  NULL,
  PRIMARY KEY (tip_id),
  UNIQUE KEY uq_tip_title (title),
  KEY idx_tips_category (category)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- 5. quiz_results: quiz scores for authenticated users only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS quiz_results (
  result_id       INT       NOT NULL AUTO_INCREMENT,
  user_id         INT       NOT NULL,
  score           INT       NOT NULL,
  total_questions INT       NOT NULL,
  completed_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (result_id),
  KEY idx_quiz_user_date (user_id, completed_at),
  CONSTRAINT fk_quiz_user FOREIGN KEY (user_id)
    REFERENCES users (user_id) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT chk_quiz_total CHECK (total_questions > 0),
  CONSTRAINT chk_quiz_score CHECK (score >= 0 AND score <= total_questions)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------------
-- Seed data: attack scenarios (illustrative assumptions, NOT measurements).
-- These mirror the four reference scenarios already built into script.js.
-- ---------------------------------------------------------------------------
INSERT INTO attack_scenarios (scenario_name, guesses_per_second, description) VALUES
 ('Online, rate-limited login', 1,
  'Assumption: guesses go through a live login form that throttles attempts (modelled here as at most 1 guess per second; real throttled logins are often slower and may lock accounts). Actual speed depends on the site''s rate limits, lockouts and multifactor authentication.'),
 ('Online, high-speed API', 1000,
  'Assumption: a poorly protected online API accepts about 1,000 guesses per second with no lockout. Real services vary widely; many block or slow this traffic.'),
 ('Offline, slow hash (bcrypt/Argon2)', 10000,
  'Assumption: an attacker holds a stolen database of slow, salted hashes and can test about 10,000 guesses per second. Actual speed depends on the algorithm''s cost settings and the attacker''s hardware.'),
 ('Offline, fast hash (MD5/NTLM, GPU)', 100000000000,
  'High-speed hypothetical: a stolen database of fast, unsalted hashes attacked with powerful GPUs at about 100 billion guesses per second. Real rates depend on the exact hash algorithm and hardware, and are not guaranteed.')
ON DUPLICATE KEY UPDATE
  guesses_per_second = VALUES(guesses_per_second),
  description        = VALUES(description);

-- ---------------------------------------------------------------------------
-- Seed data: educational security tips.
-- ---------------------------------------------------------------------------
INSERT INTO security_tips (title, content, category, difficulty_level) VALUES
 ('Creating strong passphrases',
  'A passphrase is several unrelated words chosen at random, for example by dice or a generator. Length is what protects it: five or six random words from a large list are both strong and memorable. Do not pick words yourself from a song, quote or personal detail, because those choices are predictable. Adding a number or symbol to a predictable phrase helps far less than adding another random word.',
  'Passwords', 'Beginner'),
 ('Using a password manager',
  'A password manager generates and stores a different long random password for every account, so you only memorize one strong master passphrase. It also fills passwords only on the real site, which helps against fake login pages. Protect the manager itself with a long unique passphrase and multifactor authentication.',
  'Passwords', 'Beginner'),
 ('Multi-factor authentication (MFA)',
  'MFA asks for a second proof of identity besides your password, such as a hardware security key, a passkey, or a code from an authenticator app. Even if a password leaks, an attacker still needs the second factor. App-based codes and security keys are generally safer than SMS codes, but any MFA is better than none.',
  'Authentication', 'Beginner'),
 ('Avoiding password reuse',
  'Attackers replay leaked username-password pairs on other services, an attack called credential stuffing. If you reuse a password, one breach can unlock many accounts, however strong the password is. Use a unique password per account, and change a password immediately if you learn it was exposed.',
  'Passwords', 'Beginner'),
 ('Understanding password entropy',
  'Entropy, measured in bits, describes how unpredictable a password is: each extra bit doubles the number of guesses needed. The formula H = L x log2(R) is valid only when each of L characters is chosen independently and uniformly at random from R possibilities, as a generator does. Human-made passwords are predictable, so this formula overstates their strength. Treat any entropy figure as an estimate, not a guarantee.',
  'Concepts', 'Intermediate'),
 ('Recognizing phishing',
  'Phishing tricks you into giving credentials to a fake site or message. Warning signs include urgent threats, unexpected attachments, mismatched sender addresses and links to look-alike domains. Instead of clicking, open the service by typing its address or using your bookmark. A password manager that refuses to autofill on an unfamiliar domain is a useful warning, and security keys and passkeys resist phishing.',
  'Awareness', 'Beginner'),
 ('Using breached-password protection safely',
  'Breach-check services let you learn whether a password has appeared in known leaks. Use a method that never sends the password itself: with k-anonymity, your device hashes the password locally and sends only a short hash prefix, then compares the returned list on your device. Never type a real password into a site that does not explain how it checks. If a password is found in a breach, stop using it everywhere.',
  'Awareness', 'Intermediate'),
 ('How sites should store passwords: hashing and salting',
  'A well-built service never stores your password, only a slow, salted hash made with an algorithm such as Argon2id, bcrypt or scrypt. A unique random salt per account stops precomputed tables and forces attackers to crack each account separately, and a slow algorithm sharply reduces how many guesses per second they can make after a database theft.',
  'Concepts', 'Advanced'),
 ('Online vs offline guessing attacks',
  'Online attacks target a live login and are limited by rate limits, lockouts and MFA. Offline attacks start from a stolen database of hashes and run as fast as the attacker''s hardware allows, so they are the reason long random passwords matter. Guessing speeds in simulators are illustrative assumptions; real speeds depend on hardware, the hashing algorithm and defenses.',
  'Concepts', 'Intermediate')
ON DUPLICATE KEY UPDATE
  content          = VALUES(content),
  category         = VALUES(category),
  difficulty_level = VALUES(difficulty_level);