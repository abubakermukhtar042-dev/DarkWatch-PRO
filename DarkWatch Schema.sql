-- ============================================================
--  DarkWatch Pro — Dark Web Threat Intelligence Monitor
--  MySQL Database Schema
--  Tables: 11 (Fully Normalized to 3NF / BCNF)
-- ============================================================

DROP DATABASE IF EXISTS darkwatch;
CREATE DATABASE darkwatch CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE darkwatch;

-- ============================================================
-- TABLE 1: country  (Lookup — ISO 3166 Countries)
-- Stores country metadata; separates country data from actors
-- and breaches (eliminates repeating country attributes — 3NF)
-- ============================================================
CREATE TABLE country (
    country_code   CHAR(2)      PRIMARY KEY,          -- ISO-3166 alpha-2
    country_name   VARCHAR(100) NOT NULL,
    region         VARCHAR(50),
    is_high_risk   TINYINT(1)   DEFAULT 0             -- 1 = known threat-origin country
);

-- ============================================================
-- TABLE 2: industry  (Lookup — Sector Classification)
-- Separated from breach_record to avoid repeating criticality
-- data across rows (2NF → 3NF)
-- ============================================================
CREATE TABLE industry (
    industry_id    INT          AUTO_INCREMENT PRIMARY KEY,
    name           VARCHAR(100) NOT NULL UNIQUE,
    criticality    ENUM('Low','Medium','High','Critical') DEFAULT 'Medium'
);

-- ============================================================
-- TABLE 3: analyst  (Internal Security Analysts)
-- Created before risk_alert because risk_alert has FK → analyst
-- ============================================================
CREATE TABLE analyst (
    analyst_id     CHAR(36)     PRIMARY KEY,          -- UUID
    name           VARCHAR(100) NOT NULL,
    email          VARCHAR(150) NOT NULL UNIQUE,
    role           ENUM('junior','analyst','senior','manager') DEFAULT 'analyst',
    specialization VARCHAR(100),
    created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- TABLE 4: threat_actor  (Hacker Groups / APTs / Criminals)
-- country_code FK → country avoids repeating country data (3NF)
-- ============================================================
CREATE TABLE threat_actor (
    actor_id       CHAR(36)     PRIMARY KEY,
    alias          VARCHAR(100) NOT NULL,
    real_name      VARCHAR(100),
    country_code   CHAR(2),
    actor_type     ENUM('nation_state','ransomware_group','criminal_group','hacktivist') NOT NULL,
    motivation     VARCHAR(100),
    sophistication ENUM('Low','Medium','High','Critical'),
    active_since   DATE,
    last_seen      DATE,
    status         ENUM('active','inactive','arrested','disbanded') DEFAULT 'active',
    description    TEXT,
    created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_actor_country FOREIGN KEY (country_code)
        REFERENCES country(country_code) ON DELETE SET NULL
);

-- ============================================================
-- TABLE 5: dark_source  (Dark Web Forums, Leak Sites, Telegram)
-- Normalised separately — a source can appear in many breaches
-- ============================================================
CREATE TABLE dark_source (
    source_id      CHAR(36)     PRIMARY KEY,
    name           VARCHAR(150) NOT NULL,
    source_type    ENUM('forum','leak_site','telegram','paste_site','marketplace') NOT NULL,
    url_pattern    VARCHAR(255),
    tor_address    VARCHAR(255),
    language       VARCHAR(50),
    reliability    TINYINT      DEFAULT 5 CHECK (reliability BETWEEN 1 AND 10),
    is_active      TINYINT(1)   DEFAULT 1,
    discovered_at  DATE,
    description    TEXT
);

-- ============================================================
-- TABLE 6: breach_record  (Core Breach Incident Facts)
-- Central fact table; FKs → industry, country, actor, source
-- Eliminates transitive dependencies (3NF)
-- ============================================================
CREATE TABLE breach_record (
    breach_id        CHAR(36)     PRIMARY KEY,
    organization     VARCHAR(200) NOT NULL,
    industry_id      INT,
    country_code     CHAR(2),
    actor_id         CHAR(36),
    source_id        CHAR(36),
    breach_date      DATE,
    discovered_date  DATE,
    reported_date    DATE,
    breach_type      ENUM('Ransomware','Data Exfiltration','Credential Stuffing',
                          'SQL Injection','Phishing','Supply Chain',
                          'Insider Threat','Zero-Day Exploit') NOT NULL,
    records_exposed  BIGINT       DEFAULT 0,
    data_types       VARCHAR(255),
    ransom_demanded  DECIMAL(15,2),
    ransom_paid      DECIMAL(15,2),
    ransom_currency  VARCHAR(10)  DEFAULT 'USD',
    status           ENUM('active','contained','resolved','unknown') DEFAULT 'active',
    severity         ENUM('Critical','High','Medium','Low') NOT NULL,
    public_disclosed TINYINT(1)   DEFAULT 0,
    description      TEXT,
    created_at       DATETIME     DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_breach_industry FOREIGN KEY (industry_id)
        REFERENCES industry(industry_id) ON DELETE SET NULL,
    CONSTRAINT fk_breach_country  FOREIGN KEY (country_code)
        REFERENCES country(country_code) ON DELETE SET NULL,
    CONSTRAINT fk_breach_actor    FOREIGN KEY (actor_id)
        REFERENCES threat_actor(actor_id) ON DELETE SET NULL,
    CONSTRAINT fk_breach_source   FOREIGN KEY (source_id)
        REFERENCES dark_source(source_id) ON DELETE SET NULL
);

-- ============================================================
-- TABLE 7: leaked_credential  (Credential Batches per Breach)
-- Dependent on breach_record; CASCADE DELETE if breach removed
-- Separated because one breach can have multiple cred types
-- ============================================================
CREATE TABLE leaked_credential (
    cred_id         CHAR(36)     PRIMARY KEY,
    breach_id       CHAR(36)     NOT NULL,
    email_domain    VARCHAR(100),
    credential_type ENUM('email_password','email_hash','full_pii',
                         'financial','session_token','api_key') NOT NULL,
    record_count    BIGINT       DEFAULT 0,
    is_verified     TINYINT(1)   DEFAULT 0,
    is_for_sale     TINYINT(1)   DEFAULT 0,
    asking_price    DECIMAL(12,2),
    sale_currency   VARCHAR(10)  DEFAULT 'USD',
    first_seen      DATE,
    last_seen       DATE,
    sample_hash     VARCHAR(64),                      -- SHA-256 of anonymised sample
    CONSTRAINT fk_cred_breach FOREIGN KEY (breach_id)
        REFERENCES breach_record(breach_id) ON DELETE CASCADE
);

-- ============================================================
-- TABLE 8: malware_sample  (Malware Samples & Hashes)
-- Stored independently; multiple actors can use same malware
-- Unique constraints on hashes enforce data integrity
-- ============================================================
CREATE TABLE malware_sample (
    malware_id     CHAR(36)     PRIMARY KEY,
    name           VARCHAR(150) NOT NULL,
    family         VARCHAR(100),
    malware_type   ENUM('Ransomware','RAT','Backdoor','Worm',
                        'Trojan','Dropper','Toolkit') NOT NULL,
    first_seen     DATE,
    last_seen      DATE,
    hash_md5       CHAR(32)     UNIQUE,
    hash_sha256    CHAR(64)     UNIQUE,
    target_os      VARCHAR(100),
    target_sector  VARCHAR(150),
    description    TEXT,
    is_active      TINYINT(1)   DEFAULT 1
);

-- ============================================================
-- TABLE 9: actor_malware  (M:M Junction — Actors ↔ Malware)
-- Resolves Many-to-Many between threat_actor & malware_sample
-- One actor can develop/use many malwares; one malware can be
-- used by many actors (e.g. Cobalt Strike) — pure BCNF
-- ============================================================
CREATE TABLE actor_malware (
    id             INT          AUTO_INCREMENT PRIMARY KEY,
    actor_id       CHAR(36)     NOT NULL,
    malware_id     CHAR(36)     NOT NULL,
    relationship   ENUM('developer','operator','buyer','attributed') DEFAULT 'developer',
    first_used     DATE,
    UNIQUE KEY uq_actor_malware (actor_id, malware_id),
    CONSTRAINT fk_am_actor   FOREIGN KEY (actor_id)
        REFERENCES threat_actor(actor_id)  ON DELETE CASCADE,
    CONSTRAINT fk_am_malware FOREIGN KEY (malware_id)
        REFERENCES malware_sample(malware_id) ON DELETE CASCADE
);

-- ============================================================
-- TABLE 10: ioc  (Indicators of Compromise)
-- Links to both breach_record and threat_actor (optional FKs)
-- TLP (Traffic Light Protocol) field for sharing classification
-- ============================================================
CREATE TABLE ioc (
    ioc_id         CHAR(36)     PRIMARY KEY,
    breach_id      CHAR(36),
    actor_id       CHAR(36),
    ioc_type       ENUM('ip','domain','hash_md5','hash_sha256',
                        'email','url','bitcoin_wallet','registry_key') NOT NULL,
    value          VARCHAR(512) NOT NULL,
    confidence     TINYINT      DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    is_active      TINYINT(1)   DEFAULT 1,
    first_seen     DATE,
    last_seen      DATE,
    tags           VARCHAR(200),
    tlp_level      ENUM('WHITE','GREEN','AMBER','RED') DEFAULT 'AMBER',
    CONSTRAINT fk_ioc_breach FOREIGN KEY (breach_id)
        REFERENCES breach_record(breach_id) ON DELETE SET NULL,
    CONSTRAINT fk_ioc_actor  FOREIGN KEY (actor_id)
        REFERENCES threat_actor(actor_id)  ON DELETE SET NULL
);

-- ============================================================
-- TABLE 11: risk_alert  (Auto-Generated Security Alerts)
-- FK → breach_record (CASCADE) and analyst (SET NULL)
-- Tracks who is assigned to investigate each alert
-- ============================================================
CREATE TABLE risk_alert (
    alert_id       CHAR(36)     PRIMARY KEY,
    breach_id      CHAR(36)     NOT NULL,
    analyst_id     CHAR(36),
    alert_type     VARCHAR(100) NOT NULL,
    severity       ENUM('Critical','High','Medium','Low') NOT NULL,
    title          VARCHAR(255) NOT NULL,
    description    TEXT,
    is_resolved    TINYINT(1)   DEFAULT 0,
    created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
    resolved_at    DATETIME,
    CONSTRAINT fk_alert_breach  FOREIGN KEY (breach_id)
        REFERENCES breach_record(breach_id) ON DELETE CASCADE,
    CONSTRAINT fk_alert_analyst FOREIGN KEY (analyst_id)
        REFERENCES analyst(analyst_id) ON DELETE SET NULL
);

-- ============================================================
-- INDEXES (Performance Optimization)
-- ============================================================
CREATE INDEX idx_breach_severity    ON breach_record(severity);
CREATE INDEX idx_breach_status      ON breach_record(status);
CREATE INDEX idx_breach_actor       ON breach_record(actor_id);
CREATE INDEX idx_breach_industry    ON breach_record(industry_id);
CREATE INDEX idx_breach_discovered  ON breach_record(discovered_date);
CREATE INDEX idx_ioc_type           ON ioc(ioc_type);
CREATE INDEX idx_ioc_active         ON ioc(is_active);
CREATE INDEX idx_alert_resolved     ON risk_alert(is_resolved);
CREATE INDEX idx_alert_severity     ON risk_alert(severity);
CREATE INDEX idx_cred_breach        ON leaked_credential(breach_id);
CREATE INDEX idx_actor_status       ON threat_actor(status);
CREATE INDEX idx_actor_type         ON threat_actor(actor_type);

-- ============================================================
-- SEED DATA — TABLE 1: country
-- ============================================================
INSERT INTO country VALUES
('RU','Russia',       'Europe',      1),
('CN','China',        'Asia',        1),
('KP','North Korea',  'Asia',        1),
('IR','Iran',         'Middle East', 1),
('UA','Ukraine',      'Europe',      1),
('US','United States','Americas',    0),
('GB','United Kingdom','Europe',     0),
('DE','Germany',      'Europe',      0),
('AU','Australia',    'Oceania',     0),
('CA','Canada',       'Americas',    0),
('IN','India',        'Asia',        0),
('FR','France',       'Europe',      0),
('BR','Brazil',       'Americas',    0),
('JP','Japan',        'Asia',        0),
('AE','UAE',          'Middle East', 0);

-- ============================================================
-- SEED DATA — TABLE 2: industry
-- ============================================================
INSERT INTO industry (name, criticality) VALUES
('Healthcare',       'Critical'),
('Finance',          'Critical'),
('Government',       'Critical'),
('Energy',           'Critical'),
('Telecommunications','Critical'),
('Technology',       'High'),
('Education',        'High'),
('Retail',           'High'),
('Legal',            'High'),
('Insurance',        'High'),
('Transportation',   'High'),
('Manufacturing',    'Medium');

-- ============================================================
-- SEED DATA — TABLE 3: analyst
-- ============================================================
INSERT INTO analyst VALUES
('a1000001-0000-0000-0000-000000000001','Omar Sheikh',  'omar@darkwatch.io', 'senior', 'Ransomware & APT',       NOW()),
('a1000001-0000-0000-0000-000000000002','Nadia Hussain','nadia@darkwatch.io','manager','Dark Web Intelligence',   NOW()),
('a1000001-0000-0000-0000-000000000003','Bilal Raza',   'bilal@darkwatch.io','analyst','Credential Monitoring',  NOW()),
('a1000001-0000-0000-0000-000000000004','Sara Malik',   'sara@darkwatch.io', 'senior', 'Malware Analysis',       NOW());

-- ============================================================
-- SEED DATA — TABLE 4: threat_actor
-- ============================================================
INSERT INTO threat_actor
    (actor_id,alias,real_name,country_code,actor_type,motivation,sophistication,active_since,last_seen,status,description) VALUES
('b1000001-0000-0000-0000-000000000001','LockBit',          NULL,  'RU','ransomware_group','Financial',        'High',    '2019-01-01','2024-09-01','active',  'Most prolific ransomware group globally. Operates RaaS with 1000+ affiliates.'),
('b1000001-0000-0000-0000-000000000002','ALPHV/BlackCat',    NULL,  'RU','ransomware_group','Financial',        'High',    '2021-11-01','2024-03-01','inactive','Rust-written RaaS behind MGM Resorts and Change Healthcare breaches.'),
('b1000001-0000-0000-0000-000000000003','Cl0p',              NULL,  'UA','ransomware_group','Financial',        'High',    '2019-02-01','2023-12-01','active',  'Exploited MOVEit zero-day affecting 2500+ organizations worldwide.'),
('b1000001-0000-0000-0000-000000000004','APT29 / Cozy Bear','SVR', 'RU','nation_state',    'Espionage',        'Critical','2008-01-01','2024-10-01','active',  'Russian SVR intelligence group behind SolarWinds supply chain attack.'),
('b1000001-0000-0000-0000-000000000005','APT41',             NULL,  'CN','nation_state',    'Espionage',        'Critical','2012-01-01','2024-08-01','active',  'Chinese dual espionage and financial cybercrime group.'),
('b1000001-0000-0000-0000-000000000006','Scattered Spider',  NULL,  'US','criminal_group',  'Financial',        'High',    '2022-01-01','2024-09-01','active',  'English-speaking group behind MGM Resorts and Caesars Entertainment attacks.'),
('b1000001-0000-0000-0000-000000000007','ShinyHunters',      NULL,  'FR','criminal_group',  'Financial',        'Medium',  '2020-01-01','2024-07-01','active',  'Prolific database theft group; sells on BreachForums.'),
('b1000001-0000-0000-0000-000000000008','REvil / Sodinokibi',NULL,  'RU','ransomware_group','Financial',        'High',    '2019-04-01','2022-01-01','arrested','Behind Kaseya and JBS Food attacks. Key members arrested Jan 2022.'),
('b1000001-0000-0000-0000-000000000009','Lazarus Group',    'RGB', 'KP','nation_state',    'Financial',        'Critical','2009-01-01','2024-10-01','active',  'North Korean state group stealing billions in crypto to fund regime.'),
('b1000001-0000-0000-0000-000000000010','Vice Society',      NULL,  'RU','ransomware_group','Financial',        'Medium',  '2021-06-01','2023-10-01','active',  'Targets education and healthcare with double extortion.'),
('b1000001-0000-0000-0000-000000000011','Volt Typhoon',      NULL,  'CN','nation_state',    'Espionage',        'Critical','2021-01-01','2024-10-01','active',  'Chinese APT pre-positioning in US critical infrastructure systems.'),
('b1000001-0000-0000-0000-000000000012','Sandworm',         'GRU', 'RU','nation_state',    'Espionage',        'Critical','2009-01-01','2024-09-01','active',  'GRU Unit 74455 — behind NotPetya and Ukraine power grid attacks.');

-- ============================================================
-- SEED DATA — TABLE 5: dark_source
-- ============================================================
INSERT INTO dark_source VALUES
('c1000001-0000-0000-0000-000000000001','BreachForums',         'forum',      'breachforums[.]st','breachforums***.onion','English',9,1,'2022-03-01','Primary dark web marketplace for leaked databases post-RaidForums.'),
('c1000001-0000-0000-0000-000000000002','LockBit Blog',          'leak_site',  'lockbit3[.]onion', 'lockbit3***.onion',   'Multi',  10,1,'2019-09-01','Official LockBit victim leak portal and ransom negotiation site.'),
('c1000001-0000-0000-0000-000000000003','ALPHV Leak Site',       'leak_site',  'alphvmmm[.]onion', 'alphvmmm***.onion',   'English',9,0,'2021-11-01','ALPHV/BlackCat ransomware group data publication blog.'),
('c1000001-0000-0000-0000-000000000004','Cl0p Leak Site',        'leak_site',  'clop[.]onion',     'clop***.onion',       'English',9,1,'2020-03-01','Cl0p ransomware victim data publication and extortion site.'),
('c1000001-0000-0000-0000-000000000005','XSS[.]is Forum',        'forum',      'xss[.]is',         'xss***.onion',        'Russian',8,1,'2018-06-01','Russian-language cybercrime forum and exploit marketplace.'),
('c1000001-0000-0000-0000-000000000006','Exploit[.]in',          'forum',      'exploit[.]in',     NULL,                  'Russian',7,1,'2005-01-01','Long-running Russian darknet cybercrime marketplace.'),
('c1000001-0000-0000-0000-000000000007','Telegram: DataBreaches','telegram',   't.me/databreaches',NULL,                  'English',6,1,'2021-01-01','Telegram channel aggregating breach announcements.'),
('c1000001-0000-0000-0000-000000000008','RaidForums Archive',    'forum',      'raidforums[.]ws',  'raidf***.onion',      'English',5,0,'2015-01-01','Archived mirror of the seized RaidForums stolen data marketplace.'),
('c1000001-0000-0000-0000-000000000009','Paste[.]ee Dark',       'paste_site', 'paste[.]ee',       NULL,                  'English',4,1,'2012-01-01','Paste site used for small credential and config dumps.'),
('c1000001-0000-0000-0000-000000000010','Genesis Market',        'marketplace','genesis[.]market',  'genesis***.onion',   'English',8,0,'2017-01-01','Stolen browser session and fingerprint underground marketplace.');

-- ============================================================
-- SEED DATA — TABLE 6: breach_record  (20 sample breaches)
-- ============================================================
INSERT INTO breach_record
    (breach_id,organization,industry_id,country_code,actor_id,source_id,
     breach_date,discovered_date,reported_date,breach_type,records_exposed,
     data_types,ransom_demanded,ransom_paid,ransom_currency,status,severity,public_disclosed,description)
VALUES
('d1000001-0000-0000-0000-000000000001','Change Healthcare',   1,'US','b1000001-0000-0000-0000-000000000002','c1000001-0000-0000-0000-000000000003','2024-02-21','2024-02-22',NULL,'Ransomware',      100000000,'Medical Records,PII,SSN',22000000,22000000,'USD','resolved', 'Critical',1,'ALPHV ransomware attack disrupted US healthcare payments nationwide.'),
('d1000001-0000-0000-0000-000000000002','MGM Resorts',         8,'US','b1000001-0000-0000-0000-000000000006','c1000001-0000-0000-0000-000000000001','2023-09-11','2023-09-12',NULL,'Ransomware',       6000000,'PII,Payment Cards,SSN',30000000,NULL,       'USD','resolved', 'Critical',1,'Scattered Spider social-engineered IT help desk to deploy BlackCat ransomware.'),
('d1000001-0000-0000-0000-000000000003','AT&T',                5,'US','b1000001-0000-0000-0000-000000000007','c1000001-0000-0000-0000-000000000001','2024-04-01','2024-07-12',NULL,'Data Exfiltration',73000000,'Phone Records,Call Logs',NULL,NULL,              'USD','resolved', 'Critical',1,'73M customer call records stolen and published on BreachForums.'),
('d1000001-0000-0000-0000-000000000004','MOVEit Transfer Users',6,'US','b1000001-0000-0000-0000-000000000003','c1000001-0000-0000-0000-000000000004','2023-05-27','2023-06-01',NULL,'Zero-Day Exploit', 77000000,'PII,SSN,Financial Records',NULL,NULL,         'USD','contained','Critical',1,'Cl0p exploited MOVEit zero-day CVE-2023-34362 affecting 2500+ organizations.'),
('d1000001-0000-0000-0000-000000000005','LastPass',            6,'US','b1000001-0000-0000-0000-000000000006','c1000001-0000-0000-0000-000000000007','2022-08-01','2022-12-22',NULL,'Supply Chain',     33000000,'Password Vaults,Encrypted Keys',NULL,NULL,     'USD','resolved', 'Critical',1,'Threat actor stole encrypted password vaults of 33M users.'),
('d1000001-0000-0000-0000-000000000006','Medibank',            1,'AU','b1000001-0000-0000-0000-000000000001','c1000001-0000-0000-0000-000000000002','2022-10-13','2022-10-25',NULL,'Ransomware',        9700000,'Medical Records,PII',10000000,NULL,             'AUD','resolved', 'Critical',1,'LockBit published all stolen data after Medibank refused to pay ransom.'),
('d1000001-0000-0000-0000-000000000007','T-Mobile',            5,'US','b1000001-0000-0000-0000-000000000007','c1000001-0000-0000-0000-000000000001','2023-01-19','2023-01-19',NULL,'Data Exfiltration', 37000000,'PII,SSN,DOB,Phone',NULL,NULL,                'USD','resolved', 'High',    1,'ShinyHunters sold 37M T-Mobile customer records on dark web forums.'),
('d1000001-0000-0000-0000-000000000008','23andMe',             1,'US','b1000001-0000-0000-0000-000000000007','c1000001-0000-0000-0000-000000000001','2023-10-01','2023-10-06',NULL,'Credential Stuffing',6900000,'DNA Data,PII,Ancestry',NULL,NULL,             'USD','resolved', 'High',    1,'Attacker used credential stuffing to steal DNA profiles of 6.9M users.'),
('d1000001-0000-0000-0000-000000000009','HCA Healthcare',      1,'US','b1000001-0000-0000-0000-000000000003','c1000001-0000-0000-0000-000000000001','2023-07-05','2023-07-10',NULL,'Data Exfiltration', 11000000,'PII,Medical Scheduling',NULL,NULL,             'USD','resolved', 'High',    1,'11M patient records stolen and posted to a dark web hacking forum.'),
('d1000001-0000-0000-0000-000000000010','Optus',               5,'AU','b1000001-0000-0000-0000-000000000006','c1000001-0000-0000-0000-000000000009','2022-09-22','2022-09-22',NULL,'Data Exfiltration', 11200000,'PII,Passport,License,DOB',NULL,NULL,           'USD','resolved', 'Critical',1,'Unauthenticated API exposed personal data of 11.2M Optus customers.'),
('d1000001-0000-0000-0000-000000000011','Latitude Financial',  2,'AU','b1000001-0000-0000-0000-000000000009','c1000001-0000-0000-0000-000000000005','2023-03-16','2023-03-16',NULL,'Data Exfiltration', 14000000,'PII,Passport,License,Financial',NULL,NULL,      'USD','resolved', 'Critical',1,'Lazarus Group stole 14M customer records from Australian fintech.'),
('d1000001-0000-0000-0000-000000000012','Sony',                6,'JP','b1000001-0000-0000-0000-000000000003','c1000001-0000-0000-0000-000000000001','2023-09-25','2023-09-26',NULL,'Data Exfiltration',  250000,'Source Code,Employee Data,IP',NULL,NULL,        'USD','contained','Medium',  1,'Cl0p published 260K Sony files via MOVEit zero-day exploitation.'),
('d1000001-0000-0000-0000-000000000013','Dish Network',        5,'US','b1000001-0000-0000-0000-000000000001','c1000001-0000-0000-0000-000000000002','2023-02-23','2023-02-27',NULL,'Ransomware',         300000,'Employee PII,SSN,Financial',1000000,1000000,  'BTC','resolved', 'High',    1,'LockBit ransomware took Dish offline for weeks. Paid $1M ransom.'),
('d1000001-0000-0000-0000-000000000014','Uber',                6,'US','b1000001-0000-0000-0000-000000000006','c1000001-0000-0000-0000-000000000007','2022-09-15','2022-09-15',NULL,'Phishing',           57000000,'Source Code,Internal Tools',NULL,NULL,          'USD','resolved', 'High',    1,'Scattered Spider used MFA fatigue attack on an Uber contractor.'),
('d1000001-0000-0000-0000-000000000015','Maximus',             3,'US','b1000001-0000-0000-0000-000000000003','c1000001-0000-0000-0000-000000000004','2023-05-29','2023-07-26',NULL,'Zero-Day Exploit',  11000000,'SSN,Medical,PII',NULL,NULL,                   'USD','resolved', 'Critical',1,'US government contractor hit by Cl0p via MOVEit zero-day.'),
('d1000001-0000-0000-0000-000000000016','Duolingo',            7,'US','b1000001-0000-0000-0000-000000000007','c1000001-0000-0000-0000-000000000001','2023-01-13','2023-08-22',NULL,'Data Exfiltration',   2600000,'Emails,Names,Usernames',NULL,NULL,             'USD','resolved', 'Medium',  1,'2.6M Duolingo accounts scraped and sold on BreachForums.'),
('d1000001-0000-0000-0000-000000000017','Royal Mail',          11,'GB','b1000001-0000-0000-0000-000000000001','c1000001-0000-0000-0000-000000000002','2023-01-10','2023-01-11',NULL,'Ransomware',           0,'Internal Systems',80000000,NULL,               'BTC','resolved', 'High',    1,'LockBit encrypted Royal Mail systems disrupting international post.'),
('d1000001-0000-0000-0000-000000000018','WestJet Airlines',    11,'CA','b1000001-0000-0000-0000-000000000005','c1000001-0000-0000-0000-000000000005','2024-06-01','2024-06-04',NULL,'Insider Threat',      350000,'PII,Booking,Payment',NULL,NULL,               'USD','contained','Medium',  0,'Malicious insider exfiltrated customer booking data to competitor.'),
('d1000001-0000-0000-0000-000000000019','Capita',              3,'GB','b1000001-0000-0000-0000-000000000001','c1000001-0000-0000-0000-000000000002','2023-03-22','2023-04-03',NULL,'Ransomware',           90000,'Employee PII,Client Data',25000000,NULL,        'BTC','resolved', 'High',    1,'LockBit attacked UK outsourcing giant Capita serving government depts.'),
('d1000001-0000-0000-0000-000000000020','Shields Health Care', 1,'US','b1000001-0000-0000-0000-000000000009','c1000001-0000-0000-0000-000000000006','2022-03-28','2022-06-13',NULL,'Data Exfiltration',  2300000,'Medical Records,SSN,DOB',NULL,NULL,             'USD','resolved', 'High',    1,'Lazarus Group exfiltrated 2.3M patient records over several months.');

-- ============================================================
-- SEED DATA — TABLE 7: leaked_credential
-- ============================================================
INSERT INTO leaked_credential
    (cred_id,breach_id,email_domain,credential_type,record_count,is_verified,is_for_sale,asking_price,sale_currency,first_seen,last_seen,sample_hash)
VALUES
('e1-0001','d1000001-0000-0000-0000-000000000001','company.com',  'full_pii',       4500000,1,0,NULL,   'USD','2024-02-22','2024-03-01','a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4'),
('e1-0002','d1000001-0000-0000-0000-000000000002','gmail.com',    'email_password',  600000,1,0,NULL,   'USD','2023-09-12','2023-10-01','b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5'),
('e1-0003','d1000001-0000-0000-0000-000000000003','outlook.com',  'email_password', 5000000,0,1,2500,  'USD','2024-07-12','2024-08-01','c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6'),
('e1-0004','d1000001-0000-0000-0000-000000000004','gov.uk',       'full_pii',      10000000,1,1,50000, 'USD','2023-06-01','2023-07-15','d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1'),
('e1-0005','d1000001-0000-0000-0000-000000000005','icloud.com',   'email_hash',    33000000,1,0,NULL,  'USD','2022-12-22','2023-01-10','e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'),
('e1-0006','d1000001-0000-0000-0000-000000000006','hotmail.com',  'full_pii',       9700000,1,1,15000, 'AUD','2022-10-25','2022-11-30','f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3'),
('e1-0007','d1000001-0000-0000-0000-000000000007','yahoo.com',    'email_password', 3700000,1,0,NULL,  'USD','2023-01-20','2023-02-10','a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d5'),
('e1-0008','d1000001-0000-0000-0000-000000000008','gmail.com',    'full_pii',        690000,0,1,800,   'USD','2023-10-06','2023-10-20','b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e6'),
('e1-0009','d1000001-0000-0000-0000-000000000009','edu.au',       'full_pii',       1100000,1,0,NULL,  'USD','2023-07-10','2023-08-01','c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f7'),
('e1-0010','d1000001-0000-0000-0000-000000000010','company.com',  'session_token',  2000000,1,1,5000,  'USD','2022-09-23','2022-10-15','d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a2'),
('e1-0011','d1000001-0000-0000-0000-000000000011','protonmail.com','financial',     1400000,0,1,12000, 'USD','2023-03-18','2023-04-10','e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b3'),
('e1-0012','d1000001-0000-0000-0000-000000000013','outlook.com',  'email_password',  300000,1,0,NULL,  'USD','2023-02-28','2023-03-15','f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c4'),
('e1-0013','d1000001-0000-0000-0000-000000000014','gmail.com',    'api_key',         250000,1,1,3500,  'USD','2022-09-16','2022-10-01','a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d6'),
('e1-0014','d1000001-0000-0000-0000-000000000015','gov.uk',       'full_pii',       1100000,1,0,NULL,  'USD','2023-07-26','2023-08-20','b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e7'),
('e1-0015','d1000001-0000-0000-0000-000000000020','icloud.com',   'full_pii',        230000,1,1,9000,  'USD','2022-06-14','2022-07-01','c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f8');

-- ============================================================
-- SEED DATA — TABLE 8: malware_sample
-- ============================================================
INSERT INTO malware_sample
    (malware_id,name,family,malware_type,first_seen,last_seen,hash_md5,hash_sha256,target_os,target_sector,description,is_active)
VALUES
('f1-0001','LockBit 3.0',     'LockBit',    'Ransomware','2022-06-01','2024-09-01','a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4','aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3','Windows,Linux',    'Finance,Healthcare','Latest LockBit variant with StealBit exfiltration and anti-analysis.',1),
('f1-0002','BlackCat/ALPHV',  'ALPHV',      'Ransomware','2021-11-01','2024-03-01','b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5','bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4','Windows,Linux,ESXi','All sectors',       'Rust cross-platform ransomware with triple extortion capability.',1),
('f1-0003','Cl0p',            'Cl0p',       'Ransomware','2019-02-01','2023-12-01','c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6','cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5','Windows',          'Finance,Energy',    'Used in MOVEit, GoAnywhere, Accellion mass exploitation campaigns.',1),
('f1-0004','SUNBURST',        'SolarWinds', 'Backdoor',  '2020-03-01','2021-01-01','d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1','dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6','Windows',          'Government,Tech',   'Supply-chain DLL backdoor inside SolarWinds Orion software update.',0),
('f1-0005','WannaCry',        'WannaCry',   'Worm',      '2017-05-01','2023-06-01','e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2','ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1','Windows XP/7',     'All sectors',       'Self-propagating ransomworm using NSA EternalBlue SMB exploit.',1),
('f1-0006','AppleJeus',       'AppleJeus',  'Trojan',    '2018-01-01','2024-10-01','f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3','ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2','Windows,macOS',    'Finance,Crypto',    'Fake crypto trading app distributing Lazarus Group RAT payload.',1),
('f1-0007','0ktapus Kit',     '0ktapus',    'Toolkit',   '2022-06-01','2024-09-01','a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d5','aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc4','SaaS',             'Tech,Retail',       'Phishing toolkit targeting Okta SSO; used by Scattered Spider.',1),
('f1-0008','PlugX',           'PlugX',      'RAT',       '2012-01-01','2024-08-01','b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e6','bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd5','Windows',          'Government,Defense','Long-running Chinese APT modular remote access trojan (RAT).',1),
('f1-0009','BlackEnergy 3',   'BlackEnergy','Backdoor',  '2015-01-01','2022-01-01','c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f7','cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee6','Windows/ICS',      'Energy,Government', 'Sandworm backdoor used in 2015 Ukraine power grid cyberattack.',0),
('f1-0010','NotPetya',        'NotPetya',   'Worm',      '2017-06-01','2017-07-01','d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a2','dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff7','Windows',          'All sectors',       'Destructive wiper disguised as ransomware. $10B global damage.',0),
('f1-0011','Cobalt Strike',   'CobaltStrike','Toolkit',  '2012-01-01','2024-10-01','e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b3','ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa2','Windows,Linux',    'All sectors',       'Legitimate pen-test framework widely abused as attacker C2 tool.',1),
('f1-0012','Industroyer2',    'Industroyer','Backdoor',  '2022-04-01','2022-04-30','f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c4','ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb3','Windows/ICS',      'Energy',            'ICS-targeting malware deployed against Ukraine energy grid 2022.',0);

-- ============================================================
-- SEED DATA — TABLE 9: actor_malware (M:M Junction)
-- ============================================================
INSERT INTO actor_malware (actor_id,malware_id,relationship,first_used) VALUES
('b1000001-0000-0000-0000-000000000001','f1-0001','developer','2022-06-01'),
('b1000001-0000-0000-0000-000000000001','f1-0011','operator', '2022-01-01'),
('b1000001-0000-0000-0000-000000000002','f1-0002','developer','2021-11-01'),
('b1000001-0000-0000-0000-000000000003','f1-0003','developer','2019-02-01'),
('b1000001-0000-0000-0000-000000000004','f1-0004','developer','2020-03-01'),
('b1000001-0000-0000-0000-000000000005','f1-0008','developer','2012-01-01'),
('b1000001-0000-0000-0000-000000000006','f1-0007','operator', '2022-06-01'),
('b1000001-0000-0000-0000-000000000006','f1-0011','buyer',    '2023-01-01'),
('b1000001-0000-0000-0000-000000000008','f1-0011','operator', '2020-01-01'),
('b1000001-0000-0000-0000-000000000009','f1-0005','operator', '2017-05-01'),
('b1000001-0000-0000-0000-000000000009','f1-0006','developer','2018-01-01'),
('b1000001-0000-0000-0000-000000000012','f1-0009','developer','2015-01-01'),
('b1000001-0000-0000-0000-000000000012','f1-0010','developer','2017-06-01'),
('b1000001-0000-0000-0000-000000000012','f1-0012','developer','2022-04-01');

-- ============================================================
-- SEED DATA — TABLE 10: ioc
-- ============================================================
INSERT INTO ioc (ioc_id,breach_id,actor_id,ioc_type,value,confidence,is_active,first_seen,last_seen,tags,tlp_level) VALUES
('g1-0001','d1000001-0000-0000-0000-000000000001','b1000001-0000-0000-0000-000000000002','ip',           '185.220.101.45',             95,1,'2024-02-22','2024-03-10','c2,ransomware','RED'),
('g1-0002','d1000001-0000-0000-0000-000000000001','b1000001-0000-0000-0000-000000000002','domain',       'malicious-a1b2c3.onion',     90,1,'2024-02-22','2024-03-10','c2,ransomware','RED'),
('g1-0003','d1000001-0000-0000-0000-000000000002','b1000001-0000-0000-0000-000000000006','ip',           '192.168.45.210',             85,1,'2023-09-12','2023-09-30','phishing,c2','AMBER'),
('g1-0004','d1000001-0000-0000-0000-000000000002','b1000001-0000-0000-0000-000000000006','email',        'threat@d4e5f6.ru',           80,1,'2023-09-11','2023-09-15','phishing',   'AMBER'),
('g1-0005','d1000001-0000-0000-0000-000000000003','b1000001-0000-0000-0000-000000000007','bitcoin_wallet','1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf',72,1,'2024-07-12','2024-08-01','ransom','RED'),
('g1-0006','d1000001-0000-0000-0000-000000000004','b1000001-0000-0000-0000-000000000003','hash_sha256',  'aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3dd4ee5ff6aa1bb2cc3',98,1,'2023-06-01','2023-07-01','malware,exfil','RED'),
('g1-0007','d1000001-0000-0000-0000-000000000004','b1000001-0000-0000-0000-000000000003','url',          'http://evil-a1b2c3d4.net/moveit.jsp',95,1,'2023-06-01','2023-06-30','exploit,c2','RED'),
('g1-0008','d1000001-0000-0000-0000-000000000005','b1000001-0000-0000-0000-000000000006','ip',           '45.141.84.100',              88,1,'2022-08-01','2022-09-01','c2',          'AMBER'),
('g1-0009','d1000001-0000-0000-0000-000000000006','b1000001-0000-0000-0000-000000000001','domain',       'lockbit3-medibank.onion',    99,0,'2022-10-25','2022-11-15','leak_site',   'RED'),
('g1-0010','d1000001-0000-0000-0000-000000000009','b1000001-0000-0000-0000-000000000003','hash_md5',     'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6',87,1,'2023-07-10','2023-08-01','malware','AMBER'),
('g1-0011','d1000001-0000-0000-0000-000000000011','b1000001-0000-0000-0000-000000000009','registry_key', 'HKLM\\Software\\f6a1b2c3',  75,1,'2023-03-17','2023-04-01','persistence', 'AMBER'),
('g1-0012','d1000001-0000-0000-0000-000000000014','b1000001-0000-0000-0000-000000000006','domain',       'okta-uber-sso.phish.com',    97,0,'2022-09-15','2022-09-16','phishing',   'RED'),
('g1-0013','d1000001-0000-0000-0000-000000000015','b1000001-0000-0000-0000-000000000003','ip',           '91.215.153.70',              93,1,'2023-05-29','2023-06-15','c2,exfil',   'RED'),
('g1-0014','d1000001-0000-0000-0000-000000000017','b1000001-0000-0000-0000-000000000001','bitcoin_wallet','3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',88,1,'2023-01-11','2023-02-01','ransom', 'RED'),
('g1-0015','d1000001-0000-0000-0000-000000000019','b1000001-0000-0000-0000-000000000001','url',          'http://capita-leak.lockbit3.onion',99,0,'2023-04-03','2023-04-30','leak_site','RED');

-- ============================================================
-- SEED DATA — TABLE 11: risk_alert
-- ============================================================
INSERT INTO risk_alert
    (alert_id,breach_id,analyst_id,alert_type,severity,title,description,is_resolved,created_at)
VALUES
('h1-0001','d1000001-0000-0000-0000-000000000001','a1000001-0000-0000-0000-000000000001','Ransomware Deployment','Critical','[CRITICAL] ALPHV Ransomware — Change Healthcare','100M medical records compromised. Immediate containment required.',0,'2024-02-22 08:00:00'),
('h1-0002','d1000001-0000-0000-0000-000000000002','a1000001-0000-0000-0000-000000000002','Actor Activity',       'Critical','[CRITICAL] Scattered Spider — MGM Resorts','Social engineering attack confirmed. $30M ransom demanded.',0,'2023-09-12 10:30:00'),
('h1-0003','d1000001-0000-0000-0000-000000000003','a1000001-0000-0000-0000-000000000003','Data for Sale',        'High',    '[HIGH] AT&T — 73M records on BreachForums','Call records and location data listed for sale at $2,500.',0,'2024-07-13 09:00:00'),
('h1-0004','d1000001-0000-0000-0000-000000000004','a1000001-0000-0000-0000-000000000001','New Breach Detected',  'Critical','[CRITICAL] MOVEit Zero-Day — Mass Exploitation','Cl0p actively exploiting CVE-2023-34362. 2500+ orgs at risk.',0,'2023-06-01 06:00:00'),
('h1-0005','d1000001-0000-0000-0000-000000000005','a1000001-0000-0000-0000-000000000002','Leak Published',       'Critical','[CRITICAL] LastPass Vault Data Published','33M encrypted password vaults now in attacker possession.',1,'2022-12-23 14:00:00'),
('h1-0006','d1000001-0000-0000-0000-000000000006','a1000001-0000-0000-0000-000000000004','Ransom Demanded',      'Critical','[CRITICAL] LockBit — Medibank Extortion','AUD 10M demanded. Patient data being published in batches.',1,'2022-10-26 11:00:00'),
('h1-0007','d1000001-0000-0000-0000-000000000008','a1000001-0000-0000-0000-000000000003','Credentials Found',    'High',    '[HIGH] 23andMe — DNA Data for Sale','690K genetic profiles listed on dark web marketplace.',1,'2023-10-07 08:30:00'),
('h1-0008','d1000001-0000-0000-0000-000000000010','a1000001-0000-0000-0000-000000000002','New Breach Detected',  'Critical','[CRITICAL] Optus — API Exposure','11.2M Australian customer records exposed via unauthenticated API.',1,'2022-09-23 07:00:00'),
('h1-0009','d1000001-0000-0000-0000-000000000014','a1000001-0000-0000-0000-000000000001','Actor Activity',       'High',    '[HIGH] Scattered Spider — Uber Breach','MFA fatigue phishing confirmed. Internal tools accessed.',1,'2022-09-16 09:00:00'),
('h1-0010','d1000001-0000-0000-0000-000000000019','a1000001-0000-0000-0000-000000000004','Ransomware Deployment','High',    '[HIGH] LockBit — Capita UK Government','UK government outsourcer attacked. Client data at risk.',1,'2023-04-04 10:00:00');

-- ============================================================
-- USEFUL VIEWS FOR REPORTING
-- ============================================================

-- View 1: Full breach summary with joins
CREATE VIEW v_breach_summary AS
SELECT
    b.breach_id, b.organization, b.breach_type, b.severity, b.status,
    b.records_exposed, b.ransom_demanded, b.ransom_paid,
    b.breach_date, b.discovered_date,
    i.name          AS industry,
    i.criticality   AS industry_criticality,
    co.country_name AS country,
    co.is_high_risk AS country_high_risk,
    ta.alias        AS threat_actor,
    ta.actor_type, ta.sophistication,
    ds.name         AS dark_source,
    ds.source_type
FROM breach_record b
LEFT JOIN industry     i  ON i.industry_id  = b.industry_id
LEFT JOIN country      co ON co.country_code = b.country_code
LEFT JOIN threat_actor ta ON ta.actor_id     = b.actor_id
LEFT JOIN dark_source  ds ON ds.source_id    = b.source_id;

-- View 2: Threat actor statistics
CREATE VIEW v_actor_stats AS
SELECT
    ta.actor_id, ta.alias, ta.actor_type, ta.status, ta.sophistication,
    co.country_name,
    COUNT(DISTINCT b.breach_id)   AS total_breaches,
    SUM(b.records_exposed)        AS total_records_stolen,
    SUM(b.ransom_paid)            AS total_ransom_collected,
    COUNT(DISTINCT am.malware_id) AS malware_count
FROM threat_actor ta
LEFT JOIN country      co ON co.country_code = ta.country_code
LEFT JOIN breach_record b  ON b.actor_id     = ta.actor_id
LEFT JOIN actor_malware am ON am.actor_id    = ta.actor_id
GROUP BY ta.actor_id, ta.alias, ta.actor_type, ta.status, ta.sophistication, co.country_name;

-- View 3: Open alerts with details
CREATE VIEW v_open_alerts AS
SELECT
    ra.alert_id, ra.alert_type, ra.severity, ra.title, ra.created_at,
    b.organization, b.breach_type,
    an.name AS analyst_name, an.role AS analyst_role
FROM risk_alert ra
JOIN breach_record b ON b.breach_id   = ra.breach_id
LEFT JOIN analyst  an ON an.analyst_id = ra.analyst_id
WHERE ra.is_resolved = 0
ORDER BY ra.created_at DESC;

-- ============================================================
-- END OF SCHEMA
-- ============================================================