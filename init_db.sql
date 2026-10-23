CREATE DATABASE gmao_db;
CREATE USER app_gmao_user WITH ENCRYPTED PASSWORD 'MotDePasseTresRobuste2026!';

\c gmao_db

CREATE TABLE equipements (
    id SERIAL PRIMARY KEY,
    code_actif VARCHAR(30) UNIQUE NOT NULL,
    nom VARCHAR(100) NOT NULL,
    zone_atelier VARCHAR(50) NOT NULL,
    ip_equipement VARCHAR(45) NOT NULL,
    statut VARCHAR(30) NOT NULL CHECK (statut IN ('En service', 'En maintenance', 'En panne')),
    derniere_inspection DATE NOT NULL DEFAULT CURRENT_DATE,
    commentaire TEXT,
    modifie_par VARCHAR(60) NOT NULL,
    date_modification TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE journal_audit (
    id SERIAL PRIMARY KEY,
    horodatage TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    utilisateur VARCHAR(60) NOT NULL,
    role_utilisateur VARCHAR(30) NOT NULL,
    ip_source VARCHAR(45) NOT NULL,
    action VARCHAR(50) NOT NULL,
    details TEXT NOT NULL
);

GRANT CONNECT ON DATABASE gmao_db TO app_gmao_user;
GRANT USAGE ON SCHEMA public TO app_gmao_user;
GRANT SELECT, INSERT, UPDATE ON TABLE equipements TO app_gmao_user;
GRANT SELECT, INSERT ON TABLE journal_audit TO app_gmao_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_gmao_user;

INSERT INTO equipements (code_actif, nom, zone_atelier, ip_equipement, statut, derniere_inspection, commentaire, modifie_par) VALUES
('AUTOMATE-01', 'Automate programmable Siemens S7-1500', 'Atelier Assemblage A', '10.10.200.11', 'En service', '2026-10-01', 'RAS - Firmware à jour', 'system_init'),
('ROBOT-KUKA-04', 'Bras robotisé de soudure KUKA KR-16', 'Ligne Soudure B', '10.10.200.24', 'En maintenance', '2026-10-15', 'Remplacement du servomoteur axe 3 en cours', 'system_init'),
('POMPE-HYD-02', 'Groupe hydraulique haute pression P2', 'Zone Pressage C', '10.10.200.45', 'En service', '2026-09-28', 'Pression nominale 250 bars vérifiée', 'system_init'),
('FOUR-IND-01', 'Four de traitement thermique F-900', 'Fonderie Nord', '10.10.200.80', 'En panne', '2026-10-20', 'Sonde thermique défaillante - Pièce commandée', 'system_init');
