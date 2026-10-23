import os
import logging
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from ldap3 import Server, Connection, ALL, Tls
import ssl

app = Flask(__name__)
# Clé secrète servant à signer et chiffrer le cookie de session de l'utilisateur
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CleSecreteIndusAMU2026_TresLongueEtAleatoire!")

# Configuration sécurisée des cookies de session (Protection contre le vol de session XSS/CSRF)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# --- PARAMÈTRES DE CONNEXION BASE DE DONNÉES (VLAN 70) ---
DB_CONFIG = {
    "host": "10.10.70.10",
    "port": 5432,
    "dbname": "gmao_db",
    "user": "app_gmao_user",
    "password": "MotDePasseTresRobuste2026!",
    "sslmode": "require"  # Exige le chiffrement TLS entre VLAN 60 et VLAN 70
}

# --- PARAMÈTRES ACTIVE DIRECTORY (VLAN 50) ---
AD_ENABLED = True  # Passer à True dès que le serveur Windows AD (10.10.50.10) est prêt
AD_SERVER_IP = "10.10.50.10"
AD_DOMAIN = "nova.test"
AD_BASE_DN = "DC=nova,DC=test"

# --- COMPTES DE SECOURS / DÉMONSTRATION (Mots de passe hachés avec PBKDF2-SHA256) ---
# Permet de démontrer les 4 cas de contrôle d'accès (RBAC) exigés en 1.3
USERS_DEMO = {
    "operateur": {
        "password_hash": generate_password_hash("Operateur2026!"),
        "nom_complet": "Jean Martin (Opérateur Atelier)",
        "role": "LECTURE"       # Peut uniquement consulter les équipements
    },
    "technicien": {
        "password_hash": generate_password_hash("Technicien2026!"),
        "nom_complet": "Sophie Bernard (Maintenance Industrielle)",
        "role": "MAINTENANCE"   # Peut consulter, ajouter et modifier les équipements
    },
    "responsable": {
        "password_hash": generate_password_hash("Responsable2026!"),
        "nom_complet": "Marc Dubois (Responsable SSI / Audit)",
        "role": "ADMIN"         # Lecture + Maintenance + Accès au journal d'audit
    },
    "comptable": {
        "password_hash": generate_password_hash("Comptable2026!"),
        "nom_complet": "Claire Petit (Service Comptabilité)",
        "role": "NON_AUTORISE"  # Salarié de l'entreprise mais NON autorisé sur l'application industrielle
    }
}

# Configuration du fichier de log local (pour envoi vers Syslog central)
logging.basicConfig(
    filename='/var/log/gmao/audit.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def get_db_connection():
    """Établit une connexion chiffrée vers le serveur PostgreSQL du VLAN 70."""
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)

def enregistrer_audit(utilisateur, role, action, details):
    """Enregistre chaque événement dans le fichier Syslog ET dans la base PostgreSQL."""
    ip_source = request.headers.get('X-Forwarded-For', request.remote_addr)
    logging.info(f"USER={utilisateur} ROLE={role} IP={ip_source} ACTION={action} DETAILS={details}")
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO journal_audit (utilisateur, role_utilisateur, ip_source, action, details)
                   VALUES (%s, %s, %s, %s, %s)""",
                (utilisateur, role, ip_source, action, details)
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logging.error(f"Erreur d'écriture d'audit en base : {e}")

def authentifier_active_directory(username, password):
    """Vérifie l'identifiant et les groupes de sécurité sur l'Active Directory (VLAN 50)."""
    try:
        server = Server(AD_SERVER_IP, port=636, use_ssl=True, get_info=ALL)
        user_upn = f"{username}@{AD_DOMAIN}"
        conn = Connection(server, user=user_upn, password=password, auto_bind=True)
        conn.search(AD_BASE_DN, f"(sAMAccountName={username})", attributes=['memberOf', 'displayName'])
        if not conn.entries:
            return None
        entry = conn.entries[0]
        groupes = str(entry.memberOf) if 'memberOf' in entry else ""
        nom = str(entry.displayName) if 'displayName' in entry else username
        
        if "GRP_APP_ADMIN" in groupes:
            role = "ADMIN"
        elif "GRP_APP_MAINTENANCE" in groupes:
            role = "MAINTENANCE"
        elif "GRP_APP_LECTURE" in groupes:
            role = "LECTURE"
        else:
            role = "NON_AUTORISE"
        return {"username": username, "nom_complet": nom, "role": role}
    except Exception as e:
        logging.warning(f"Échec d'authentification AD pour {username} : {e}")
        return None

# --- DÉCORATEURS DE CONTRÔLE D'ACCÈS (RBAC) ---
def connexion_requise(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def role_requis(roles_autorises):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in roles_autorises:
                enregistrer_audit(session["user"], session["role"], "ACCES_INTERDIT_403",
                                  f"Tentative d'accès non autorisé à la route {request.path}")
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- ROUTES DE L'APPLICATION ---

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        user_info = None
        # 1. Test sur Active Directory si activé
        if AD_ENABLED:
            user_info = authentifier_active_directory(username, password)
        
        # 2. Mode comptes locaux sécurisés
        if not user_info and username in USERS_DEMO:
            if check_password_hash(USERS_DEMO[username]["password_hash"], password):
                user_info = {
                    "username": username,
                    "nom_complet": USERS_DEMO[username]["nom_complet"],
                    "role": USERS_DEMO[username]["role"]
                }

        if not user_info:
            enregistrer_audit(username or "inconnu", "AUCUN", "ECHEC_AUTH", "Identifiant ou mot de passe incorrect")
            flash("Identifiant ou mot de passe incorrect.", "danger")
            return render_template("index.html", page="login")

        # Vérification que l'utilisateur fait bien partie des personnes autorisées (Exigence 1.3)
        if user_info["role"] == "NON_AUTORISE":
            enregistrer_audit(username, "NON_AUTORISE", "REFUS_AUTORISATION",
                              "Compte valide mais ne fait pas partie du personnel industriel autorisé")
            flash("Accès refusé : votre compte n'est pas autorisé à accéder à l'application industrielle.", "danger")
            return render_template("index.html", page="login")

        # Connexion acceptée
        session["user"] = user_info["username"]
        session["nom_complet"] = user_info["nom_complet"]
        session["role"] = user_info["role"]
        enregistrer_audit(session["user"], session["role"], "CONNEXION_REUSSIE", "Ouverture de session")
        return redirect(url_for("dashboard"))

    return render_template("index.html", page="login")

@app.route("/logout")
def logout():
    if "user" in session:
        enregistrer_audit(session["user"], session["role"], "DECONNEXION", "Fermeture de session")
        session.clear()
    return redirect(url_for("login"))

@app.route("/")
@connexion_requise
def dashboard():
    statut_filtre = request.args.get("statut", "")
    conn = get_db_connection()
    with conn.cursor() as cur:
        if statut_filtre:
            # Requête paramétrée (%s) protégeant contre toute injection SQL
            cur.execute("SELECT * FROM equipements WHERE statut = %s ORDER BY code_actif", (statut_filtre,))
        else:
            cur.execute("SELECT * FROM equipements ORDER BY code_actif")
        equipements = cur.fetchall()
        
        logs = []
        if session.get("role") == "ADMIN":
            cur.execute("SELECT * FROM journal_audit ORDER BY horodatage DESC LIMIT 25")
            logs = cur.fetchall()
    conn.close()
    return render_template("index.html", page="dashboard", equipements=equipements, logs=logs, statut_filtre=statut_filtre)

@app.route("/equipement/ajouter", methods=["POST"])
@role_requis(["MAINTENANCE", "ADMIN"])
def ajouter_equipement():
    code_actif = request.form.get("code_actif", "").strip().upper()
    nom = request.form.get("nom", "").strip()
    zone_atelier = request.form.get("zone_atelier", "").strip()
    ip_equipement = request.form.get("ip_equipement", "").strip()
    statut = request.form.get("statut", "En service")
    commentaire = request.form.get("commentaire", "").strip()

    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO equipements (code_actif, nom, zone_atelier, ip_equipement, statut, commentaire, modifie_par)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (code_actif, nom, zone_atelier, ip_equipement, statut, commentaire, session["user"])
            )
        conn.commit()
        conn.close()
        enregistrer_audit(session["user"], session["role"], "AJOUT_EQUIPEMENT", f"Ajout de {code_actif} ({statut})")
        flash(f"Équipement {code_actif} ajouté avec succès.", "success")
    except Exception as e:
        flash(f"Erreur lors de l'ajout : vérifiez que le code actif n'existe pas déjà.", "danger")
    return redirect(url_for("dashboard"))

@app.route("/equipement/modifier/<int:eq_id>", methods=["POST"])
@role_requis(["MAINTENANCE", "ADMIN"])
def modifier_equipement(eq_id):
     nouveau_statut = request.form.get("statut")
     nouveau_commentaire = request.form.get("commentaire", "").strip()
     
     conn = get_db_connection()
     with conn.cursor() as cur:
         cur.execute(
             """UPDATE equipements 
                SET statut = %s, commentaire = %s, derniere_inspection = CURRENT_DATE,
                    modifie_par = %s, date_modification = CURRENT_TIMESTAMP
                WHERE id = %s RETURNING code_actif""",
             (nouveau_statut, nouveau_commentaire, session["user"], eq_id)
         )
         res = cur.fetchone()
     conn.commit()
     conn.close()
     
     if res:
         enregistrer_audit(session["user"], session["role"], "MODIF_EQUIPEMENT",
                           f"Mise à jour de {res['code_actif']} -> Statut: {nouveau_statut}")
         flash(f"Équipement {res['code_actif']} mis à jour.", "success")
     return redirect(url_for("dashboard"))

# --- ENDPOINT DE SUPERVISION ZABBIX (VLAN 40 -> VLAN 60) ---
@app.route("/health")
def health_check():
    """Permet à Zabbix (VLAN 40) de vérifier que l'application ET la liaison PostgreSQL (VLAN 70) fonctionnent."""
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
        conn.close()
        return jsonify({"status": "UP", "database": "CONNECTED", "service": "GMAO-Interne"}), 200
    except Exception as e:
        return jsonify({"status": "DOWN", "database": "UNREACHABLE", "error": str(e)}), 503

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
