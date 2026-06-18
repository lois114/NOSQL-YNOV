// =====================================================================
// 05_attack_paths.cypher
// Étape 4 — Analyse des chemins d'attaque.
// Hypothèse : la machine PC-ALICE est compromise (phishing).
// =====================================================================

// --- A1 : Chemin(s) de PC-ALICE vers le contrôleur de domaine -------
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine {name: "DC-01"})
RETURN path;

// --- A2 : Le plus court chemin vers DC-01 (bonus : shortestPath) -----
MATCH (start:Machine {name: "PC-ALICE"}), (target:Machine {name: "DC-01"})
MATCH path = shortestPath((start)-[:CONNECTED_TO*1..6]->(target))
RETURN [n IN nodes(path) | n.name] AS chemin_le_plus_court,
       length(path)               AS nombre_de_sauts;

// --- A3 : Tous les chemins vers les machines CRITIQUES ---------------
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(target:Machine)
WHERE target.criticality = "critical"
RETURN [n IN nodes(path) | n.name] AS chemin,
       target.name                 AS cible_critique,
       length(path)                AS sauts
ORDER BY sauts;

// --- A4 : Machines vulnérables atteignables depuis PC-ALICE ----------
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name        AS machine,
       v.cve         AS cve,
       v.name        AS vulnerabilite,
       v.score       AS score,
       v.status      AS statut,
       length(path)  AS distance_reseau
ORDER BY v.score DESC;

// --- A5 : Ressources sensibles atteignables depuis PC-ALICE ----------
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
RETURN r.name          AS ressource,
       r.sensitivity   AS sensibilite,
       m.name          AS hebergee_sur,
       [n IN nodes(path) | n.name] AS chemin
ORDER BY r.sensitivity DESC;

// --- A6 : Utilisateurs disposant de droits d'administration ---------
MATCH (u:User)-[:ADMIN_OF]->(m:Machine)
RETURN u.name AS utilisateur, collect(m.name) AS machines_administrees;

// --- A7 : Utilisateurs accédant à des machines sensibles via groupe --
MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
WHERE m.criticality IN ["high", "critical"]
RETURN u.name        AS utilisateur,
       g.name        AS groupe,
       m.name        AS machine,
       m.criticality AS criticite
ORDER BY m.criticality DESC, u.name;

// --- A8 : Chemin de REBOND PAR LES CREDENTIALS (bonus) --------------
// PC-ALICE -> PC-BOB (réseau) ; or charlie (ADMIN_OF DC-01) UTILISE PC-BOB.
// Compromettre PC-BOB = voler les identifiants admin = accès direct à DC-01.
MATCH credPath = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..3]->(pivot:Machine)
                 <-[:USES]-(admin:User)-[:ADMIN_OF]->(target:Machine)
WHERE target.criticality = "critical"
RETURN [n IN nodes(credPath) | n.name] AS chemin_reseau,
       admin.name  AS compte_admin_vole_sur_pivot,
       pivot.name  AS machine_pivot,
       target.name AS cible_finale
ORDER BY target.name;

// --- A9 : Chemin COMPLET réseau -> machine -> ressource critique -----
MATCH path = (start:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..5]->(m:Machine)-[:HOSTS]->(r:Resource)
WHERE r.sensitivity = "critical"
RETURN [n IN nodes(path) | n.name] AS chemin,
       r.name AS ressource_critique
ORDER BY size([n IN nodes(path) | n.name]);
