// =====================================================================
// 04_exploration.cypher
// Étape 3 — Requêtes d'exploration du graphe.
// Exécuter une requête à la fois dans Neo4j Browser.
// =====================================================================

// --- Q1 : Afficher tout le graphe -----------------------------------
MATCH (n)
RETURN n;

// --- Q2 : Compter les nœuds par type --------------------------------
MATCH (n)
RETURN labels(n)[0] AS type_noeud, count(*) AS nombre
ORDER BY nombre DESC;

// --- Q3 : Compter les relations par type ----------------------------
MATCH ()-[r]->()
RETURN type(r) AS type_relation, count(*) AS nombre
ORDER BY nombre DESC;

// --- Q4 : Utilisateurs et leurs machines ----------------------------
MATCH (u:User)-[:USES]->(m:Machine)
RETURN u.name AS utilisateur, u.role AS role, m.name AS machine
ORDER BY u.name;

// --- Q5 : Machines critiques ----------------------------------------
MATCH (m:Machine)
WHERE m.criticality = "critical"
RETURN m.name AS machine, m.type AS type, m.criticality AS criticite;

// --- Q6 : Machines vulnérables (triées par score CVSS) --------------
MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name        AS machine,
       v.cve         AS cve,
       v.name        AS vulnerabilite,
       v.score       AS score,
       v.status      AS statut
ORDER BY v.score DESC;

// --- Q7 : Services exposés ------------------------------------------
MATCH (m:Machine)-[:EXPOSES]->(s:Service)
RETURN m.name AS machine, s.name AS service, s.port AS port
ORDER BY m.name, s.port;

// --- Q8 : Appartenance aux groupes ----------------------------------
MATCH (u:User)-[:MEMBER_OF]->(g:Group)
RETURN g.name AS groupe, collect(u.name) AS membres
ORDER BY g.name;
