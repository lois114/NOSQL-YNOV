// =====================================================================
// 06_bonus_risk_scoring.cypher  (BONUS)
// Scoring de risque par machine + classification des vulnérabilités
// + proposition de segmentation réseau.
// =====================================================================

// --- B1 : Classification des vulnérabilités par criticité -----------
MATCH (v:Vulnerability)
RETURN v.severity AS categorie,
       count(*)   AS nombre,
       collect(v.name + " (" + toString(v.score) + ")") AS vulnerabilites
ORDER BY categorie;

// --- B2 : Score de risque par machine -------------------------------
// Risque = somme des scores CVSS des vulns NON corrigées
//          + bonus de criticité de la machine
//          + bonus si exposée sur Internet.
MATCH (m:Machine)
OPTIONAL MATCH (m)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: "unpatched"})
WITH m,
     coalesce(sum(v.score), 0) AS score_vulns,
     CASE m.criticality
        WHEN "critical" THEN 10
        WHEN "high"     THEN 7
        WHEN "medium"   THEN 4
        ELSE 1
     END AS poids_criticite
WITH m, score_vulns, poids_criticite,
     CASE WHEN m.internet_exposed THEN 5 ELSE 0 END AS poids_internet
RETURN m.name        AS machine,
       m.criticality AS criticite,
       m.internet_exposed AS exposee_internet,
       round(score_vulns + poids_criticite + poids_internet, 1) AS score_de_risque
ORDER BY score_de_risque DESC;

// --- B3 : Surface d'attaque (services exposés + Internet) ------------
MATCH (m:Machine)-[:EXPOSES]->(s:Service)
RETURN m.name AS machine,
       m.internet_exposed AS exposee_internet,
       count(s) AS nb_services_exposes,
       collect(s.name + ":" + toString(s.port)) AS services
ORDER BY m.internet_exposed DESC, nb_services_exposes DESC;

// --- B4 : Machines "pivot" les plus dangereuses ---------------------
// Degré entrant + sortant de CONNECTED_TO = centralité dans le réseau.
MATCH (m:Machine)
OPTIONAL MATCH (m)-[out:CONNECTED_TO]->()
OPTIONAL MATCH ()-[in:CONNECTED_TO]->(m)
RETURN m.name AS machine,
       count(DISTINCT out) AS connexions_sortantes,
       count(DISTINCT in)  AS connexions_entrantes,
       count(DISTINCT out) + count(DISTINCT in) AS centralite
ORDER BY centralite DESC;

// --- B5 : Comptes à privilèges exposés sur des postes vulnérables ---
// Un compte admin/security dont la machine utilisée porte une vuln non corrigée.
MATCH (u:User)-[:USES]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability {status: "unpatched"})
WHERE u.privilege_level IN ["admin", "security"]
RETURN u.name AS compte_sensible,
       u.privilege_level AS niveau,
       m.name AS poste_utilise,
       collect(v.cve) AS vulns_non_corrigees;

// --- B6 : Liens réseau à supprimer/limiter (segmentation) -----------
// Connexions directes d'un poste utilisateur vers un serveur sensible :
// candidates idéales à un cloisonnement par VLAN / pare-feu.
MATCH (a:Machine)-[:CONNECTED_TO]->(b:Machine)
WHERE a.type = "workstation" AND b.criticality IN ["high", "critical"]
RETURN a.name AS poste, b.name AS serveur_sensible, b.criticality AS criticite,
       "À cloisonner (VLAN / pare-feu)" AS recommandation;
