// =====================================================================
// 01_constraints.cypher
// Contraintes d'unicité et index.
// Garantissent l'intégrité du modèle et accélèrent les MATCH sur clés.
// (Syntaxe Neo4j 5.x)
// =====================================================================

CREATE CONSTRAINT user_name        IF NOT EXISTS FOR (u:User)          REQUIRE u.name IS UNIQUE;
CREATE CONSTRAINT machine_name     IF NOT EXISTS FOR (m:Machine)       REQUIRE m.name IS UNIQUE;
CREATE CONSTRAINT service_name     IF NOT EXISTS FOR (s:Service)       REQUIRE s.name IS UNIQUE;
CREATE CONSTRAINT vuln_cve         IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve  IS UNIQUE;
CREATE CONSTRAINT group_name       IF NOT EXISTS FOR (g:Group)         REQUIRE g.name IS UNIQUE;
CREATE CONSTRAINT resource_name    IF NOT EXISTS FOR (r:Resource)      REQUIRE r.name IS UNIQUE;

// Index secondaires utiles pour l'analyse
CREATE INDEX machine_criticality   IF NOT EXISTS FOR (m:Machine)       ON (m.criticality);
CREATE INDEX vuln_score            IF NOT EXISTS FOR (v:Vulnerability) ON (v.score);
