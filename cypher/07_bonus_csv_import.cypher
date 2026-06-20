// =====================================================================
// 07_bonus_csv_import.cypher  (BONUS — import depuis CSV)
//
// Alternative à 02/03 : charge tout le graphe depuis les fichiers CSV
// du dossier /data via LOAD CSV.
//
// PRÉREQUIS : copier le contenu de ./data dans le dossier "import" de
// Neo4j (ou monter le volume avec Docker, voir docker-compose.yml).
// Lancer d'abord 00_reset.cypher puis 01_constraints.cypher.
// =====================================================================

// --- Nœuds ----------------------------------------------------------
LOAD CSV WITH HEADERS FROM 'file:///users.csv' AS row
CREATE (:User {name: row.name, role: row.role, privilege_level: row.privilege_level});

LOAD CSV WITH HEADERS FROM 'file:///machines.csv' AS row
CREATE (:Machine {
  name: row.name,
  type: row.type,
  criticality: row.criticality,
  internet_exposed: toBoolean(row.internet_exposed),
  last_patch: row.last_patch
});

LOAD CSV WITH HEADERS FROM 'file:///services.csv' AS row
CREATE (:Service {name: row.name, port: toInteger(row.port)});

LOAD CSV WITH HEADERS FROM 'file:///vulnerabilities.csv' AS row
CREATE (:Vulnerability {
  cve: row.cve,
  name: row.name,
  score: toFloat(row.score),
  severity: row.severity,
  status: row.status,
  description: row.description
});

LOAD CSV WITH HEADERS FROM 'file:///groups.csv' AS row
CREATE (:Group {name: row.name, description: row.description});

LOAD CSV WITH HEADERS FROM 'file:///resources.csv' AS row
CREATE (:Resource {name: row.name, sensitivity: row.sensitivity});

// --- Relations (génériques via APOC) --------------------------------
// Nécessite le plugin APOC (inclus dans l'image Docker neo4j fournie).
LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
CALL apoc.cypher.doIt(
  'MATCH (a:' + row.source_label + ' {' + row.source_key + ': $src}) ' +
  'MATCH (b:' + row.target_label + ' {' + row.target_key + ': $dst}) ' +
  'CREATE (a)-[:' + row.rel_type + ']->(b)',
  {src: row.source, dst: row.target}
) YIELD value
RETURN value;

// --- Vérification du chargement -------------------------------------
MATCH (n)            RETURN count(n) AS total_noeuds;
MATCH ()-[r]->()     RETURN count(r) AS total_relations;

// --- Variante SANS APOC ---------------------------------------------
// Si APOC n'est pas disponible, importer les relations type par type, ex. :
//
// LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
// WITH row WHERE row.rel_type = 'CONNECTED_TO'
// MATCH (a:Machine {name: row.source}), (b:Machine {name: row.target})
// CREATE (a)-[:CONNECTED_TO]->(b);
//   ... (répéter pour USES, MEMBER_OF, ADMIN_OF, HAS_ACCESS_TO,
//        EXPOSES, HAS_VULNERABILITY, HOSTS)
