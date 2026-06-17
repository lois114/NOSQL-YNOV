// =====================================================================
// 03_create_relationships.cypher
// Étape 2 — Création des relations (8 types de relations)
//
//   (:User)-[:USES]->(:Machine)
//   (:User)-[:MEMBER_OF]->(:Group)
//   (:User)-[:ADMIN_OF]->(:Machine)
//   (:Group)-[:HAS_ACCESS_TO]->(:Machine)
//   (:Machine)-[:CONNECTED_TO]->(:Machine)
//   (:Machine)-[:EXPOSES]->(:Service)
//   (:Machine)-[:HAS_VULNERABILITY]->(:Vulnerability)
//   (:Machine)-[:HOSTS]->(:Resource)
//
// Total : 47 relations (> 20 minimum demandé), 8 types de relations.
// =====================================================================

// ---------------------------------------------------------------------
// (:User)-[:USES]->(:Machine)   — 5 relations
// Remarque sécurité : eve (stagiaire) partage PC-ALICE avec alice,
// et charlie (admin) ouvre des sessions sur PC-BOB (poste de dev).
// ---------------------------------------------------------------------
MATCH (u:User {name: "alice"}),   (m:Machine {name: "PC-ALICE"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "eve"}),     (m:Machine {name: "PC-ALICE"}) CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "bob"}),     (m:Machine {name: "PC-BOB"})   CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "PC-BOB"})   CREATE (u)-[:USES]->(m);
MATCH (u:User {name: "diana"}),   (m:Machine {name: "PC-ALICE"}) CREATE (u)-[:USES]->(m);

// ---------------------------------------------------------------------
// (:User)-[:MEMBER_OF]->(:Group)   — 5 relations
// ---------------------------------------------------------------------
MATCH (u:User {name: "alice"}),   (g:Group {name: "RH"})       CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "eve"}),     (g:Group {name: "RH"})       CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "bob"}),     (g:Group {name: "DEV"})      CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "charlie"}), (g:Group {name: "ADMINS"})   CREATE (u)-[:MEMBER_OF]->(g);
MATCH (u:User {name: "diana"}),   (g:Group {name: "SECURITY"}) CREATE (u)-[:MEMBER_OF]->(g);

// ---------------------------------------------------------------------
// (:User)-[:ADMIN_OF]->(:Machine)   — 3 relations
// charlie est l'administrateur des serveurs critiques.
// ---------------------------------------------------------------------
MATCH (u:User {name: "charlie"}), (m:Machine {name: "DC-01"})      CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "SRV-DB"})     CREATE (u)-[:ADMIN_OF]->(m);
MATCH (u:User {name: "charlie"}), (m:Machine {name: "NAS-BACKUP"}) CREATE (u)-[:ADMIN_OF]->(m);

// ---------------------------------------------------------------------
// (:Group)-[:HAS_ACCESS_TO]->(:Machine)   — 7 relations
// Remarque : DEV a un accès direct à SRV-DB (droit trop large).
// ---------------------------------------------------------------------
MATCH (g:Group {name: "RH"}),       (m:Machine {name: "SRV-WEB"})    CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "DEV"}),      (m:Machine {name: "SRV-WEB"})    CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "DEV"}),      (m:Machine {name: "SRV-DB"})     CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "ADMINS"}),   (m:Machine {name: "DC-01"})      CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "ADMINS"}),   (m:Machine {name: "SRV-DB"})     CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "ADMINS"}),   (m:Machine {name: "NAS-BACKUP"}) CREATE (g)-[:HAS_ACCESS_TO]->(m);
MATCH (g:Group {name: "SECURITY"}), (m:Machine {name: "DC-01"})      CREATE (g)-[:HAS_ACCESS_TO]->(m);

// ---------------------------------------------------------------------
// (:Machine)-[:CONNECTED_TO]->(:Machine)   — 8 relations
// Topologie réseau (sens = flux de connexion autorisé).
// ---------------------------------------------------------------------
MATCH (a:Machine {name: "PC-ALICE"}), (b:Machine {name: "SRV-WEB"})    CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "PC-ALICE"}), (b:Machine {name: "PC-BOB"})     CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "PC-BOB"}),   (b:Machine {name: "SRV-WEB"})    CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "PC-BOB"}),   (b:Machine {name: "SRV-DB"})     CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-WEB"}),  (b:Machine {name: "SRV-DB"})     CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-DB"}),   (b:Machine {name: "DC-01"})      CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "SRV-DB"}),   (b:Machine {name: "NAS-BACKUP"}) CREATE (a)-[:CONNECTED_TO]->(b);
MATCH (a:Machine {name: "DC-01"}),    (b:Machine {name: "NAS-BACKUP"}) CREATE (a)-[:CONNECTED_TO]->(b);

// ---------------------------------------------------------------------
// (:Machine)-[:EXPOSES]->(:Service)   — 8 relations
// ---------------------------------------------------------------------
MATCH (m:Machine {name: "SRV-WEB"}),    (s:Service {name: "HTTP"})    CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-WEB"}),    (s:Service {name: "HTTPS"})   CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-WEB"}),    (s:Service {name: "SSH"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-DB"}),     (s:Service {name: "MongoDB"}) CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "SRV-DB"}),     (s:Service {name: "SSH"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "DC-01"}),      (s:Service {name: "SMB"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "PC-BOB"}),     (s:Service {name: "RDP"})     CREATE (m)-[:EXPOSES]->(s);
MATCH (m:Machine {name: "NAS-BACKUP"}), (s:Service {name: "SMB"})     CREATE (m)-[:EXPOSES]->(s);

// ---------------------------------------------------------------------
// (:Machine)-[:HAS_VULNERABILITY]->(:Vulnerability)   — 6 relations
// ---------------------------------------------------------------------
MATCH (m:Machine {name: "SRV-WEB"}),    (v:Vulnerability {cve: "CVE-2021-44228"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "SRV-WEB"}),    (v:Vulnerability {cve: "CVE-2022-22965"}) CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "PC-BOB"}),     (v:Vulnerability {cve: "CVE-2019-0708"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "DC-01"}),      (v:Vulnerability {cve: "CVE-2020-1472"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "NAS-BACKUP"}), (v:Vulnerability {cve: "CVE-2023-0001"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);
MATCH (m:Machine {name: "SRV-DB"}),     (v:Vulnerability {cve: "CVE-2023-0001"})  CREATE (m)-[:HAS_VULNERABILITY]->(v);

// ---------------------------------------------------------------------
// (:Machine)-[:HOSTS]->(:Resource)   — 5 relations
// ---------------------------------------------------------------------
MATCH (m:Machine {name: "SRV-DB"}),     (r:Resource {name: "Base clients"})        CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "SRV-DB"}),     (r:Resource {name: "Données RH"})          CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "SRV-DB"}),     (r:Resource {name: "Secrets applicatifs"}) CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "DC-01"}),      (r:Resource {name: "Active Directory"})    CREATE (m)-[:HOSTS]->(r);
MATCH (m:Machine {name: "NAS-BACKUP"}), (r:Resource {name: "Sauvegardes"})         CREATE (m)-[:HOSTS]->(r);
