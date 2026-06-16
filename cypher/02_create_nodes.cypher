// =====================================================================
// 02_create_nodes.cypher
// Étape 1 — Création des nœuds (6 types)
// (:User) (:Machine) (:Service) (:Vulnerability) (:Group) (:Resource)
//
// Le modèle est enrichi (bonus) avec des propriétés supplémentaires :
//   - User.privilege_level     : niveau de privilège (standard / admin / security)
//   - Machine.internet_exposed : machine exposée sur Internet (true/false)
//   - Machine.last_patch       : date du dernier correctif appliqué
//   - Vulnerability.status     : "unpatched" / "patched"
//   - Vulnerability.severity   : "critical" / "high" (dérivée du score CVSS)
// =====================================================================

// ---------------------------------------------------------------------
// UTILISATEURS (5)
// ---------------------------------------------------------------------
CREATE (:User {name: "alice",   role: "RH",             privilege_level: "standard"});
CREATE (:User {name: "bob",     role: "Développeur",    privilege_level: "standard"});
CREATE (:User {name: "charlie", role: "Admin Système",  privilege_level: "admin"});
CREATE (:User {name: "diana",   role: "RSSI",           privilege_level: "security"});
CREATE (:User {name: "eve",     role: "Stagiaire",      privilege_level: "standard"});

// ---------------------------------------------------------------------
// MACHINES (6)
// ---------------------------------------------------------------------
CREATE (:Machine {name: "PC-ALICE",   type: "workstation",        criticality: "low",      internet_exposed: false, last_patch: "2024-11-02"});
CREATE (:Machine {name: "PC-BOB",      type: "workstation",        criticality: "medium",   internet_exposed: false, last_patch: "2024-09-15"});
CREATE (:Machine {name: "SRV-WEB",     type: "server",             criticality: "medium",   internet_exposed: true,  last_patch: "2024-06-20"});
CREATE (:Machine {name: "SRV-DB",      type: "database",           criticality: "high",     internet_exposed: false, last_patch: "2024-08-01"});
CREATE (:Machine {name: "DC-01",       type: "domain_controller",  criticality: "critical", internet_exposed: false, last_patch: "2024-03-10"});
CREATE (:Machine {name: "NAS-BACKUP",  type: "backup_server",      criticality: "critical", internet_exposed: false, last_patch: "2023-12-05"});

// ---------------------------------------------------------------------
// SERVICES (6)
// ---------------------------------------------------------------------
CREATE (:Service {name: "SSH",     port: 22});
CREATE (:Service {name: "HTTP",    port: 80});
CREATE (:Service {name: "HTTPS",   port: 443});
CREATE (:Service {name: "RDP",     port: 3389});
CREATE (:Service {name: "SMB",     port: 445});
CREATE (:Service {name: "MongoDB", port: 27017});

// ---------------------------------------------------------------------
// VULNÉRABILITÉS (5)
// ---------------------------------------------------------------------
CREATE (:Vulnerability {cve: "CVE-2021-44228", name: "Log4Shell",            score: 10.0, severity: "critical", status: "unpatched", description: "Exécution de code à distance via Log4j"});
CREATE (:Vulnerability {cve: "CVE-2020-1472",  name: "Zerologon",            score: 10.0, severity: "critical", status: "unpatched", description: "Élévation de privilèges sur contrôleur de domaine"});
CREATE (:Vulnerability {cve: "CVE-2019-0708",  name: "BlueKeep",             score: 9.8,  severity: "critical", status: "unpatched", description: "Exécution de code à distance via RDP"});
CREATE (:Vulnerability {cve: "CVE-2022-22965", name: "Spring4Shell",         score: 9.8,  severity: "critical", status: "patched",   description: "Exécution de code à distance sur application Spring"});
CREATE (:Vulnerability {cve: "CVE-2023-0001",  name: "SMB Misconfiguration", score: 7.5,  severity: "high",     status: "unpatched", description: "Mauvaise configuration du partage SMB"});

// ---------------------------------------------------------------------
// GROUPES (4)
// ---------------------------------------------------------------------
CREATE (:Group {name: "RH",       description: "Utilisateurs du service RH"});
CREATE (:Group {name: "DEV",      description: "Équipe de développement"});
CREATE (:Group {name: "ADMINS",   description: "Administrateurs système"});
CREATE (:Group {name: "SECURITY", description: "Équipe sécurité"});

// ---------------------------------------------------------------------
// RESSOURCES SENSIBLES (5)
// ---------------------------------------------------------------------
CREATE (:Resource {name: "Base clients",        sensitivity: "high"});
CREATE (:Resource {name: "Données RH",          sensitivity: "high"});
CREATE (:Resource {name: "Active Directory",    sensitivity: "critical"});
CREATE (:Resource {name: "Sauvegardes",         sensitivity: "critical"});
CREATE (:Resource {name: "Secrets applicatifs", sensitivity: "critical"});
