# CyberCorp : analyse des chemins d'attaque avec Neo4j

Projet B3 Cyber / Infra (base de données orientée graphe Neo4j + Cypher).

Problématique : à partir d'une machine compromise (PC-ALICE), quels sont les chemins possibles vers les ressources critiques de l'entreprise ?

## Contenu du dépôt

```
.
├── README.md                       ce fichier
├── RAPPORT_ANALYSE_CYBER.md        le rapport d'analyse
├── docker-compose.yml              Neo4j + APOC prêt à l'emploi
├── cypher/
│   ├── 00_reset.cypher             purge de la base
│   ├── 01_constraints.cypher       contraintes d'unicité + index
│   ├── 02_create_nodes.cypher      création des nœuds
│   ├── 03_create_relationships.cypher  création des relations
│   ├── 04_exploration.cypher       requêtes d'exploration
│   ├── 05_attack_paths.cypher      analyse des chemins d'attaque
│   ├── 06_bonus_risk_scoring.cypher    scoring de risque (bonus)
│   └── 07_bonus_csv_import.cypher  import via LOAD CSV (bonus)
├── data/                           les données au format CSV
├── docs/
│   ├── GUIDE_SOUTENANCE.md         notes pour la présentation orale
│   └── Soutenance_CyberCorp.pptx   support de présentation
└── scripts/
    ├── load_data.py                insertion via le driver Python
    └── requirements.txt
```

## Le modèle de données

6 types de nœuds : `User`, `Machine`, `Service`, `Vulnerability`, `Group`, `Resource`.

8 types de relations :

| Relation | Sens | Signification |
|---|---|---|
| `USES` | User vers Machine | l'utilisateur ouvre une session sur la machine |
| `MEMBER_OF` | User vers Group | appartenance à un groupe |
| `ADMIN_OF` | User vers Machine | droits d'administration |
| `HAS_ACCESS_TO` | Group vers Machine | accès accordé au groupe |
| `CONNECTED_TO` | Machine vers Machine | connexion réseau autorisée |
| `EXPOSES` | Machine vers Service | service/port exposé |
| `HAS_VULNERABILITY` | Machine vers Vulnerability | vulnérabilité présente |
| `HOSTS` | Machine vers Resource | ressource sensible hébergée |

Au total : 31 nœuds et 47 relations (le minimum demandé était de 6 nœuds par type et 20 relations).

## Comment lancer le projet

### Option A : Neo4j Desktop ou AuraDB

1. Créer une base (Neo4j Desktop en local ou AuraDB Free).
2. Ouvrir Neo4j Browser.
3. Copier-coller dans l'ordre le contenu de `01_constraints.cypher`, puis `02_create_nodes.cypher`, puis `03_create_relationships.cypher`.
4. Lancer ensuite les requêtes d'exploration (`04`), d'analyse (`05`) et de scoring (`06`) une par une.

### Option B : Docker

```bash
docker compose up -d
```

Neo4j Browser est ensuite accessible sur http://localhost:7474 (identifiants : neo4j / cybercorp123).

Pour charger les données, au choix : coller `02` et `03` dans le Browser, ou utiliser l'import CSV (`07_bonus_csv_import.cypher`, les fichiers de `data/` sont déjà montés dans le dossier import de Neo4j), ou passer par le script Python.

### Option C : script Python

Avec le conteneur Docker démarré :

```bash
cd scripts
pip install -r requirements.txt
python load_data.py
```

Le script affiche `31 nœuds et 47 relations chargés`.

## Quelques requêtes clés

| Fichier | Objectif |
|---|---|
| `04` | exploration : comptages, machines critiques, machines vulnérables, services |
| `05` | chemins d'attaque depuis PC-ALICE (plus court chemin, rebond de credentials) |
| `06` | scoring de risque, centralité, segmentation réseau |

Exemple, le plus court chemin vers le contrôleur de domaine :

```cypher
MATCH (start:Machine {name: "PC-ALICE"}), (target:Machine {name: "DC-01"})
MATCH path = shortestPath((start)-[:CONNECTED_TO*1..6]->(target))
RETURN [n IN nodes(path) | n.name] AS chemin, length(path) AS sauts;
```

Résultat : `["PC-ALICE","SRV-WEB","SRV-DB","DC-01"]`, 3 sauts.

## Principaux résultats

* Depuis PC-ALICE, les 5 ressources sensibles sont atteignables. Le cloisonnement réseau est insuffisant.
* Le plus court chemin vers DC-01 fait 3 sauts.
* Le chemin le plus dangereux est le rebond de credentials via PC-BOB (session admin de charlie + BlueKeep), qui mène directement à DC-01.
* Les machines les plus à risque sont DC-01 (20), SRV-WEB (19) et NAS-BACKUP (17.5).

L'analyse complète et les recommandations sont dans `RAPPORT_ANALYSE_CYBER.md`.

## Correspondance avec les livrables

| Livrable | Où |
|---|---|
| 1. Graphe Neo4j (scripts + description) | `cypher/01` à `03`, plus la section "modèle de données" ci-dessus |
| 2. Requêtes Cypher | `cypher/04` à `06` |
| 3. Rapport d'analyse | `RAPPORT_ANALYSE_CYBER.md` |
| 4. Présentation orale | `docs/GUIDE_SOUTENANCE.md` et `docs/Soutenance_CyberCorp.pptx` |
| Bonus | import CSV (`data/`), script Python (`scripts/`), Docker, scoring de risque |

Pour le livrable 1, penser à ajouter la capture d'écran du graphe : dans Neo4j Browser, lancer `MATCH (n) RETURN n` puis exporter l'image dans `docs/`.
