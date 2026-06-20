#!/usr/bin/env python3
"""
load_data.py  (BONUS — insertion des données dans Neo4j via Python)

Charge le graphe CyberCorp dans Neo4j à partir des fichiers CSV du
dossier ../data, en utilisant le driver officiel `neo4j`.

Usage:
    pip install -r requirements.txt
    python load_data.py

Variables d'environnement (avec valeurs par défaut adaptées au
docker-compose.yml fourni) :
    NEO4J_URI       (défaut: bolt://localhost:7687)
    NEO4J_USER      (défaut: neo4j)
    NEO4J_PASSWORD  (défaut: cybercorp123)
"""

import csv
import os
from pathlib import Path

from neo4j import GraphDatabase

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASSWORD = os.environ.get("NEO4J_PASSWORD", "cybercorp123")

# Clé d'unicité par label (utilisée pour le MATCH lors des relations)
KEY_BY_LABEL = {
    "User": "name",
    "Machine": "name",
    "Service": "name",
    "Vulnerability": "cve",
    "Group": "name",
    "Resource": "name",
}


def read_csv(filename):
    with open(DATA_DIR / filename, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def reset(tx):
    tx.run("MATCH (n) DETACH DELETE n")


def create_constraints(tx):
    stmts = [
        "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
        "CREATE CONSTRAINT machine_name IF NOT EXISTS FOR (m:Machine) REQUIRE m.name IS UNIQUE",
        "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
        "CREATE CONSTRAINT vuln_cve IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.cve IS UNIQUE",
        "CREATE CONSTRAINT group_name IF NOT EXISTS FOR (g:Group) REQUIRE g.name IS UNIQUE",
        "CREATE CONSTRAINT resource_name IF NOT EXISTS FOR (r:Resource) REQUIRE r.name IS UNIQUE",
    ]
    for s in stmts:
        tx.run(s)


def load_nodes(tx):
    for row in read_csv("users.csv"):
        tx.run(
            "CREATE (:User {name:$name, role:$role, privilege_level:$privilege_level})",
            **row,
        )

    for row in read_csv("machines.csv"):
        tx.run(
            """CREATE (:Machine {name:$name, type:$type, criticality:$criticality,
                                 internet_exposed:$internet_exposed, last_patch:$last_patch})""",
            name=row["name"],
            type=row["type"],
            criticality=row["criticality"],
            internet_exposed=row["internet_exposed"].lower() == "true",
            last_patch=row["last_patch"],
        )

    for row in read_csv("services.csv"):
        tx.run(
            "CREATE (:Service {name:$name, port:$port})",
            name=row["name"],
            port=int(row["port"]),
        )

    for row in read_csv("vulnerabilities.csv"):
        tx.run(
            """CREATE (:Vulnerability {cve:$cve, name:$name, score:$score,
                                       severity:$severity, status:$status,
                                       description:$description})""",
            cve=row["cve"],
            name=row["name"],
            score=float(row["score"]),
            severity=row["severity"],
            status=row["status"],
            description=row["description"],
        )

    for row in read_csv("groups.csv"):
        tx.run(
            "CREATE (:Group {name:$name, description:$description})", **row
        )

    for row in read_csv("resources.csv"):
        tx.run(
            "CREATE (:Resource {name:$name, sensitivity:$sensitivity})", **row
        )


def load_relationships(tx):
    for row in read_csv("relationships.csv"):
        # Le type de relation provient du CSV : il est validé contre une
        # liste blanche pour éviter toute injection Cypher.
        rel = row["rel_type"]
        allowed = {
            "USES", "MEMBER_OF", "ADMIN_OF", "HAS_ACCESS_TO",
            "CONNECTED_TO", "EXPOSES", "HAS_VULNERABILITY", "HOSTS",
        }
        if rel not in allowed:
            raise ValueError(f"Type de relation non autorisé: {rel}")

        src_label, src_key = row["source_label"], row["source_key"]
        dst_label, dst_key = row["target_label"], row["target_key"]

        query = (
            f"MATCH (a:{src_label} {{{src_key}: $src}}) "
            f"MATCH (b:{dst_label} {{{dst_key}: $dst}}) "
            f"CREATE (a)-[:{rel}]->(b)"
        )
        tx.run(query, src=row["source"], dst=row["target"])


def stats(tx):
    nodes = tx.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    rels = tx.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
    return nodes, rels


def main():
    print(f"Connexion à {URI} ...")
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    with driver.session() as session:
        print("Réinitialisation de la base ...")
        session.execute_write(reset)
        print("Création des contraintes ...")
        session.execute_write(create_constraints)
        print("Import des nœuds ...")
        session.execute_write(load_nodes)
        print("Import des relations ...")
        session.execute_write(load_relationships)
        nodes, rels = session.execute_read(stats)
        print(f"OK — {nodes} nœuds et {rels} relations chargés.")
    driver.close()


if __name__ == "__main__":
    main()
