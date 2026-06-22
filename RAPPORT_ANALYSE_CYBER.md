# Rapport d'analyse cyber : CyberCorp

Projet B3 Cyber / Infra. Cartographie d'un système d'information et analyse des chemins d'attaque avec Neo4j.

Problématique : à partir d'une machine compromise (PC-ALICE), quels sont les chemins possibles vers les ressources critiques de l'entreprise ?

## 1. Présentation du système modélisé

On a modélisé le SI de l'entreprise fictive CyberCorp sous forme de graphe dans Neo4j.

Le graphe contient 31 nœuds et 47 relations :

* 5 utilisateurs, 6 machines, 6 services, 5 vulnérabilités, 4 groupes, 5 ressources
* 47 relations réparties sur 8 types différents

On utilise 6 types de nœuds (`User`, `Machine`, `Service`, `Vulnerability`, `Group`, `Resource`) et 8 types de relations :

```
(:User)-[:USES]->(:Machine)
(:User)-[:MEMBER_OF]->(:Group)
(:User)-[:ADMIN_OF]->(:Machine)
(:Group)-[:HAS_ACCESS_TO]->(:Machine)
(:Machine)-[:CONNECTED_TO]->(:Machine)
(:Machine)-[:EXPOSES]->(:Service)
(:Machine)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:Machine)-[:HOSTS]->(:Resource)
```

On a aussi ajouté quelques propriétés supplémentaires pour aller plus loin dans l'analyse : l'exposition Internet des machines, le statut de correction des vulnérabilités (corrigée ou non), et le niveau de privilège des comptes.

## 2. Schéma du graphe

Voici la topologie réseau (relations `CONNECTED_TO`) :

```
            PC-ALICE  (compromise par phishing)
            /      \
       SRV-WEB    PC-BOB
            \      /
            SRV-DB        HOSTS : Base clients, Données RH, Secrets applicatifs
            /     \
        DC-01    NAS-BACKUP
        HOSTS :   HOSTS :
        Active    Sauvegardes
        Directory
```

La capture d'écran du graphe Neo4j (`MATCH (n) RETURN n` dans le Browser) est disponible dans le dossier `docs/`.

## 3. Hypothèse d'attaque

Le poste PC-ALICE, celui de l'employée RH alice, est compromis suite à un phishing. L'attaquant se retrouve donc avec un accès dans le réseau interne, avec les droits d'un utilisateur standard. Son objectif : atteindre les ressources critiques (Active Directory, sauvegardes, secrets applicatifs).

Un détail aggrave déjà la situation au départ : PC-ALICE est partagé par trois personnes (alice, eve la stagiaire, et diana la RSSI). Le fait que la RSSI ouvre des sessions sur ce poste peu protégé est un problème en soi.

## 4. Chemins d'attaque identifiés

Requêtes utilisées : `cypher/05_attack_paths.cypher`.

### 4.1 Chemin réseau vers le contrôleur de domaine

Deux trajets de 3 sauts permettent d'atteindre DC-01 depuis PC-ALICE :

```
PC-ALICE -> SRV-WEB -> SRV-DB -> DC-01
PC-ALICE -> PC-BOB  -> SRV-DB -> DC-01
```

La requête `shortestPath` confirme une distance minimale de 3 sauts.

### 4.2 Toutes les ressources sont atteignables

Depuis PC-ALICE, les 5 ressources sensibles sont atteignables par le réseau :

| Ressource | Sensibilité | Hébergée sur | Distance |
|---|---|---|---|
| Base clients | high | SRV-DB | 2 sauts |
| Données RH | high | SRV-DB | 2 sauts |
| Secrets applicatifs | critical | SRV-DB | 2 sauts |
| Active Directory | critical | DC-01 | 3 sauts |
| Sauvegardes | critical | NAS-BACKUP | 3 sauts |

Aucune ressource n'est isolée du poste compromis. Attention, "atteignable" ne veut pas dire que l'attaquant a un accès immédiat : il doit exploiter une vulnérabilité ou voler des identifiants à chaque saut. Mais ici rien ne le bloque sur le chemin, ce qui montre que le cloisonnement réseau est insuffisant.

### 4.3 Le chemin le plus dangereux : rebond par les identifiants

C'est le trajet le plus court vers une compromission complète :

```
PC-ALICE -> PC-BOB
   charlie (Admin Système) utilise PC-BOB
   charlie est ADMIN_OF de DC-01, SRV-DB et NAS-BACKUP
```

PC-ALICE est directement connecté à PC-BOB, le poste du développeur. PC-BOB expose RDP et porte BlueKeep, qui n'est pas corrigée : l'attaquant le compromet sans difficulté. Or charlie, l'administrateur, ouvre des sessions sur ce même poste. Ses identifiants à privilèges se retrouvent donc exposés sur une machine vulnérable.

En les volant, l'attaquant obtient un accès direct à DC-01, SRV-DB et NAS-BACKUP, c'est-à-dire à tout le domaine, en un seul saut réseau et sans même avoir besoin d'exploiter Zerologon.

## 5. Machines vulnérables

On a calculé un score de risque par machine (`cypher/06_bonus_risk_scoring.cypher`). La formule additionne les scores CVSS des vulnérabilités non corrigées, un poids selon la criticité de la machine, et un bonus si elle est exposée sur Internet.

| Machine | Vulnérabilité non corrigée | Score |
|---|---|---|
| DC-01 | Zerologon (CVE-2020-1472, 10) | 20.0 |
| SRV-WEB | Log4Shell (CVE-2021-44228, 10), exposé Internet | 19.0 |
| NAS-BACKUP | SMB Misconfiguration (CVE-2023-0001, 7.5) | 17.5 |
| SRV-DB | SMB Misconfiguration (CVE-2023-0001, 7.5) | 14.5 |
| PC-BOB | BlueKeep (CVE-2019-0708, 9.8) | 13.8 |
| PC-ALICE | aucune | 1.0 |

Spring4Shell (CVE-2022-22965) sur SRV-WEB est marquée comme corrigée, elle n'entre donc pas dans le calcul.

L'analyse de centralité (degré entrant et sortant des connexions réseau) montre que SRV-DB est la machine pivot la plus importante du graphe : elle relie le segment bureautique aux deux machines critiques et héberge à elle seule trois ressources sensibles.

## 6. Services exposés

| Machine | Services exposés | Exposée Internet |
|---|---|---|
| SRV-WEB | HTTP:80, HTTPS:443, SSH:22 | oui |
| SRV-DB | MongoDB:27017, SSH:22 | non |
| DC-01 | SMB:445 | non |
| NAS-BACKUP | SMB:445 | non |
| PC-BOB | RDP:3389 | non |

Ce qui pose problème :

* SRV-WEB est exposé sur Internet avec HTTP/HTTPS et porte Log4Shell, donc c'est un point d'entrée externe possible en plus du phishing.
* MongoDB sur le port 27017 est souvent mal authentifié.
* RDP sur PC-BOB combiné à BlueKeep permet une exécution de code à distance.
* SMB sur DC-01 et NAS-BACKUP, mal configuré, facilite la propagation et l'accès aux sauvegardes.

## 7. Utilisateurs et groupes à risque

* charlie (Admin Système) est administrateur de DC-01, SRV-DB et NAS-BACKUP, mais il ouvre des sessions sur PC-BOB, un poste vulnérable. Ses identifiants à privilèges sont donc exposés sur une machine mal protégée. C'est le compte le plus à risque.
* Le groupe DEV a un accès direct à SRV-DB (le serveur de base de données). Un développeur n'a normalement pas besoin de ça, c'est un droit trop large.
* Le groupe ADMINS a accès à DC-01, SRV-DB et NAS-BACKUP. Comme tout est concentré sur le compte de charlie, la compromission d'un seul compte suffit à tout compromettre.
* eve (stagiaire) et diana (RSSI) partagent PC-ALICE avec alice, ce qui mélange des niveaux de sensibilité différents sur le même poste.

## 8. Recommandations

Classées de la plus urgente à la plus structurelle :

1. Corriger en priorité les vulnérabilités critiques non patchées : Zerologon sur DC-01, Log4Shell sur SRV-WEB, BlueKeep sur PC-BOB, et la mauvaise configuration SMB sur NAS-BACKUP et SRV-DB.
2. Segmenter le réseau avec des VLAN et un pare-feu. Supprimer notamment la connexion directe PC-BOB vers SRV-DB, et plus généralement interdire tout flux direct d'un poste utilisateur vers un serveur critique. Faire passer les accès par un bastion.
3. Appliquer le principe du moindre privilège : retirer l'accès du groupe DEV à SRV-DB, et arrêter de concentrer l'administration de DC-01, SRV-DB et NAS-BACKUP sur un seul compte.
4. Interdire les sessions à privilèges sur les postes bureautiques. charlie ne devrait pas se connecter sur PC-BOB avec un compte admin (utiliser des comptes d'administration dédiés, principe du tiering Active Directory).
5. Réduire la surface exposée : fermer SSH sur SRV-WEB s'il est inutile, restreindre MongoDB à un réseau d'administration, et placer RDP derrière une passerelle.
6. Durcir le poste d'entrée : anti-phishing et EDR sur PC-ALICE, et arrêter de mutualiser ce poste entre trois personnes.
7. Renforcer l'authentification des comptes à privilèges avec du MFA, de la rotation des secrets et une surveillance des connexions anormales.
8. Isoler les sauvegardes : NAS-BACKUP ne devrait pas être joignable depuis le segment bureautique, et il faudrait des sauvegardes hors-ligne ou immuables pour résister à un rançongiciel.

## 9. Conclusion

La modélisation en graphe montre que depuis un simple poste compromis par phishing, un attaquant peut atteindre l'intégralité des ressources critiques de CyberCorp. Le chemin le plus dangereux n'est pas le plus long parcours réseau mais le rebond par les identifiants admin exposés sur PC-BOB, qui mène directement au contrôleur de domaine.

Deux causes reviennent à chaque fois : une segmentation réseau insuffisante (tout est joignable de proche en proche) et des droits trop concentrés ou trop larges (un seul compte admin pour tout, un accès DEV direct à la base, des sessions admin sur des postes vulnérables).

Neo4j est bien adapté à ce genre d'analyse. Les requêtes de chemin et de centralité rendent visibles en quelques lignes des trajets d'attaque qu'un simple inventaire sous tableur ne ferait pas ressortir. Le graphe sert donc autant au diagnostic qu'à la priorisation des corrections.
