# Notes pour la soutenance

Objectif : présenter en 8 à 10 minutes le graphe, le scénario d'attaque, un chemin identifié, les requêtes Cypher, les vulnérabilités et les recommandations. Puis répondre aux questions.

À garder ouvert pendant la présentation :

* Neo4j Browser sur http://localhost:7474 avec le graphe déjà chargé
* les fichiers `cypher/05_attack_paths.cypher` et `cypher/06_bonus_risk_scoring.cypher`
* le rapport et le PowerPoint
* la capture du graphe

Astuce : garder un onglet du Browser avec le résultat de `MATCH (n) RETURN n` déjà affiché, ça évite d'attendre devant le jury.

## Le déroulé des slides

1. Titre et contexte
2. Le modèle de graphe (avec la capture)
3. Scénario et chemin d'attaque
4. Les requêtes Cypher (démo)
5. Les constats (vulnérabilités, droits, surface)
6. Recommandations et conclusion

## Ce qu'on dit, slide par slide

### Slide 1, introduction (environ 1 min)

On présente CyberCorp, une entreprise fictive dont on a modélisé le système d'information dans Neo4j. Le contexte : le poste PC-ALICE a été compromis par phishing. La question qu'on se pose : depuis ce poste, quels chemins permettent d'atteindre les ressources critiques ? L'intérêt d'utiliser une base graphe ici, c'est qu'un chemin d'attaque est littéralement un chemin dans le graphe, ce qu'un simple tableur ne montre pas.

### Slide 2, le modèle (environ 1 min 30)

On a 6 types de nœuds (utilisateurs, machines, services, vulnérabilités, groupes, ressources) reliés par 8 types de relations : qui utilise quelle machine, qui en est administrateur, quelles machines sont connectées, exposent un service, portent une vulnérabilité ou hébergent une ressource. Au total 31 nœuds et 47 relations. On a aussi ajouté des propriétés utiles pour l'analyse (exposition Internet, statut de patch, niveau de privilège). On montre la capture du graphe.

### Slide 3, scénario et chemin (environ 2 min)

On part de PC-ALICE. Premier constat : ce poste est partagé par alice, eve la stagiaire et diana la RSSI, ce qui est déjà un risque.

On bascule sur le Browser pour lancer la requête du plus court chemin. Le résultat : PC-ALICE vers SRV-WEB vers SRV-DB vers DC-01, soit 3 sauts. SRV-DB est la machine pivot, elle relie le segment bureautique aux machines critiques et héberge la base clients et les secrets.

Mais le chemin le plus dangereux n'est pas le plus long. C'est le rebond par les identifiants : PC-ALICE est connecté à PC-BOB, sur lequel l'administrateur charlie ouvre des sessions. PC-BOB expose RDP et porte BlueKeep, non corrigée. En compromettant PC-BOB, on vole les identifiants admin de charlie (qui est administrateur de DC-01, SRV-DB et NAS-BACKUP), et on accède directement à tout le domaine en un seul saut.

### Slide 4, les requêtes Cypher (environ 2 min)

On lance en direct, dans l'ordre :

1. le plus court chemin vers DC-01, qui donne les 3 sauts
2. les ressources atteignables depuis PC-ALICE, qui montre que les 5 ressources sensibles sont accessibles
3. le scoring de risque, qui classe les machines avec DC-01, SRV-WEB et NAS-BACKUP en tête

### Slide 5, les constats (environ 1 min 30)

Côté vulnérabilités non corrigées : Log4Shell sur SRV-WEB (exposé Internet), Zerologon sur DC-01, BlueKeep sur PC-BOB, et la mauvaise config SMB sur NAS-BACKUP et SRV-DB.

Côté droits : le groupe DEV a un accès direct à SRV-DB (trop large) et un seul compte admin couvre DC-01, SRV-DB et NAS-BACKUP (pas de séparation des rôles).

Côté surface exposée : SRV-WEB sur Internet, MongoDB en interne, RDP sur le poste de dev.

### Slide 6, recommandations et conclusion (environ 1 min)

Les priorités : patcher Zerologon, Log4Shell et BlueKeep, segmenter le réseau (couper le lien direct PC-BOB vers SRV-DB), appliquer le moindre privilège (retirer l'accès DEV à la base, séparer les comptes admin), interdire les sessions admin sur les postes bureautiques, et mettre du MFA avec de la surveillance.

Conclusion : depuis un simple poste compromis, l'attaquant atteint toutes les ressources critiques. Les deux causes racines sont une segmentation insuffisante et des droits trop concentrés. Neo4j nous a permis de visualiser ces chemins et de prioriser les correctifs.

## Questions possibles du jury

**Pourquoi une base graphe plutôt que du SQL ?**
Un chemin d'attaque est une suite de sauts de longueur variable. En SQL il faudrait des jointures récursives lourdes. En Cypher, `(:Machine)-[:CONNECTED_TO*1..5]->(:Machine)` exprime directement toutes les machines à 1 à 5 sauts. Le parcours de relations est natif dans Neo4j.

**Que veut dire `[:CONNECTED_TO*1..5]` ?**
Un chemin de 1 à 5 relations `CONNECTED_TO` à la suite. La borne haute évite les parcours infinis dans un graphe avec des cycles et limite la profondeur d'analyse.

**Comment est calculé le score de risque ?**
La somme des scores CVSS des vulnérabilités non corrigées de la machine, plus un poids selon la criticité (critique = 10, élevée = 7, etc.), plus un bonus si la machine est exposée sur Internet. C'est un indicateur de priorisation, pas un score normalisé.

**Pourquoi Spring4Shell n'apparaît pas dans le scoring de SRV-WEB ?**
Parce qu'on l'a marquée comme corrigée. Le scoring ne compte que les vulnérabilités non corrigées, ce qui reflète le risque résiduel réel.

**Quelle est la machine la plus critique ?**
DC-01 a le score le plus élevé (critique plus Zerologon). Mais SRV-DB est la plus stratégique par sa position : c'est le pivot le plus central du réseau et il héberge trois ressources sensibles.

**Donc alice peut tout lire ?**
Non. Le graphe montre qu'il existe un chemin vers chaque ressource, pas que l'accès est immédiat. L'attaquant doit exploiter une vulnérabilité ou voler des identifiants à chaque saut. Mais ici rien ne le bloque, d'où le risque.

**Comment garantissez-vous l'intégrité des données ?**
Des contraintes d'unicité sur les clés (`User.name`, `Machine.name`, `Vulnerability.cve`, etc.) et des index sur la criticité et le score pour accélérer les requêtes.

**Comment avez-vous chargé les données ?**
Trois méthodes au choix, toutes testées : les scripts Cypher, l'import CSV avec LOAD CSV et APOC, et un script Python avec le driver neo4j. Le tout est conteneurisé avec Docker.

**Quelle limite à votre modèle ?**
Il est statique, sans logs temps réel ni tentatives d'authentification. On pourrait l'enrichir avec des pare-feux, des VLAN, des comptes de service, ou comparer un graphe avant et après sécurisation.

## À vérifier avant de passer

* le conteneur Neo4j est démarré et le graphe chargé (`MATCH (n) RETURN count(n)` doit donner 31)
* un onglet Browser affiche déjà le graphe complet
* les requêtes du plus court chemin, des ressources et du scoring sont prêtes à coller
* la capture du graphe est dans les slides
* la répartition de la parole est claire si on présente à plusieurs
