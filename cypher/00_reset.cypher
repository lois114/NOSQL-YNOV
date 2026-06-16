// =====================================================================
// 00_reset.cypher
// Réinitialisation complète de la base (à exécuter avant un re-chargement)
// ATTENTION : supprime TOUS les nœuds et toutes les relations.
// =====================================================================

MATCH (n)
DETACH DELETE n;
