// =====================================================================================
// 02_zero_day_reset.cypher — RESET del día cero (para repetir la demo o el ensayo)
// ⚠️  A VALIDAR en Aura (29-oct-2026).
//
// Elimina SOLO CVE-2021-44228 y su relación AFFECTS. No toca la librería `log4j-core` ni nada de la
// carga base (que es sintética). Tras ejecutarlo el grafo vuelve a 70 nodos y 103 relaciones.
// Ejecútalo SOLO cuando quieras volver al estado previo al día cero.
// =====================================================================================

MATCH (v:Vulnerability {id: 'CVE-2021-44228'})
DETACH DELETE v;

// Comprobación: debe devolver 17 y 103
MATCH (v:Vulnerability) WITH count(v) AS vulnerabilities
MATCH ()-[r]->() RETURN vulnerabilities, count(r) AS relationships;
