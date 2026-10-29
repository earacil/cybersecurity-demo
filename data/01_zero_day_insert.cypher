// =====================================================================================
// 01_zero_day_insert.cypher — DÍA CERO EN DIRECTO: CVE-2021-44228 (Log4Shell)
// ⚠️  A VALIDAR en Aura (29-oct-2026).
//
// PRERREQUISITO: carga base ejecutada (00_load_live.cypher) y `baseUrl` definido (`:params`).
// El grafo de partida es sintético; este es el único CVE real. Idempotente (MERGE): repetirlo no duplica.
//
// Tras ejecutarlo (en este orden): Vulnerability 17 → 18 · AFFECTS 17 → 18 · total 71 nodos y 104 relaciones.
// Si AFFECTS no sube a 18, el MATCH de la librería no encontró `log4j-core` 2.14.1: ¿se cargó el segmento 1?
// Para repetir el ensayo: 02_zero_day_reset.cypher.
// =====================================================================================

// 1 · Foto del grafo ANTES (opcional, para la narrativa)
MATCH (v:Vulnerability) RETURN count(v) AS vulnerabilities;

// 2 · La vulnerabilidad nueva (nodo)
LOAD CSV WITH HEADERS FROM $baseUrl + 'zero_day_vulnerability.csv' AS row
MERGE (v:Vulnerability {id: row.id})
SET v.cvss_score = toFloat(row.cvss_score),
    v.known_exploited = (row.known_exploited = 'true'),
    v.description = row.description;

// 3 · Dónde cae: sobre la librería, que está enterrada a 3-4 niveles de las aplicaciones
LOAD CSV WITH HEADERS FROM $baseUrl + 'zero_day_affects.csv' AS row
MATCH (v:Vulnerability {id: row.vulnerability_id})
MATCH (l:Library {name: row.library_name, version: row.library_version})
MERGE (v)-[:AFFECTS]->(l);

// 4 · Comprobación (debe devolver 1 fila: CVE-2021-44228 → log4j-core 2.14.1)
MATCH (v:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(l:Library)
RETURN v.id AS vulnerability, v.cvss_score AS cvss, v.known_exploited AS exploited, l.name AS library, l.version AS version;
