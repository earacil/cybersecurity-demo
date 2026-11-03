// =====================================================================================
// 03_attack_paths_gds.cypher — Caso 3 · Análisis de caminos de ataque (+ GDS como complemento)
// Demo de ciberseguridad con Neo4j · AuraDB + Aura Graph Analytics (GDS serverless)
//
// ESTADO: ⚠️ A VALIDAR en Aura (29-oct-2026). La carga base sí está validada.
//         Las cifras «esperado» salen de `python3 data/validate_dataset.py` (cálculo en Python), no de Neo4j ni de GDS.
//         Si algo de GDS falla, las PARTES A-F y H dan el resultado completo en Cypher puro, sin sesión.
//
// PRERREQUISITO: carga base (data/00_load_live.cypher). El día cero NO afecta a este fichero (no cambia la red).
//
// HILO: «¿hasta dónde llegaría un atacante y dónde corto?». Casos de POSTURA y exposición (prevenir), no detección
//       de un ataque en curso (eso es el SIEM).
//
// VOCABULARIO
//   · Entrada       = host con internet_exposed = true (3: dmz-web-01, dmz-api-01, dmz-portal-01).
//   · Activo crítico (crown jewel) = DataStore con crown_jewel = true (3: Customer PII DB, Card Ledger, Subscriber Registry).
//   · Camino de ataque = entrada → saltos de red (CAN_REACH) → activo crítico, por una de DOS rutas:
//        por red:      … → (Host)-[:STORES]->(DataStore)               el dato vive en un host alcanzado
//        por identidad … → (Host)-[:RUNS_AS]->(Identity)-[:HAS_ACCESS_TO]->(DataStore)   el host hereda credenciales
//   · Blast radius  = todo lo que alcanza quien compromete un host.
//   · Punto de estrangulamiento = host, identidad o regla de red por el que pasa gran parte de los caminos.
//
// ÍNDICE
//   A. Caminos de las entradas a los activos críticos
//   B. Caminos que solo existen a través de una identidad
//   C. Blast radius y contraste entre entradas
//   D. Activos críticos no alcanzables (lo que está bien protegido)
//   E. Puntos de estrangulamiento en Cypher (nodos y reglas de red)
//   F. What-if: ¿qué pasa si corto aquí?
//   G. GDS (complemento): betweenness (centralidad) y Louvain (comunidades)
//   Z. Borrar las proyecciones y la sesión GDS
//   H. Fallback en Cypher puro de las comunidades: zonas por alcanzabilidad
//
// Profundidad máxima de camino variable: 10. LITERALES CAMBIABLES: marcados con ← CAMBIA.
// =====================================================================================


// =====================================================================================
// PARTE A · CAMINOS DE LAS ENTRADAS A LOS ACTIVOS CRÍTICOS
// =====================================================================================

// A.1 · Tabla: un camino por fila
//       esperado: 11 filas · 2 por red (a Card Ledger, vía db-pay-01) y 9 por identidad
//         dmz-web-01: 6 · dmz-api-01: 4 · dmz-portal-01: 1
//         Customer PII DB: 7 caminos (todos por identidad) · Card Ledger: 4 (2 por red, 2 por identidad) · Subscriber Registry: 0
CALL {
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(d:DataStore {crown_jewel: true})
  RETURN e.name AS entry, 'network' AS via, d.name AS crown_jewel, [n IN nodes(p) | n.name] AS route
  UNION ALL
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(d:DataStore {crown_jewel: true})
  RETURN e.name AS entry, 'identity' AS via, d.name AS crown_jewel, [n IN nodes(p) | n.name] AS route
}
RETURN entry, via, crown_jewel, size(route) AS nodes_in_path, route
ORDER BY entry, crown_jewel, via, nodes_in_path;

// A.2 · Visual (Bloom / vista de grafo): los 11 caminos
MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(:DataStore {crown_jewel: true})
RETURN p
UNION
MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(:DataStore {crown_jewel: true})
RETURN p;

// A.3 · Visual: los caminos de UNA entrada
//       esperado: dmz-web-01 → 6 · dmz-api-01 → 4 · dmz-portal-01 → 1
MATCH p = (:Host {name: 'dmz-web-01'})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(:DataStore {crown_jewel: true})   // ← CAMBIA
RETURN p
UNION
MATCH p = (:Host {name: 'dmz-web-01'})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(:DataStore {crown_jewel: true})   // ← CAMBIA
RETURN p;


// =====================================================================================
// PARTE B · CAMINOS QUE SOLO EXISTEN A TRAVÉS DE UNA IDENTIDAD
// Aquí no hay camino de RED hasta el host que guarda el dato: el atacante llega con las credenciales que hereda.
// =====================================================================================

// B.1 · Tabla
//       esperado: 7 filas, todas a Customer PII DB (db-cust-01 no tiene ninguna entrada por red):
//         dmz-web-01 (4), dmz-api-01 (2) y dmz-portal-01 (1), por svc-customer-profile o svc-billing
//       Lectura: un cortafuegos perfecto no lo evita; hay que revisar el permiso. svc-billing NO debería leer PII.
MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(i:Identity)-[:HAS_ACCESS_TO]->(d:DataStore {crown_jewel: true})
WHERE NOT EXISTS { MATCH (e)-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(d) }
RETURN e.name AS entry, i.name AS identity, d.name AS crown_jewel, [n IN nodes(p) | n.name] AS route
ORDER BY entry, identity;

// B.2 · Visual
MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(d:DataStore {crown_jewel: true})
WHERE NOT EXISTS { MATCH (e)-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(d) }
RETURN p;


// =====================================================================================
// PARTE C · BLAST RADIUS
// =====================================================================================

// C.1 · Comparación de las tres entradas
//       esperado:
//         dmz-api-01     hosts 6 · identidades 4 · almacenes 4 · críticos 2
//         dmz-web-01     hosts 6 · identidades 4 · almacenes 4 · críticos 2
//         dmz-portal-01  hosts 3 · identidades 2 · almacenes 3 · críticos 1
//       Lectura: dos puertas de entrada, dos alcances muy distintos. El portal parece menos grave… hasta que se ve que llega a PII.
//       (para una sola entrada, descomenta la línea del WHERE)
MATCH (e:Host {internet_exposed: true})
// WHERE e.name = 'dmz-web-01'                                          // ← CAMBIA
CALL (e) {
  OPTIONAL MATCH (e)-[:CAN_REACH*1..10]->(h:Host)
  RETURN count(DISTINCT h) AS hosts_reached
}
CALL (e) {
  OPTIONAL MATCH (e)-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(i:Identity)
  RETURN count(DISTINCT i) AS identities_inherited
}
CALL (e) {
  OPTIONAL MATCH (e)-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(d:DataStore)
  RETURN collect(DISTINCT d) AS stored_on_reached_hosts
}
CALL (e) {
  OPTIONAL MATCH (e)-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(d:DataStore)
  RETURN collect(DISTINCT d) AS reachable_by_identity
}
WITH e, hosts_reached, identities_inherited,
     stored_on_reached_hosts + [x IN reachable_by_identity WHERE NOT x IN stored_on_reached_hosts] AS data_stores
RETURN e.name AS entry_host, hosts_reached, identities_inherited,
       size(data_stores) AS data_stores_reached,
       size([x IN data_stores WHERE x.crown_jewel]) AS crown_jewels_reached
ORDER BY entry_host;

// C.2 · Visual: todo el alcance por red de una entrada
//       esperado: dmz-web-01 → 6 hosts alcanzados
MATCH p = (:Host {name: 'dmz-web-01'})-[:CAN_REACH*1..10]->(:Host)   // ← CAMBIA
RETURN p;


// =====================================================================================
// PARTE D · ACTIVOS CRÍTICOS NO ALCANZABLES
// =====================================================================================

// D.1 · Activos críticos a los que NO llega ninguna entrada, ni por red ni por identidad
//       esperado: 1 fila · Subscriber Registry (Subscriber)
//       Lectura: lo bien protegido también se enseña. Vive en la zona de gestión (jump-01, app-prov-01, db-sub-01),
//                a la que no llega ningún host expuesto.
MATCH (d:DataStore {crown_jewel: true})
WHERE NOT EXISTS { MATCH (:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(d) }
  AND NOT EXISTS { MATCH (:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(d) }
RETURN d.name AS unreachable_crown_jewel, d.data_class AS data_class;

// D.2 · Matiz: lo que alcanzaría quien SÍ entrara por la puerta de gestión (jump-01, no expuesta)
//       esperado: 4 caminos, hacia app-prov-01, db-sub-01 (directo y vía app-prov-01) e int-web-01; al expandir app-prov-01
//         aparece svc-provisioning con acceso a Subscriber Registry. Pero ninguna entrada llega a jump-01 (ver D.1).
MATCH p = (:Host {name: 'jump-01'})-[:CAN_REACH*1..10]->(:Host)   // ← CAMBIA
RETURN p;


// =====================================================================================
// PARTE E · PUNTOS DE ESTRANGULAMIENTO EN CYPHER
// «¿Por cuántos caminos entrada → activo crítico pasa cada nodo?» Es la medida que importa para cortar.
// =====================================================================================

// E.1 · Hosts e identidades, por nº de caminos que cruzan (no cuenta el host de entrada)
//       esperado (de 11 caminos):
//         Host app-pay-01 8 (73 %) · Host app-cust-01 6 (55 %) · Host app-bill-01 4 (36 %) · Identity svc-billing 4 (36 %) ·
//         Identity svc-customer-profile 3 (27 %) · Host db-pay-01 2 (18 %) · Identity svc-payments 2 (18 %)
//       Lectura: app-pay-01 está en 8 de 11 caminos: es el primer sitio donde cortar.
CALL {
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(:DataStore {crown_jewel: true})
  RETURN p
  UNION ALL
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(:DataStore {crown_jewel: true})
  RETURN p
}
WITH collect(p) AS paths
WITH paths, size(paths) AS total
UNWIND paths AS p
UNWIND [n IN nodes(p) WHERE (n:Host OR n:Identity) AND n <> head(nodes(p))] AS n
WITH n, total, count(*) AS paths_through
RETURN labels(n)[0] AS type, n.name AS name, paths_through, total AS total_paths,
       round(100.0 * paths_through / total) AS percent
ORDER BY paths_through DESC, name;

// E.2 · Reglas de red (aristas CAN_REACH), por nº de caminos que cruzan: candidatas a una regla de segmentación
//       esperado (de 11 caminos):
//         app-pay-01 → app-cust-01 4 (36 %) · dmz-api-01 → app-pay-01 4 (36 %) · dmz-web-01 → app-pay-01 4 (36 %) ·
//         app-cust-01 → app-bill-01 3 (27 %) · app-pay-01 → db-pay-01 2 (18 %) · dmz-web-01 → app-cust-01 2 (18 %) ·
//         dmz-portal-01 → app-bill-01 1 (9 %)
CALL {
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(:DataStore {crown_jewel: true})
  RETURN p
  UNION ALL
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(:DataStore {crown_jewel: true})
  RETURN p
}
WITH collect(p) AS paths
WITH paths, size(paths) AS total
UNWIND paths AS p
UNWIND [r IN relationships(p) WHERE type(r) = 'CAN_REACH'] AS r
WITH r, total, count(*) AS paths_through
RETURN startNode(r).name AS from_host, endNode(r).name AS to_host, r.port AS port,
       paths_through, total AS total_paths, round(100.0 * paths_through / total) AS percent
ORDER BY paths_through DESC, from_host, to_host;


// =====================================================================================
// PARTE F · WHAT-IF: ¿QUÉ PASA SI CORTO AQUÍ?
// No modifica el grafo: cuenta los caminos que SOBREVIVEN si se quita un permiso o una regla.
// =====================================================================================

// F.1 · Quitar el permiso svc-billing → Customer PII DB
//       esperado: dmz-api-01 4 → 3 · dmz-portal-01 1 → 0 (ya no llega a ningún activo crítico) · dmz-web-01 6 → 4
//       Lectura: un solo permiso sobrante abría el camino del portal hasta datos personales.
CALL {
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(:DataStore {crown_jewel: true})
  RETURN p
  UNION ALL
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(:DataStore {crown_jewel: true})
  RETURN p
}
WITH head(nodes(p)) AS entry,
     any(r IN relationships(p)
         WHERE type(r) = 'HAS_ACCESS_TO'
           AND startNode(r).name = 'svc-billing'                       // ← CAMBIA
           AND endNode(r).name = 'Customer PII DB') AS uses_the_cut    // ← CAMBIA
WITH entry, count(*) AS paths_before, sum(CASE WHEN uses_the_cut THEN 0 ELSE 1 END) AS paths_after
RETURN entry.name AS entry_host, paths_before, paths_after, paths_after = 0 AS no_longer_reaches_a_crown_jewel
ORDER BY entry_host;

// F.2 · Cortar la regla de red app-pay-01 → app-cust-01
//       esperado: dmz-api-01 4 → 2 · dmz-portal-01 1 → 1 · dmz-web-01 6 → 4
CALL {
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(:DataStore {crown_jewel: true})
  RETURN p
  UNION ALL
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(:DataStore {crown_jewel: true})
  RETURN p
}
WITH head(nodes(p)) AS entry,
     any(r IN relationships(p)
         WHERE type(r) = 'CAN_REACH'
           AND startNode(r).name = 'app-pay-01'                        // ← CAMBIA
           AND endNode(r).name = 'app-cust-01') AS uses_the_cut        // ← CAMBIA
WITH entry, count(*) AS paths_before, sum(CASE WHEN uses_the_cut THEN 0 ELSE 1 END) AS paths_after
RETURN entry.name AS entry_host, paths_before, paths_after, paths_after = 0 AS no_longer_reaches_a_crown_jewel
ORDER BY entry_host;

// F.3 · Aislar por completo el host app-pay-01 (todo camino que lo cruza)
//       esperado: dmz-api-01 4 → 0 · dmz-portal-01 1 → 1 · dmz-web-01 6 → 2
CALL {
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:STORES]->(:DataStore {crown_jewel: true})
  RETURN p
  UNION ALL
  MATCH p = (e:Host {internet_exposed: true})-[:CAN_REACH*0..10]->(:Host)-[:RUNS_AS]->(:Identity)-[:HAS_ACCESS_TO]->(:DataStore {crown_jewel: true})
  RETURN p
}
WITH head(nodes(p)) AS entry,
     any(n IN nodes(p) WHERE n:Host AND n.name = 'app-pay-01' AND n <> head(nodes(p))) AS uses_the_cut   // ← CAMBIA
WITH entry, count(*) AS paths_before, sum(CASE WHEN uses_the_cut THEN 0 ELSE 1 END) AS paths_after
RETURN entry.name AS entry_host, paths_before, paths_after, paths_after = 0 AS no_longer_reaches_a_crown_jewel
ORDER BY entry_host;


// =====================================================================================
// PARTE G · GDS (COMPLEMENTO, A VALIDAR) — Aura Graph Analytics serverless, SESIÓN IMPLÍCITA
//
// Cómo funciona (igual que en la demo de data lineage, ya validada en esta instancia):
//   El algoritmo NO corre en la base de datos: corre en una sesión efímera. La primera proyección crea la sesión
//   por su cuenta y se elimina al borrar todos sus grafos (parte Z). Flujo: (1) proyectar, (2) ejecutar, (3) borrar.
//   Se factura por minuto. Los `nodeId` son los ids de la BD: se vuelve a los nodos con `MATCH (n) WHERE id(n) = nodeId`.
//
// Dos algoritmos, uno de cada tipo (decisión de la persona), ambos PROVISIONALES:
//   · BETWEENNESS (centralidad): ¿por qué nodos pasan más caminos mínimos? Puntos de estrangulamiento.
//   · LOUVAIN (comunidades): agrupa hosts en zonas naturales; los caminos que cruzan de una zona a otra son
//     candidatos a una regla de microsegmentación.
// Alcanzabilidad y caminos (partes A-F) son la parte fiable y explicable; GDS la complementa.
// =====================================================================================

// G.1 · BETWEENNESS ------------------------------------------------------------------

// G.1a · Proyección Cypher con dirección natural: hosts, identidades y almacenes con sus 4 tipos de relación
//        (crea la sesión implícita)
//        esperado: 24 nodos (14 hosts —sin tst-report-01, que no tiene relaciones—, 5 identidades, 5 almacenes)
//                  y 31 relaciones (15 CAN_REACH + 5 RUNS_AS + 6 HAS_ACCESS_TO + 5 STORES)
CYPHER runtime=parallel
MATCH (a)-[r:CAN_REACH|RUNS_AS|HAS_ACCESS_TO|STORES]->(b)
RETURN gds.graph.project(
  'attack_graph',
  a,
  b,
  {
    sourceNodeLabels: labels(a),
    targetNodeLabels: labels(b),
    relationshipType: type(r)
  },
  { memory: '2GB' }
) AS projection;

// G.1b · Comprobar la proyección
//        esperado: attack_graph · 24 nodos · 31 relaciones
CALL gds.graph.list('attack_graph')
YIELD graphName, nodeCount, relationshipCount
RETURN graphName, nodeCount, relationshipCount;

// G.1c · Betweenness (top 10)
//        esperado (cálculo de Brandes dirigido en Python; GDS puede diferir ligeramente):
//          Host app-cust-01 19.5 · Host app-bill-01 19.0 · Host app-pay-01 17.5 · Host mon-01 12.0 ·
//          Identity svc-billing 5.0 · Identity svc-customer-profile 4.0 · Host db-bill-01 3.0 · Host db-pay-01 1.5
//        LECTURA HONESTA: betweenness calcula sobre TODOS los pares de nodos, no solo entrada → activo crítico.
//          Por eso `mon-01` (donde convergen los logs) sale alto aunque NINGÚN camino a un activo crítico lo cruza,
//          y app-pay-01, que cruza el 73 % de los caminos reales, queda tercero. Se contrasta SIEMPRE con la parte E.
CALL gds.betweenness.stream('attack_graph')
YIELD nodeId, score
WHERE score > 0
MATCH (n) WHERE id(n) = nodeId
RETURN labels(n)[0] AS type, n.name AS name, round(score, 1) AS betweenness
ORDER BY betweenness DESC, name
LIMIT 10;

// G.2 · LOUVAIN ----------------------------------------------------------------------

// G.2a · Proyección nativa NO dirigida: solo hosts y CAN_REACH
//        esperado: 15 nodos y 30 relaciones (cada arista no dirigida cuenta dos veces)
//        (puede crear una segunda sesión implícita: se verá en Z.2)
CALL gds.graph.project(
  'host_zones',
  ['Host'],
  ['CAN_REACH'],
  { memory: '2GB', undirectedRelationshipTypes: ['*'] }
)
YIELD graphName, nodeCount, relationshipCount, projectMillis
RETURN graphName, nodeCount, relationshipCount, projectMillis;

// G.2b · Zonas (comunidades) y sus hosts
//        esperado: AL MENOS 4 comunidades (Louvain nunca mezcla componentes sin conexión):
//          · la zona aislada de gestión: app-prov-01, db-sub-01, int-web-01, jump-01 (4)
//          · db-cust-01 sola (1) y tst-report-01 sola (1)
//          · los 9 hosts conectados (dmz-*, app-*, db-pay-01, db-bill-01, mon-01) en 1, 2 o 3 comunidades
//        Louvain NO es determinista del todo: si la división de los 9 cambia entre ejecuciones, es normal.
//        Lectura: describe cómo se agrupa la red, no el riesgo. Se interpreta junto con los caminos.
CALL gds.louvain.stream('host_zones')
YIELD nodeId, communityId
MATCH (h:Host) WHERE id(h) = nodeId
WITH communityId, h ORDER BY h.name
WITH communityId, collect(h.name) AS hosts
RETURN communityId, size(hosts) AS size, hosts
ORDER BY size DESC, communityId;

// G.2c · Reglas de red que CRUZAN de una zona a otra: candidatas a microsegmentación
//        esperado: depende de cómo parta Louvain los 9 hosts conectados. Si los deja en una sola comunidad: 0 filas
//        (todas las reglas son internas a la zona). Cruza el resultado con E.2: la mejor regla a revisar es la que
//        cruza zonas Y soporta muchos caminos.
CALL gds.louvain.stream('host_zones')
YIELD nodeId, communityId
WITH collect({id: nodeId, community: communityId}) AS assignments
MATCH (a:Host)-[r:CAN_REACH]->(b:Host)
WITH a, b, r,
     head([x IN assignments WHERE x.id = id(a)]).community AS zone_a,
     head([x IN assignments WHERE x.id = id(b)]).community AS zone_b
WHERE zone_a <> zone_b
RETURN a.name AS from_host, zone_a AS from_zone, b.name AS to_host, zone_b AS to_zone, r.port AS port
ORDER BY from_zone, to_zone, from_host;


// =====================================================================================
// PARTE Z · BORRAR LAS PROYECCIONES Y LA SESIÓN (deja de facturar; el grafo de la BD no se toca)
// Ejecuta Z DESPUÉS de la parte G. Las demás partes no necesitan la sesión.
// =====================================================================================

// Z.1 · Borrar las proyecciones (una consulta por línea; si te saltaste una, omite su drop)
CALL gds.graph.drop('attack_graph')
YIELD graphName
RETURN graphName;

CALL gds.graph.drop('host_zones')
YIELD graphName
RETURN graphName;

// Z.2 · Comprobar que no queda ninguna sesión (esperado: 0 filas)
CALL gds.session.list()
YIELD id, name, status, memory, expiryDate
RETURN id, name, status, memory, expiryDate;

// Z.3 · Solo si Z.2 devuelve alguna sesión: bórrala por nombre (el que muestre Z.2)
// CALL gds.session.delete('<name>')
// YIELD deleted
// RETURN deleted;


// =====================================================================================
// PARTE H · CYPHER PURO — FALLBACK DE LAS COMUNIDADES: ZONAS POR ALCANZABILIDAD
// Sin GDS ni sesión. No es Louvain, pero responde lo mismo para la demo: ¿qué zonas hay y qué hosts caen en cada una?
// (El fallback de betweenness es la parte E.)
// =====================================================================================

// H.1 · Zonas: expuesto / alcanzable desde un expuesto / aislado
//       esperado: expuesto (3): dmz-api-01, dmz-portal-01, dmz-web-01
//                 alcanzable desde un expuesto (6): app-bill-01, app-cust-01, app-pay-01, db-bill-01, db-pay-01, mon-01
//                 aislado (6): app-prov-01, db-cust-01, db-sub-01, int-web-01, jump-01, tst-report-01
MATCH (h:Host)
WITH h, EXISTS { (:Host {internet_exposed: true})-[:CAN_REACH*1..10]->(h) } AS reachable
WITH h, CASE WHEN h.internet_exposed THEN '1 · expuesto'
             WHEN reachable THEN '2 · alcanzable desde un expuesto'
             ELSE '3 · aislado' END AS zone
ORDER BY h.name
RETURN zone, count(h) AS hosts, collect(h.name) AS host_names
ORDER BY zone;

// H.2 · Reglas de red que parten de un host expuesto (las «puertas» hacia la zona interna)
//       esperado: 4 reglas: dmz-web-01 → app-cust-01 · dmz-web-01 → app-pay-01 · dmz-api-01 → app-pay-01 ·
//         dmz-portal-01 → app-bill-01. Son los controles de «entrada» que más importan; el resto es movimiento lateral.
MATCH (a:Host {internet_exposed: true})-[r:CAN_REACH]->(b:Host)
RETURN a.name AS from_exposed_host, b.name AS to_internal_host, r.port AS port
ORDER BY from_exposed_host, to_internal_host;
