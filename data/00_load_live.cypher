// =====================================================================================
// 00_load_live.cypher — carga del dataset sintético, segmentada por capa
// Demo de ciberseguridad con Neo4j · Neo4j 5.x (AuraDB)
//
// ⚠️  A VALIDAR en Aura (29-oct-2026): los CSV están validados por `validate_dataset.py`, pero este
//     script aún no se ha ejecutado contra una instancia real. Tras cargar, comprueba los recuentos del
//     bloque de VERIFICACIÓN (abajo) contra la salida de `python3 validate_dataset.py`.
//
// CÓMO USARLO
//   1. Ejecuta el PASO 0: define `baseUrl` apuntando a los CSV (repo público; para la demo, mejor una
//      etiqueta o SHA que `main`). `:param` es un comando del Query tool, NO Cypher: ejecútalo SOLO.
//      Se pierde al refrescar la página: comprueba con `:params`.
//   2. Ejecuta el segmento 0 (restricciones) y luego los segmentos 1..4 EN ORDEN. Todos son
//      idempotentes (MERGE): se pueden repetir sin duplicar. Si el editor solo ejecuta una sentencia a la
//      vez, ve sentencia a sentencia (separadas por `;`).
//   3. Ejecuta la VERIFICACIÓN. Debe dar 70 nodos y 103 relaciones (sin el día cero).
//   4. El día cero (CVE-2021-44228) NO forma parte de esta carga: va aparte, para lanzarlo EN DIRECTO:
//        01_zero_day_insert.cypher  → lo inserta        02_zero_day_reset.cypher → lo elimina (reset)
//      Así el grafo de partida es 100 % sintético y el único CVE real es el de la historia.
//
// EL ORDEN IMPORTA: restricciones → software → infraestructura → identidad y datos → negocio.
//   Cada segmento usa MATCH sobre nodos que ya deben existir (las relaciones de un segmento solo
//   enlazan nodos creados en ese segmento o en uno anterior). Si ejecutas uno antes de tiempo,
//   las relaciones no se crean y NO hay error: la VERIFICACIÓN lo delata.
//
// CLAVES DE MERGE (legibles a propósito):
//   Vulnerability.id · Library (name, version) · Application.name · Host.name · Identity.name ·
//   DataStore.name · BusinessService.name
//
// Alternativa local (Desktop/Docker): copiar data/*.csv a `import/` y usar `:param baseUrl => 'file:///'`.
//
// CAMBIA: la URL del PASO 0 si el repo o la rama/etiqueta cambian.
// =====================================================================================


// -------------------------------------------------------------------------------------
// PASO 0 · Parámetro `baseUrl` (con `/` final)                                  ← CAMBIA
// -------------------------------------------------------------------------------------

:param baseUrl => 'https://raw.githubusercontent.com/earacil/cybersecurity-demo/main/data/';

// Prueba de humo (ejecutar sola; debe devolver 15)
LOAD CSV WITH HEADERS FROM $baseUrl + 'hosts.csv' AS row
RETURN count(row) AS hosts;


// -------------------------------------------------------------------------------------
// SEGMENTO 0 · Restricciones
// -------------------------------------------------------------------------------------

CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;
CREATE CONSTRAINT library_name_version IF NOT EXISTS FOR (l:Library) REQUIRE (l.name, l.version) IS UNIQUE;
CREATE CONSTRAINT application_name IF NOT EXISTS FOR (a:Application) REQUIRE a.name IS UNIQUE;
CREATE CONSTRAINT host_name IF NOT EXISTS FOR (h:Host) REQUIRE h.name IS UNIQUE;
CREATE CONSTRAINT identity_name IF NOT EXISTS FOR (i:Identity) REQUIRE i.name IS UNIQUE;
CREATE CONSTRAINT data_store_name IF NOT EXISTS FOR (d:DataStore) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT business_service_name IF NOT EXISTS FOR (b:BusinessService) REQUIRE b.name IS UNIQUE;


// -------------------------------------------------------------------------------------
// SEGMENTO 1 · Capa de software: librerías, vulnerabilidades, aplicaciones y dependencias
// Narrar: «el inventario de software y el scanner de vulnerabilidades, unidos».
// -------------------------------------------------------------------------------------

LOAD CSV WITH HEADERS FROM $baseUrl + 'libraries.csv' AS row
MERGE (l:Library {name: row.name, version: row.version});

LOAD CSV WITH HEADERS FROM $baseUrl + 'vulnerabilities.csv' AS row
MERGE (v:Vulnerability {id: row.id})
SET v.cvss_score = toFloat(row.cvss_score),
    v.known_exploited = (row.known_exploited = 'true'),
    v.description = row.description;

LOAD CSV WITH HEADERS FROM $baseUrl + 'affects.csv' AS row
MATCH (v:Vulnerability {id: row.vulnerability_id})
MATCH (l:Library {name: row.library_name, version: row.library_version})
MERGE (v)-[:AFFECTS]->(l);

LOAD CSV WITH HEADERS FROM $baseUrl + 'applications.csv' AS row
MERGE (a:Application {name: row.name})
SET a.tier = row.tier;

LOAD CSV WITH HEADERS FROM $baseUrl + 'lib_depends_on.csv' AS row
MATCH (a:Library {name: row.from_name, version: row.from_version})
MATCH (b:Library {name: row.to_name, version: row.to_version})
MERGE (a)-[:DEPENDS_ON]->(b);

LOAD CSV WITH HEADERS FROM $baseUrl + 'app_depends_on.csv' AS row
MATCH (a:Application {name: row.application})
MATCH (l:Library {name: row.library_name, version: row.library_version})
MERGE (a)-[:DEPENDS_ON]->(l);


// -------------------------------------------------------------------------------------
// SEGMENTO 2 · Infraestructura: hosts, dónde corre cada aplicación y qué alcanza qué
// Narrar: «el inventario de servidores y las reglas de red».
// -------------------------------------------------------------------------------------

LOAD CSV WITH HEADERS FROM $baseUrl + 'hosts.csv' AS row
MERGE (h:Host {name: row.name})
SET h.environment = row.environment,
    h.internet_exposed = (row.internet_exposed = 'true');

LOAD CSV WITH HEADERS FROM $baseUrl + 'runs_on.csv' AS row
MATCH (a:Application {name: row.application})
MATCH (h:Host {name: row.host})
MERGE (a)-[:RUNS_ON]->(h);

LOAD CSV WITH HEADERS FROM $baseUrl + 'can_reach.csv' AS row
MATCH (a:Host {name: row.from_host})
MATCH (b:Host {name: row.to_host})
MERGE (a)-[r:CAN_REACH]->(b)
SET r.port = toInteger(row.port);


// -------------------------------------------------------------------------------------
// SEGMENTO 3 · Identidad y datos: identidades, almacenes, quién accede y dónde viven
// Narrar: «IAM y el catálogo de datos; el eslabón que casi nunca se ve junto a la red».
// -------------------------------------------------------------------------------------

LOAD CSV WITH HEADERS FROM $baseUrl + 'identities.csv' AS row
MERGE (i:Identity {name: row.name})
SET i.type = row.type;

LOAD CSV WITH HEADERS FROM $baseUrl + 'data_stores.csv' AS row
MERGE (d:DataStore {name: row.name})
SET d.data_class = row.data_class,
    d.crown_jewel = (row.crown_jewel = 'true');

LOAD CSV WITH HEADERS FROM $baseUrl + 'runs_as.csv' AS row
MATCH (h:Host {name: row.host})
MATCH (i:Identity {name: row.identity})
MERGE (h)-[:RUNS_AS]->(i);

LOAD CSV WITH HEADERS FROM $baseUrl + 'has_access_to.csv' AS row
MATCH (i:Identity {name: row.identity})
MATCH (d:DataStore {name: row.data_store})
MERGE (i)-[:HAS_ACCESS_TO]->(d);

LOAD CSV WITH HEADERS FROM $baseUrl + 'stores.csv' AS row
MATCH (h:Host {name: row.host})
MATCH (d:DataStore {name: row.data_store})
MERGE (h)-[:STORES]->(d);


// -------------------------------------------------------------------------------------
// SEGMENTO 4 · Negocio: servicios de negocio y qué aplicación los sostiene
// Narrar: «traducimos el riesgo técnico a lo que le importa al negocio».
// -------------------------------------------------------------------------------------

LOAD CSV WITH HEADERS FROM $baseUrl + 'business_services.csv' AS row
MERGE (b:BusinessService {name: row.name})
SET b.criticality = row.criticality;

LOAD CSV WITH HEADERS FROM $baseUrl + 'supports.csv' AS row
MATCH (a:Application {name: row.application})
MATCH (b:BusinessService {name: row.business_service})
MERGE (a)-[:SUPPORTS]->(b);


// -------------------------------------------------------------------------------------
// VERIFICACIÓN · recuentos esperados tras los segmentos 0-4 (sin el día cero)
//   Nodos:  Application 9 · BusinessService 5 · DataStore 5 · Host 15 · Identity 5 · Library 14 · Vulnerability 17  (=70)
//   Rel.:   AFFECTS 17 · CAN_REACH 15 · DEPENDS_ON 37 · HAS_ACCESS_TO 6 · RUNS_AS 5 · RUNS_ON 9 · STORES 5 · SUPPORTS 9  (=103)
// Si algún recuento no cuadra, un MATCH no encontró su extremo (revisa nombres y versiones).
// -------------------------------------------------------------------------------------

MATCH (n)
RETURN labels(n)[0] AS label, count(*) AS total
ORDER BY label;

MATCH ()-[r]->()
RETURN type(r) AS relationship, count(*) AS total
ORDER BY relationship;
