// =====================================================================================
// 01_supply_chain_zero_day.cypher — Caso 1 · Cadena de suministro y preparación ante un día cero
// Demo de ciberseguridad con Neo4j · AuraDB (Neo4j 5.x)
//
// ESTADO: ✅ VALIDADO en Aura (3-nov-2026): partes A a F ejecutadas y correctas. Pendiente solo la search phrase de Bloom
//         (F.4), que se comprobará al crear la perspectiva. Las cifras «esperado» salen de `python3 data/validate_dataset.py`.
//
// PRERREQUISITOS
//   · Carga base ejecutada: 70 nodos y 103 relaciones (sin el día cero).
//   · `baseUrl` definido (`:params` para comprobarlo; si no, ejecuta SOLO el PASO 0 de data/00_load_live.cypher).
//
// HILO: «sale una vulnerabilidad nueva → ¿dónde está?». El día cero es CVE-2021-44228 (Log4Shell), el único CVE
//       real del dataset; todo lo demás es sintético. Sus CSV viven en data/ pero se lanza desde AQUÍ, en directo.
//
// REGLA DE ORO: ejecuta primero la parte A (insertar) y después B..F (preguntas). Para repetir el ensayo, parte G (reset).
//
// ÍNDICE
//   A. Foto del grafo e inserción del día cero (idempotente)
//   B. Aplicaciones afectadas y a cuántos niveles de dependencia está la librería          ▣ dashboard
//   C. Hosts afectados y cuáles están expuestos a Internet                                  ▣ dashboard
//   D. Servicios de negocio afectados                                                       ▣ dashboard
//   E. Qué librería actualizar primero                                                      ▣ dashboard
//   F. Visuales en grafo y recorrido en Bloom (vulnerabilidad → librería → app → host / servicio)   ▣ dashboard (F.3b, mapa de servicios)
//   G. RESET del día cero
//
// ▣ = alimenta el dashboard «Supply Chain · Vulnerability Impact» (dashboards/). En el dashboard, el literal
//   'CVE-2021-44228' se sustituye por el parámetro $vulnerability (un filtro sobre Vulnerability.id): funciona con
//   CUALQUIER vulnerabilidad del grafo, no solo con el día cero. Detalle en dashboards/DASHBOARDS_GUIDE.md.
//
// LITERALES CAMBIABLES: 'CVE-2021-44228' ← CAMBIA (id de la vulnerabilidad que se consulta).
// Profundidad máxima de camino variable: 10.
// =====================================================================================


// =====================================================================================
// PARTE A · FOTO DEL GRAFO E INSERCIÓN DEL DÍA CERO
// =====================================================================================

// A.1 · Foto ANTES (para la narrativa)
//       esperado ANTES: 17 vulnerabilidades · 103 relaciones      (DESPUÉS de A.2 y A.3: 18 · 104)
MATCH (v:Vulnerability)
WITH count(v) AS vulnerabilities
MATCH ()-[r]->()
RETURN vulnerabilities, count(r) AS relationships;

// A.2 · La vulnerabilidad nueva (nodo). Idempotente: repetirlo no duplica.
LOAD CSV WITH HEADERS FROM $baseUrl + 'zero_day_vulnerability.csv' AS row
MERGE (v:Vulnerability {id: row.id})
SET v.cvss_score = toFloat(row.cvss_score),
    v.known_exploited = (row.known_exploited = 'true'),
    v.description = row.description;

// A.3 · Dónde cae: sobre la librería log4j-core, que ninguna aplicación usa directamente.
//       Si no se crea la relación, el MATCH no encontró `log4j-core` 2.14.1: ¿se cargó el segmento 1?
LOAD CSV WITH HEADERS FROM $baseUrl + 'zero_day_affects.csv' AS row
MATCH (v:Vulnerability {id: row.vulnerability_id})
MATCH (l:Library {name: row.library_name, version: row.library_version})
MERGE (v)-[:AFFECTS]->(l);

// A.4 · Comprobación
//       esperado: 1 fila · CVE-2021-44228 · 10.0 · true · log4j-core · 2.14.1
MATCH (v:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(l:Library)   // ← CAMBIA
RETURN v.id AS vulnerability, v.cvss_score AS cvss, v.known_exploited AS exploited,
       l.name AS library, l.version AS version;


// =====================================================================================
// PARTE B · ¿QUÉ APLICACIONES SE VEN AFECTADAS, AUNQUE LA LIBRERÍA ESTÉ ENTERRADA?
// Se sigue DEPENDS_ON hacia atrás, de la librería a las aplicaciones, hasta 10 niveles.
// =====================================================================================

// B.1 · Aplicaciones afectadas y nivel de dependencia (1 = la usa directamente la aplicación)
//       esperado: 6 filas
//         3 niveles: payments-core (P0), payments-gateway (P0)
//         4 niveles: customer-profile-service (P1), online-banking-web (P0), provisioning-engine (P0), staff-intranet (P2)
//       Lectura: NINGUNA aplicación depende de log4j-core directamente. Sin grafo, es una búsqueda manual.
MATCH p = (v:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(a:Application)   // ← CAMBIA
WITH a, min(length(p) - 1) AS dependency_levels
RETURN a.name AS application, a.tier AS tier, dependency_levels
ORDER BY dependency_levels, application;

// B.2 · Resumen en una fila
//       esperado: 6 afectadas de 9
MATCH (x:Application)
WITH count(x) AS total_applications
MATCH (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(a:Application)   // ← CAMBIA
RETURN count(DISTINCT a) AS affected_applications, total_applications;


// =====================================================================================
// PARTE C · ¿QUÉ SERVIDORES? ¿CUÁLES ESTÁN EXPUESTOS A INTERNET?
// El paso que las fuentes de referencia no dan: llegar de la aplicación al host.
// =====================================================================================

// C.1 · Hosts afectados, con las aplicaciones que corren en cada uno
//       esperado: 6 filas · 2 expuestos (dmz-api-01, dmz-web-01) y 4 internos
//         (app-cust-01, app-pay-01, app-prov-01, int-web-01)
MATCH (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(a:Application)-[:RUNS_ON]->(h:Host)   // ← CAMBIA
RETURN h.name AS host, h.environment AS environment, h.internet_exposed AS exposed,
       collect(DISTINCT a.name) AS applications
ORDER BY exposed DESC, host;

// C.2 · Solo lo URGENTE: hosts expuestos a Internet (OPCIONAL: redundante con C.1, que ya los marca; no se enseña)
//       esperado: 2 filas · dmz-api-01 (payments-gateway) y dmz-web-01 (online-banking-web)
MATCH (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(a:Application)-[:RUNS_ON]->(h:Host {internet_exposed: true})   // ← CAMBIA
RETURN h.name AS exposed_host, collect(DISTINCT a.name) AS applications
ORDER BY exposed_host;


// =====================================================================================
// PARTE D · TRADUCIDO A NEGOCIO: SERVICIOS AFECTADOS
// =====================================================================================

// D.1 · esperado: 4 de 5 servicios
//         Card Payments (High) ← payments-core, payments-gateway
//         Online Banking (High) ← customer-profile-service, online-banking-web
//         Subscriber Provisioning (High) ← provisioning-engine
//         Staff Intranet (Low) ← staff-intranet
//       No afectado: Billing and Invoicing (billing-engine y selfcare-portal no heredan la librería)
MATCH (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(a:Application)-[:SUPPORTS]->(b:BusinessService)   // ← CAMBIA
RETURN b.name AS business_service, b.criticality AS criticality, collect(DISTINCT a.name) AS applications
ORDER BY CASE criticality WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 ELSE 2 END, business_service;


// =====================================================================================
// PARTE E · ¿QUÉ LIBRERÍA ACTUALIZAR PRIMERO?
// =====================================================================================

// E.1 · Librerías de la cadena vulnerable y a cuántas aplicaciones afectadas arrastra cada una
//       esperado: 4 filas
//         log4j-core 6 · observability-sdk 6 · platform-commons 6 · service-kit 4
//       Lectura: actualizar platform-commons (o la propia log4j-core) cubre las 6 aplicaciones; service-kit solo 4.
MATCH (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(vl:Library)   // ← CAMBIA
MATCH (l:Library)-[:DEPENDS_ON*0..10]->(vl)
OPTIONAL MATCH (a:Application)-[:DEPENDS_ON*1..10]->(l)
WITH l, count(DISTINCT a) AS applications_depending
RETURN l.name AS library, l.version AS version, applications_depending
ORDER BY applications_depending DESC, library;

// E.2 · Librerías compartidas en TODO el grafo (no solo en la cadena vulnerable): candidatas a vigilar
//       esperado (top): crypto-utils 8 · json-parse-fast 7 · log4j-core 6 · observability-sdk 6 · platform-commons 6 ·
//         db-connector 5 · service-kit 4 · template-engine 4 · http-server-lite 3 · session-manager 2 · y 1 las demás
MATCH (l:Library)
OPTIONAL MATCH (a:Application)-[:DEPENDS_ON*1..10]->(l)
WITH l, count(DISTINCT a) AS applications_depending
RETURN l.name AS library, l.version AS version, applications_depending
ORDER BY applications_depending DESC, library;


// =====================================================================================
// PARTE F · VISUALES EN GRAFO Y RECORRIDO EN BLOOM
// Resultado en forma de GRAFO: Query tool (vista de grafo) o Bloom.
// =====================================================================================

// F.1 · La cadena completa: vulnerabilidad → librería → dependencias → aplicación → host
//       esperado: 6 caminos (uno por aplicación afectada; los nodos intermedios se comparten)
MATCH p = (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(:Application)-[:RUNS_ON]->(:Host)   // ← CAMBIA
RETURN p;

// F.2 · Lo mismo, hasta el servicio de negocio (OPTIONAL: no todas las aplicaciones tienen servicio)
MATCH p = (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(a:Application)-[:RUNS_ON]->(:Host)   // ← CAMBIA
OPTIONAL MATCH s = (a)-[:SUPPORTS]->(:BusinessService)
RETURN p, s;

// F.3 · Solo la parte urgente: hosts expuestos afectados
MATCH p = (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(:Application)-[:RUNS_ON]->(:Host {internet_exposed: true})   // ← CAMBIA
RETURN p;

// F.3b ▣ · Mapa vulnerabilidad → librerías → aplicaciones → servicios de negocio (tarjeta «Affected Services Map» del dashboard,
//          con `$vulnerability` en lugar del literal). Solo caminos que llegan a un servicio, sin hosts.
//          esperado (CVE-2021-44228): el grafo de 1 vulnerabilidad, 4 librerías, 6 aplicaciones y 4 servicios
MATCH p = (:Vulnerability {id: 'CVE-2021-44228'})-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(a:Application)-[:SUPPORTS]->(b:BusinessService)   // ← CAMBIA
RETURN p;


// -------------------------------------------------------------------------------------
// F.4 · BLOOM — UNA CONSULTA SIMPLE Y EL RESTO SE CAMINA A MANO
//
// Idea: en lugar de lanzar una query que devuelva todo el grafo, se BUSCA solo la vulnerabilidad en Bloom y se va
// ampliando (expandiendo) paso a paso: vulnerabilidad → librería → dependencias → aplicación → host / servicio. Es la
// forma de contar «cómo se propaga» sin enseñar Cypher. El recorrido paso a paso, con lo que debe aparecer en cada
// paso, está en GUIA_EJECUCION.md §4.
//
// ⚠️ Las search phrases se configuran en la perspectiva de Bloom (Aura → Explore → Perspective → Search phrases).
//    La perspectiva aún no está creada: esto es lo que hay que pegar, a validar al crearla.
//
// SEARCH PHRASE PRINCIPAL (la única necesaria)
//   Frase:   vulnerabilidad $id           (el parámetro $id admite autocompletado con una query; ver abajo)
//   Cypher:  la query F.4a
//
// F.4a · Buscar una vulnerabilidad por su id
//        esperado: 1 nodo (con CVE-2021-44228 insertado) · 0 filas si no existe
//        Prueba en el Query tool (define antes el parámetro; solo en el Query tool, Bloom lo sustituye solo):
//            :param id => 'CVE-2021-44228';
MATCH (v:Vulnerability)
WHERE v.id = $id
RETURN v;

// F.4b · (Opcional) Lista de sugerencias del parámetro $id: ids que ofrece Bloom al escribir
//        esperado: 17 ids sin el día cero · 18 con él
MATCH (v:Vulnerability)
RETURN DISTINCT v.id AS id
ORDER BY id;

// ATAJOS OPCIONALES (si en directo se prefiere no expandir a mano; mismas frases cortas, devuelven el camino ya hecho)
//   Frase: aplicaciones de $id   →  F.4c        Frase: servicios de $id   →  F.4d
//
// F.4c · Aplicaciones afectadas por la vulnerabilidad $id, con la cadena de librerías
//        esperado (CVE-2021-44228): 6 caminos, uno por aplicación
MATCH p = (v:Vulnerability)-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(:Application)
WHERE v.id = $id
RETURN p;

// F.4d · Servicios de negocio afectados por la vulnerabilidad $id
//        esperado (CVE-2021-44228): 4 servicios (Card Payments, Online Banking, Subscriber Provisioning, Staff Intranet)
MATCH p = (v:Vulnerability)-[:AFFECTS]->(:Library)<-[:DEPENDS_ON*1..10]-(:Application)-[:SUPPORTS]->(:BusinessService)
WHERE v.id = $id
RETURN p;


// =====================================================================================
// PARTE G · RESET DEL DÍA CERO (para repetir el ensayo)
// Elimina SOLO CVE-2021-44228 y su relación AFFECTS. No toca la librería ni nada de la carga base (sintética).
// ⚠️ Ejecútalo solo cuando quieras volver al estado previo al día cero.
// =====================================================================================

// G.1 · Borrar el día cero
MATCH (v:Vulnerability {id: 'CVE-2021-44228'})   // ← CAMBIA
DETACH DELETE v;

// G.2 · Comprobación
//       esperado: 17 vulnerabilidades · 103 relaciones  (la carga base intacta)
MATCH (v:Vulnerability)
WITH count(v) AS vulnerabilities
MATCH ()-[r]->()
RETURN vulnerabilities, count(r) AS relationships;
