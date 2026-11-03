# DASHBOARDS_GUIDE — dashboards de Aura de la demo

> **Export real de Aura Dashboards (`version: 2`), 3-nov-2026.** Partió de un JSON generado a mano a partir del formato de la demo de data lineage; la persona lo importó, añadió la tarjeta de grafo y lo volvió a exportar. El JSON del repo es el de Aura (Aura reordena y renombra algo: p. ej. el título lleva un guion simple).

| Dashboard | Fichero | Caso | Queries origen | Tarjetas | Parámetro |
|---|---|---|---|---|---|
| **Supply Chain - Vulnerability Impact** | `supply_chain_vulnerability_impact_dashboard.json` | 1 · Cadena de suministro | `queries/01_supply_chain_zero_day.cypher`, partes B, C, D y E (▣) | 1 filtro + 4 contadores + 3 tablas + 1 gráfico de barras + 1 grafo | `$vulnerability` |

Un solo dashboard con **tres pestañas**: «Supply Chain Vulnerability Impact» (caso 1), «Risk Prioritization» (caso 2) y «Attack Paths» (caso 3), cada una descrita más abajo. Solo **Cypher puro**: no usa GDS ni Aura Graph Analytics.

## Qué muestra

**Todo lo afectado por una vulnerabilidad, y solo cadena de suministro.** Se elige la vulnerabilidad con el filtro de arriba y el resto de tarjetas se recalcula. Funciona con **cualquier** vulnerabilidad del grafo, no solo con el día cero: el valor inicial es `CVE-2021-44228`, que solo aparece en el filtro tras insertarlo (`01`, parte A).

| # | Tarjeta | Query origen | Tipo y estilo |
|---|---|---|---|
| — | Filtro «1. Vulnerability» | — | Filtro de propiedad `Vulnerability.id`, enlazado a `$vulnerability`; valor inicial `CVE-2021-44228` |
| — | Affected applications | B (variante de una columna, `count`) | Valor único |
| — | Affected hosts | C (variante `count`) | Valor único |
| — | Exposed hosts (urgent) | C (variante `count`, solo `internet_exposed`) | Valor único |
| — | Affected business services | D (variante `count`) | Valor único |
| 2 | Affected Applications (dependency levels) | B.1 | Tabla; `tier` en amarillo cuando contiene `P0` |
| 3 | Affected Hosts | C.1 (con columna `exposure`: `EXPOSED` o `internal`) | Tabla; `exposure` en rojo cuando contiene `EXPOSED` |
| 4 | Business Services Affected | D.1 | Tabla; `criticality` en amarillo cuando contiene `High` |
| 5 | Library to Update First | E.1 (sin la columna de versión) | Gráfico de barras horizontal sobre `applications_depending` |
| — | **Affected Services Map** | F.3b (nueva) | Grafo: vulnerabilidad → librerías → aplicaciones → servicios de negocio, con `$vulnerability`; layout `d3Force`, sin reglas de estilo |

**Diferencia con las queries del `.cypher`:** en el dashboard el literal `'CVE-2021-44228'` es `$vulnerability`, y C.1 devuelve `exposure` (texto) en lugar de `exposed` (booleano) para poder colorearlo con una regla de texto. El grafo del dashboard es la F.3b; el resto de la parte F (con hosts y la búsqueda de Bloom) se hace en Bloom.

## Cifras esperadas (calculadas sobre los CSV, no ejecutadas en Aura)

| `$vulnerability` | Aplicaciones | Hosts | Expuestos | Servicios |
|---|---|---|---|---|
| `CVE-2021-44228` (día cero insertado) | 6 | 6 | 2 | 4 |
| `SYN-0003` (la «Medium» explotada) | 4 | 4 | 2 | 4 |
| `SYN-0004` | 3 | 3 | 3 | 4 |
| `SYN-0002` (la «Critical» aislada) | 1 | 1 | 0 | 0 |

Con `CVE-2021-44228`: aplicaciones a 3 niveles (`payments-core`, `payments-gateway`) y a 4 (el resto); hosts expuestos `dmz-api-01` y `dmz-web-01`; librería a actualizar: `log4j-core`, `observability-sdk` y `platform-commons` con 6 aplicaciones, y `service-kit` con 4.

## Cómo importarlo

1. Carga base ejecutada (`data/00_load_live.cypher`). Para ver el día cero, ejecuta antes `01`, parte A.
2. Aura → Dashboards → importar el JSON → elegir la instancia.
3. Las tarjetas llevan `"databaseName": "neo4j"` (la base por defecto de Aura). Si la instancia usa otro nombre, cámbialo en cada tarjeta.
4. No contiene credenciales ni identificadores de instancia.

## Cómo contarlo (60-90 s)

1. Con `CVE-2021-44228`: «seis aplicaciones, seis servidores, **dos expuestos a Internet**, cuatro servicios de negocio.»
2. Tabla de aplicaciones: «ninguna usa la librería directamente: a tres y cuatro niveles.»
3. Tabla de hosts: los dos en rojo son lo urgente; los demás, después.
4. Servicios: «Card Payments, Online Banking y Subscriber Provisioning, los tres de criticidad alta, están afectados.»
5. Mapa de grafo: «así llega la vulnerabilidad a cada servicio de negocio.»
6. Gráfico: «actualizar `platform-commons` o la propia `log4j-core` cubre las seis aplicaciones.»
7. Cambiar el filtro a otra vulnerabilidad (p. ej. `SYN-0003`): el mismo cuadro de mando sirve para cualquier alerta futura.

## Cuidado

- `$vulnerability` solo existe dentro del dashboard. Si pegas una query de una tarjeta en el Query tool, define antes `:param vulnerability => 'CVE-2021-44228';`.
- Las queries de las tarjetas son copias de las `▣` del `.cypher` con `$vulnerability`. No hay vínculo automático: si cambias una, actualiza también la tarjeta (y este fichero).
- Antes de insertar el día cero el filtro no lista `CVE-2021-44228` y las tarjetas salen vacías con el valor inicial: elige otra vulnerabilidad o inserta el día cero.
- El gráfico usa `ORDER BY ... ASC`: con barras horizontales la mayor queda arriba.


---

# Pestaña 2 · «Risk Prioritization» (caso 2)

> **Pestaña generada por el agente a partir de `queries/02` e importada y validada en Aura por la persona (3-nov-2026).** Las partes A, B, C, F y G son copias de `queries/02`; los contadores, la leyenda y la C.2 son propios del dashboard. Si se retoca en Aura, se vuelve a exportar y se sustituye el fichero.

**Historia que cuenta, de arriba abajo:** «un scanner ordena por CVSS; nosotros añadimos contexto (alcance, impacto, explotación) y el orden cambia. La "Critical" aislada baja y la "Medium" expuesta sube. Y de ahí sale una lista de acciones.» **No es un parámetro: no usa el filtro `$vulnerability`.** Los literales `SYN-0002`, `tst-report-01`, `SYN-0003` y `CVE-2021-44228` están dentro de las queries (en D y G, igual que en `queries/02`).

**Código de color (en las tres tablas de vulnerabilidades):** amarillo = la «Critical» que parece urgente y no lo es (`SYN-0002`); rojo = la «Medium» que sí lo es (`SYN-0003`). En la tabla de hosts, rojo = expuesto a Internet (alcance 1.5) y amarillo = el host de pruebas aislado.

| Fila | Tarjeta | Query origen | Qué explica |
|---|---|---|---|
| 0 | 4 contadores: «Scanner's #1», «Context's #1», puesto de la «Critical», puesto de la «Medium» | A y C (variantes de una celda) | El resumen de la historia en cuatro cifras |
| 1 | **1.** Qué ve un scanner | A.1 | Las vulnerabilidades por CVSS puro, con la «Critical» en amarillo y la «Medium» en rojo |
| 1 | **2.** Qué añadimos | Leyenda (nueva, sin base de datos) | Tabla con los multiplicadores de la fórmula `riesgo = CVSS × alcance × impacto × explotación` y cuándo se aplica cada uno |
| 2 | **3.** Contexto de cada host | B.1 | Alcance (1.5 / 1.25 / 1.0) e impacto (2.0 / 1.0) de los 15 hosts; «aislado» no significa «inocuo» |
| 3 | **4.** Riesgo por pareja: top 12 + la «Critical» aislada | **C.2** (C.1 con la «Critical» añadida; sustituye a C.1 y D.1 en el dashboard) | Una sola tabla con `cvss_rank` frente a `risk_rank`: arriba, en rojo, lo que sube (la «Medium»); abajo, en amarillo, lo que baja (la «Critical») |
| 4 | **5.** Qué librería actualizar primero | F.1 | La lista de acciones: «actualizar `template-engine` cierra 2 vulnerabilidades en 4 hosts» |
| 5 | **6.** Log4Shell en contexto | G.1 | El día cero puntuado host a host: de 45.0 a 15.0 |

**Una tarjeta por idea, sin duplicar.** La pestaña no tiene gráficos de barras de F.1 ni de G.1 (eran la misma tabla dibujada otra vez) ni una tabla aparte de contraste (D.1; se fusionó con C.1 en C.2). D.1 sigue en `queries/02` para el Query tool.

**No están en el dashboard:** E.1 y E.2 (caminos que justifican el impacto), que se enseñan en **Bloom** con las search phrases `caminos de $host a activos críticos` y `alcance de $host` (`queries/02`, parte E.3).

## Cifras esperadas

Los contadores y las tablas se calculan solos; el estado del grafo cambia las cifras. Calculado sobre los CSV, no en Aura (salvo lo ya validado en `queries/02`).

| Tarjeta | Sin día cero (carga base) | Con día cero (lo normal en la demo) |
|---|---|---|
| Scanner's #1 | `SYN-0002 (CVSS 9.8)` | `CVE-2021-44228 (CVSS 10.0)` |
| Context's #1 | `SYN-0003 @ dmz-portal-01 (riesgo 22.5)` | `CVE-2021-44228 @ dmz-api-01 (riesgo 45.0)` |
| Puesto de `SYN-0002` en `tst-report-01` | rank 35 of 61 | rank 41 of 67 |
| Puesto de `SYN-0003` en `dmz-web-01` | rank 1 of 61 (empatada) | rank 6 of 67 |
| Tabla 6 (Log4Shell) | vacía | 6 filas: 45.0, 45.0, 37.5, 37.5, 30.0, 15.0 |

La lectura es la misma en los dos estados: la «Critical» está muy abajo y la «Medium» muy arriba. Con el día cero insertado, además, Log4Shell domina la cabeza del ranking y `SYN-0003` baja al puesto 6 sin perder la historia.

## Cómo contarlo (2-3 min)

1. Contadores: «el scanner dice que lo primero es esto; el contexto dice esto otro. La "Critical" está en el puesto N de M.»
2. Tabla 1: «así se ve la vida con CVSS: la amarilla es la primera.»
3. Tabla 2: «lo que añadimos: ¿llega alguien desde fuera?, ¿se llega a datos críticos?, ¿se está explotando ya?»
4. Tabla 3: «los hosts con su contexto. Los rojos están expuestos; el amarillo es el de pruebas, aislado y sin datos.»
5. Tabla 4: «mismas vulnerabilidades, otro orden: la "Medium" (rojo) pasa de la posición 33 por CVSS a la 1 por riesgo, y la "Critical" (amarillo) cae al final.» **→ Bloom:** `caminos de dmz-web-01 a activos críticos` («esta es la ruta hasta datos de clientes») y `alcance de tst-report-01` («y este host no llega a nada»).
6. Tabla 5: «y de aquí sale el trabajo: una librería, varios hosts.»
7. Tabla 6: «Log4Shell, ya con contexto: de 45 a 15 según dónde esté.»

## Cuidado

- Las tarjetas de la pestaña 2 con literales (`SYN-0002`, `tst-report-01`, `SYN-0003`, `CVE-2021-44228`) no responden al filtro de la pestaña 1.
- Si no hay día cero insertado, la tabla 6 sale vacía y los dos contadores de contexto cambian (ver tabla anterior).
- Las tarjetas de riesgo recalculan todo el grafo cada una (15 hosts, 61-67 parejas): con este tamaño es instantáneo, pero no lo copies tal cual a un grafo grande.


---

# Pestaña 3 · «Attack Paths» (caso 3)

> **Pestaña generada por el agente a partir de `queries/03` e importada y validada en Aura por la persona (3-nov-2026).** Las tablas son copias de `queries/03` (A.1, B.1, C.1, D.1, E.1, F.1, F.3); los contadores son propios del dashboard. Usa solo las partes A a F (Cypher puro); GDS no.

**Historia:** «de las puertas a Internet hasta lo que más importa: qué caminos hay, cuáles no ve un cortafuegos, dónde se concentran y qué pasa si corto.» **No usa el selector `$vulnerability`.** No hay literales de entrada: son los mismos para siempre (los que dice el grafo).

**Código de color:** amarillo = camino por identidad (invisible para un cortafuegos); rojo = lo que se quiere señalar (`svc-billing`, `app-pay-01`); verde = lo bien protegido, o una entrada que el corte deja sin caminos.

| Fila | Tarjeta | Query origen | Qué explica |
|---|---|---|---|
| 0 | 4 contadores: puertas a Internet, caminos, activos críticos alcanzables, mayor estrangulamiento | variantes de una celda de A.1, D.1 y E.1 | El resumen del caso: 3 · 11 · 2 of 3 · `app-pay-01` (8 of 11 paths) |
| 1 | **1.** Todos los caminos | A.1 | 11 caminos, uno por fila: 2 por red y 9 por identidad (amarillo), con la ruta salto a salto |
| 2 | **2.** Solo por identidad | B.1 | 7 caminos sin ruta de red hasta el dato; `svc-billing` en rojo |
| 3 | **3.** Blast radius | C.1 | Hosts, identidades, almacenes y activos críticos que alcanza cada entrada |
| 3 | **4.** El activo que nadie alcanza | D.1 | `Subscriber Registry`, en verde |
| 4 | **5.** Estrangulamiento | E.1 | Por cuántos de los 11 caminos pasa cada host e identidad; `app-pay-01` en rojo (8, el 73 %) |
| 5 | **6.** What-if: quitar el permiso `svc-billing` → `Customer PII DB` | F.1 | Caminos antes y después, por entrada; en verde las entradas que quedan sin caminos |
| 5 | **7.** What-if: aislar `app-pay-01` | F.3 | Lo mismo, aislando el host |

**No están en el dashboard:** E.2 (reglas de red) y F.2 (cortar una regla), que dan lo mismo por regla que E.1 y F.1 por host, y toda la parte G (GDS). Los caminos dibujados (A.2, A.3, B.2, C.2, D.2) se enseñan en Bloom o en el Query tool.

## Cifras esperadas

No dependen del día cero ni de ningún parámetro. Calculadas sobre los CSV (`validate_dataset.py`), no en Aura.

| Tarjeta | Esperado |
|---|---|
| Puertas a Internet | 3 (`dmz-web-01`, `dmz-api-01`, `dmz-portal-01`) |
| Caminos | 11 (2 por red a `Card Ledger`, 9 por identidad): `dmz-web-01` 6, `dmz-api-01` 4, `dmz-portal-01` 1 |
| Activos críticos alcanzables | 2 of 3 (`Customer PII DB`, `Card Ledger`) |
| Mayor estrangulamiento | `app-pay-01 (8 of 11 paths)` |
| Tabla 2 (solo identidad) | 7 filas, todas a `Customer PII DB` (`dmz-web-01` 4, `dmz-api-01` 2, `dmz-portal-01` 1) |
| Tabla 3 (blast radius) | `dmz-api-01` y `dmz-web-01`: 6 hosts · 4 identidades · 4 almacenes · 2 críticos; `dmz-portal-01`: 3 · 2 · 3 · 1 |
| Tabla 4 (no alcanzable) | 1 fila: `Subscriber Registry` |
| Tabla 5 (estrangulamiento) | `app-pay-01` 8 (73 %) · `app-cust-01` 6 (55 %) · `app-bill-01` 4 (36 %) · `svc-billing` 4 (36 %) · `svc-customer-profile` 3 (27 %) · `db-pay-01` 2 · `svc-payments` 2 |
| Tabla 6 (what-if permiso) | `dmz-api-01` 4 → 3 · `dmz-portal-01` 1 → **0** · `dmz-web-01` 6 → 4 |
| Tabla 7 (what-if aislar) | `dmz-api-01` 4 → **0** · `dmz-portal-01` 1 → 1 · `dmz-web-01` 6 → 2 |

## Cómo contarlo (3-4 min)

Las frases de cada tarjeta, en `GUIA_EJECUCION.md` §6 («Qué decir en cada tarjeta · pestaña 3»). Hilo: contadores → todos los caminos → los de identidad → alcance de cada puerta → lo protegido → dónde se concentran → qué pasa si corto.

## Cuidado

- Las tablas usan la sintaxis `CALL () { ... }` / `CALL (e) { ... }` (Neo4j 5.23 o superior), la misma que `queries/03`. Si tu instancia fuera más antigua, las tarjetas fallarían: habría que reescribirlas con `CALL { WITH ... }`.
- Las columnas `route` (listas de nombres) se ven bien en tabla, pero son largas: si ensucian la pantalla, usa el ancho completo (la tarjeta 1 ya lo tiene) o quita la columna en la tarjeta.
- En las dos tarjetas de what-if, el verde se activa con `paths_after = 0`: si aparece una fila verde sin querer, revisa que la columna sea numérica.
- «Guardar» en Aura reordena y renombra algo del JSON: al volver a exportar, sustituye el fichero del repo.
