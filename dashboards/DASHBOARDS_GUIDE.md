# DASHBOARDS_GUIDE — dashboards de Aura de la demo

> **Export real de Aura Dashboards (`version: 2`), 3-nov-2026.** Partió de un JSON generado a mano a partir del formato de la demo de data lineage; la persona lo importó, añadió la tarjeta de grafo y lo volvió a exportar. El JSON del repo es el de Aura (Aura reordena y renombra algo: p. ej. el título lleva un guion simple).

| Dashboard | Fichero | Caso | Queries origen | Tarjetas | Parámetro |
|---|---|---|---|---|---|
| **Supply Chain - Vulnerability Impact** | `supply_chain_vulnerability_impact_dashboard.json` | 1 · Cadena de suministro | `queries/01_supply_chain_zero_day.cypher`, partes B, C, D y E (▣) | 1 filtro + 4 contadores + 3 tablas + 1 gráfico de barras + 1 grafo | `$vulnerability` |

Una sola página («Main page»). Solo **Cypher puro**: no usa GDS ni Aura Graph Analytics. Los candidatos de priorización y de caminos de ataque quedan para más adelante.

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
4. Servicios: «Card Payments y Online Banking, de criticidad alta, están afectados.»
5. Mapa de grafo: «así llega la vulnerabilidad a cada servicio de negocio.»
6. Gráfico: «actualizar `platform-commons` o la propia `log4j-core` cubre las seis aplicaciones.»
7. Cambiar el filtro a otra vulnerabilidad (p. ej. `SYN-0003`): el mismo cuadro de mando sirve para cualquier alerta futura.

## Cuidado

- `$vulnerability` solo existe dentro del dashboard. Si pegas una query de una tarjeta en el Query tool, define antes `:param vulnerability => 'CVE-2021-44228';`.
- Las queries de las tarjetas son copias de las `▣` del `.cypher` con `$vulnerability`. No hay vínculo automático: si cambias una, actualiza también la tarjeta (y este fichero).
- Antes de insertar el día cero el filtro no lista `CVE-2021-44228` y las tarjetas salen vacías con el valor inicial: elige otra vulnerabilidad o inserta el día cero.
- El gráfico usa `ORDER BY ... ASC`: con barras horizontales la mayor queda arriba.
