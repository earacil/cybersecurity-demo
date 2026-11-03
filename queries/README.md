# queries/

Organizado por **caso de uso**, no por tipo de nodo (mismo criterio que en `data-lineage-fs-demo`).

> **Estado (3-nov-2026):** carga base y `01` **validadas en Aura** por la persona. `02` y `03` (incluido GDS) están escritas y **pendientes de validar**; no se han ejecutado todavía. Todas las cifras «esperado» de los comentarios salen de `python3 ../data/validate_dataset.py` (cálculo en Python independiente de Neo4j), no de una ejecución real. Los repositorios de referencia no tienen licencia: las queries se escriben desde cero.

**Orden de ejecución (importa):** carga base → `01` (A. insertar el día cero) → resto de `01` → `02` → `03`. Las partes `02`.G y `01`.G dependen de que el día cero esté insertado o borrado, respectivamente.

| Fichero | Caso | Contenido |
|---|---|---|
| `01_supply_chain_zero_day.cypher` | 1 · Cadena de suministro | A. foto e **inserción del día cero** (Log4Shell, desde `../data/zero_day_*.csv`) · B. aplicaciones afectadas y nivel de dependencia · C. hosts afectados y expuestos · D. servicios de negocio · E. qué librería actualizar primero · F. visuales y **Bloom** (buscar la vulnerabilidad y expandir) · **G. reset**. Las partes B, C, D y E alimentan el dashboard `../dashboards/supply_chain_vulnerability_impact_dashboard.json` |
| `02_vulnerability_prioritization.cypher` | 2 · Priorización | A. ranking por CVSS · B. contexto del host (alcanzabilidad e impacto) · C. riesgo por pareja vulnerabilidad-host con ranking · D. el contraste «Critical aislada» frente a «Medium expuesta» · E. camino que lo justifica (Bloom) · F. acciones por librería · G. efecto del día cero |
| `03_attack_paths_gds.cypher` | 3 · Caminos de ataque | A. caminos entrada→activo crítico · B. solo por identidad · C. blast radius · D. activos críticos no alcanzables · E. puntos de estrangulamiento (nodos y reglas de red) · F. what-if · **G. GDS** (betweenness y Louvain) · Z. borrar sesión · H. fallback en Cypher puro |

## Convenciones

- Los literales que se cambian al reutilizar una query están marcados con `← CAMBIA`.
- Profundidad máxima de camino variable: **10**.
- Cada query lleva un comentario `esperado:` con las cifras que deben salir; si no cuadran, parar y revisar la carga (`../data/00_load_live.cypher`, bloque de verificación).
- Las partes con GDS (`03`.G) están separadas y tienen su equivalente en Cypher puro: la demo no depende de ellas.
- `:param baseUrl` debe estar definido solo para `01`.A (lee los CSV del día cero).
