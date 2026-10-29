# queries/

Organizado por **caso de uso**, no por tipo de nodo (mismo criterio que en `data-lineage-fs-demo`).

> ⬜ **Solo esqueletos.** Los `.cypher` contienen cabecera e índice de lo previsto, **sin sentencias**, por instrucción de la persona (27-oct-2026). Cuando se escriban, todo será «a validar» hasta probarse en Aura. Requerirán haber cargado antes el dataset (`../data/`). Los repositorios de referencia no tienen licencia: las queries se escriben desde cero.

| Fichero | Caso | Qué contendrá (propuesta) |
|---|---|---|
| `01_supply_chain_zero_day.cypher` | 1 · Cadena de suministro | Ingesta idempotente de una vulnerabilidad nueva, aplicaciones afectadas por dependencias transitivas, hosts expuestos y servicios de negocio, librería compartida, reset |
| `02_vulnerability_prioritization.cypher` | 2 · Priorización | CVSS frente a riesgo contextual (alcanzabilidad, impacto, explotación conocida), lista priorizada |
| `03_attack_paths_gds.cypher` | 3 · Caminos de ataque | Caminos a activos críticos, blast radius, no alcanzables, puntos de estrangulamiento en Cypher, GDS (centralidad y comunidades, a validar) y fallback en Cypher puro |

Los literales que se cambian al reutilizar una query se marcarán con `← CAMBIA`.
