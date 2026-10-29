# Modelo de datos — Cybersecurity Demo (BORRADOR)

> **Estado: propuesta sin validar**, simplificada a propósito. Parte del modelo común que usan los tres repositorios de ejemplo de Neo4j (priorización, caminos de ataque y cadena de suministro comparten grafo) y lo reduce a lo mínimo. Procedencia: **FUENTE** (aparece en las páginas o repos de referencia, entre paréntesis cuál) o **PROPUESTA** (añadido o cambiado para esta demo). Decisiones abiertas en `../CONTEXTO_IA.md`.

Convención: **identificadores en inglés**; prosa en español. Fuentes: **VPEM**, **APA**, **SBOM** = las tres subpáginas/repos de casos de uso; **Blog** = artículo de caminos de ataque.

## Nodos (7)

| Nodo | Propiedades | Procedencia | Para qué sirve |
|---|---|---|---|
| `Vulnerability` | `id`, `cvss_score`, `known_exploited` (boolean), `description` | FUENTE (VPEM: `CVE`, `baseScore`, flag KEV); renombrado y recortado | Lo que hay que priorizar. El identificador puede ser sintético (ver `../CONTEXTO_IA.md`, decisión abierta 1: propuesta de identificadores sintéticos) |
| `Library` | `name`, `version` | FUENTE (SBOM: `Library`) | Componente de software, con dependencias transitivas |
| `Application` | `name`, `tier` (`"P0"` \| `"P1"` \| `"P2"` \| `"P3"`) | FUENTE (VPEM/APA/SBOM: `Application.tier`) | Lo que se ejecuta; el `tier` aproxima el impacto de negocio |
| `Host` | `id`, `name`, `environment` (`"Production"` \| `"Test"`), `internet_exposed` (boolean) | FUENTE (VPEM/APA: `ComputeInstance`, `public_ip`); la IP pública pasa a booleano | Servidor o función de red donde corre una aplicación; `internet_exposed = true` marca el punto de entrada |
| `Identity` | `name`, `type` (`"ServiceAccount"` \| `"Role"` \| `"User"`) | FUENTE (VPEM/APA/Blog: `Identity`) | Qué credenciales hereda quien compromete un host |
| `DataStore` | `name`, `data_class` (`"PII"` \| `"Financial"` \| `"Subscriber"` \| `"Operational"`), `crown_jewel` (boolean) | FUENTE (VPEM: `CloudService`/S3; APA: BD «Crown Jewel» P0; Blog: activo crítico) | El objetivo del atacante. `crown_jewel = true` es el «activo crítico» |
| `BusinessService` | `name`, `criticality` (`"High"` \| `"Medium"` \| `"Low"`) | PROPUESTA (VPEM habla de impacto de negocio sin definir un nodo) | Da sabor banca/telecom y traduce el riesgo a negocio (ejemplos: pagos con tarjeta, banca online, aprovisionamiento de abonados, facturación) |

## Relaciones (8)

| Relación | Patrón | Procedencia | Descripción |
|---|---|---|---|
| `AFFECTS` | `(Vulnerability)-[:AFFECTS]->(Library)` | FUENTE (SBOM/VPEM: `IDENTIFIED_IN`, con dirección invertida); renombrada | La vulnerabilidad está en esa versión de la librería |
| `DEPENDS_ON` | `(Application)-[:DEPENDS_ON]->(Library)` y `(Library)-[:DEPENDS_ON]->(Library)` | FUENTE (SBOM: `DEPENDENCY_OF`, con dirección invertida); simplifica `BuildArtifact` y `Repo` | Dependencias directas y transitivas |
| `RUNS_ON` | `(Application)-[:RUNS_ON]->(Host)` | FUENTE (VPEM: `HOSTED_ON`); renombrada | Dónde corre la aplicación |
| `CAN_REACH` | `(Host)-[:CAN_REACH {port}]->(Host)` | FUENTE (APA y página de caminos de ataque) | Movimiento lateral posible entre hosts |
| `RUNS_AS` | `(Host)-[:RUNS_AS]->(Identity)` | FUENTE (VPEM/APA) | La identidad que hereda quien compromete el host |
| `HAS_ACCESS_TO` | `(Identity)-[:HAS_ACCESS_TO]->(DataStore)` | FUENTE (VPEM/APA), simplificada: se elimina `IAMPolicy` por claridad (decisión cerrada el 27-oct-2026; puede mencionarse de palabra en la demo) | Acceso de la identidad al almacén |
| `STORES` | `(Host)-[:STORES]->(DataStore)` | PROPUESTA | Almacén alojado físicamente en un host (por ejemplo, un servidor de base de datos) |
| `SUPPORTS` | `(Application)-[:SUPPORTS]->(BusinessService)` | PROPUESTA | Servicio de negocio que depende de la aplicación |

Se omiten a propósito, respecto a las fuentes: `Endpoint` (el punto de entrada es `Host.internet_exposed`), `BuildArtifact`, `Repo`, `Team`, `IAMPolicy`, `CVE`/`CWE`/`Vendor`/`Product`/`Catalog` (no se carga NVD ni el catálogo KEV: el flag `known_exploited` basta).

## Diagrama conceptual

```
(Vulnerability) -[AFFECTS]-> (Library) <-[DEPENDS_ON]- (Library)* <-[DEPENDS_ON]- (Application) -[RUNS_ON]-> (Host)
                                                                                      │                        │
                                                                          [SUPPORTS]  ↓          [CAN_REACH]───┤ (Host)
                                                                      (BusinessService)                       │
                                                                                         [RUNS_AS]→(Identity)─[HAS_ACCESS_TO]→(DataStore)
                                                                                         [STORES]──────────────────────────────→(DataStore)
```

## Cómo lo usa cada caso de uso (resumen; las queries no están escritas)

- **Cadena de suministro / día cero:** de `Vulnerability` por `AFFECTS` y `DEPENDS_ON*` hasta `Application`, y por `RUNS_ON` hasta `Host` con `internet_exposed`.
- **Priorización:** severidad (`cvss_score`) + alcanzabilidad (`internet_exposed` o camino desde un host expuesto) + impacto (acceso a un `DataStore` crítico o `BusinessService` de criticidad alta) + `known_exploited`.
- **Caminos de ataque:** de `Host {internet_exposed: true}` por `CAN_REACH`, `RUNS_AS` y `HAS_ACCESS_TO` / `STORES` hasta `DataStore {crown_jewel: true}`; *blast radius* desde un host; puntos de estrangulamiento.
