# data/ — dataset sintético (PENDIENTE)

> **No hay datos todavía**, por instrucción de la persona (27-oct-2026). Este fichero recoge el plan. Todo el contenido futuro será **sintético y pequeño**, con sabor a banca y telecom; no representará a ningún cliente ni entorno real. No se carga NVD ni el catálogo KEV: `known_exploited` es una propiedad.

## Plan (propuesta)

Formato previsto, como `data-lineage-fs-demo`: **CSV + script `LOAD CSV`** segmentado, con `generate_dataset.py` como fuente de verdad y `validate_dataset.py` independiente del generador.

| Fichero previsto | Contenido | Orden de magnitud |
|---|---|---|
| `vulnerabilities.csv`, `libraries.csv`, `applications.csv`, `hosts.csv`, `identities.csv`, `data_stores.csv`, `business_services.csv` | Nodos (`Vulnerability`, `Library`, `Application`, `Host`, `Identity`, `DataStore`, `BusinessService`) | 15-25 / 12-15 / 8-10 / 12-15 / 4-5 / 4-5 / 4-5 |
| un CSV por relación (nombres por decidir) | `AFFECTS`, `DEPENDS_ON`, `RUNS_ON`, `CAN_REACH`, `RUNS_AS`, `HAS_ACCESS_TO`, `STORES`, `SUPPORTS` | — |
| `00_load_live.cypher`, `generate_dataset.py`, `validate_dataset.py` | Carga, generador y validador (**no se escriben aún**) | — |

## Casos que debe cubrir (criterios de aceptación)

Lista completa en `../CONTEXTO_IA.md`, «Próximos pasos», punto 2. En resumen: CVSS alto aislado frente a CVSS medio expuesto con acceso a datos críticos; dependencias transitivas con una librería compartida; camino de ataque con salto por identidad; puntos de estrangulamiento claros; un almacén crítico no alcanzable; una vulnerabilidad nueva para insertar en directo; consistencia estricta verificada por script.

## Cómo cargar

Pendiente. Se documentará cuando existan los CSV (ver `../AURA_SETUP.md`).
