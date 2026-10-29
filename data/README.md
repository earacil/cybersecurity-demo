# data/ — dataset

> **Todo el dataset es sintético, salvo un único CVE real: `CVE-2021-44228` (Log4Shell), el gancho de la historia, que va aparte y se inserta en directo.** Es pequeño, generado por script y no representa a ningún cliente ni entorno real. Los identificadores de vulnerabilidad de la carga base son ficticios (`SYN-xxxx`); no se carga NVD ni el catálogo KEV. Sabor a banca y telecomunicaciones.
>
> Estado (29-oct-2026): **CSV generados y validados** con `validate_dataset.py`. Los scripts `.cypher` están escritos pero **a validar en Aura**.

## Glosario: «activo crítico» (*crown jewel*)

Un **activo crítico** (en inglés *crown jewel*, «joya de la corona») es un almacén de datos cuya pérdida o robo sería lo más grave para la organización: datos personales de clientes, el libro de tarjetas, el registro de abonados. Es lo que un atacante quiere alcanzar y lo que el defensor quiere proteger. En el modelo es `DataStore {crown_jewel: true}`. En este dataset hay tres: `Customer PII DB`, `Card Ledger` y `Subscriber Registry`. Un camino de ataque es **peligroso** cuando termina en un activo crítico; que un servidor esté vulnerable no basta.

## Flujo de trabajo

```bash
python3 generate_dataset.py    # reescribe los CSV (fuente única de verdad)
python3 validate_dataset.py    # valida y calcula los resultados esperados, fuera de Neo4j
```

`validate_dataset.py` solo lee los CSV (es independiente del generador) y falla con código ≠ 0 si algo no cuadra. Su salida es la **referencia** con la que hay que comparar las queries en Aura. Si cambias algo en el generador, vuelve a ejecutar ambos scripts y actualiza los recuentos de `00_load_live.cypher`.

## Orden de ejecución en Aura (el orden importa)

| Orden | Fichero | Cuándo | Efecto |
|---|---|---|---|
| 1 | `00_load_live.cypher` | Antes de la demo | Carga base **sintética**, por capas: restricciones → software → infraestructura → identidad y datos → negocio. **70 nodos y 103 relaciones** |
| 2 | `01_zero_day_insert.cypher` | **En directo** | Inserta Log4Shell y su `AFFECTS`: 71 nodos y 104 relaciones |
| 3 | `02_zero_day_reset.cypher` | Para repetir el ensayo | Elimina solo `CVE-2021-44228`: vuelve a 70 y 103 |

## Ficheros

| Fichero | Contenido | Filas |
|---|---|---|
| `vulnerabilities.csv` | `Vulnerability` base (`SYN-0002` a `SYN-0018`) | 17 |
| `libraries.csv` | `Library` (clave: `name` + `version`) | 14 |
| `applications.csv` | `Application` | 9 |
| `hosts.csv` | `Host` | 15 |
| `identities.csv` | `Identity` | 5 |
| `data_stores.csv` | `DataStore` | 5 |
| `business_services.csv` | `BusinessService` | 5 |
| `affects.csv` · `lib_depends_on.csv` · `app_depends_on.csv` | `AFFECTS` · `DEPENDS_ON` (lib→lib y app→lib) | 17 · 10 · 27 |
| `runs_on.csv` · `can_reach.csv` · `runs_as.csv` · `has_access_to.csv` · `stores.csv` · `supports.csv` | resto de relaciones | 9 · 15 · 5 · 6 · 5 · 9 |
| `zero_day_vulnerability.csv` · `zero_day_affects.csv` | **El gancho `CVE-2021-44228`**, aparte a propósito | 1 · 1 |
| `generate_dataset.py` · `validate_dataset.py` | generador y validador | — |
| `00_load_live.cypher` · `01_zero_day_insert.cypher` · `02_zero_day_reset.cypher` | carga, día cero en directo y reset | — |

Claves de `MERGE`: `Vulnerability.id` · `Library (name, version)` · `Application.name` · `Host.name` · `Identity.name` · `DataStore.name` · `BusinessService.name`. Profundidad máxima de camino variable en las queries: **10**.

## El escenario

Una entidad ficticia con dos negocios, banca y telecom, y cinco servicios de negocio.

- **Zona expuesta (DMZ):** `dmz-web-01` (banca online), `dmz-api-01` (pasarela de pagos) y `dmz-portal-01` (portal de autoservicio de abonados).
- **Zona interna alcanzable desde la DMZ:** `app-pay-01`, `app-cust-01`, `app-bill-01`, sus bases de datos (`db-pay-01`, `db-bill-01`) y `mon-01` (observabilidad, recibe logs de todos).
- **Zona aislada (telecom core y gestión):** `jump-01`, `app-prov-01`, `db-sub-01` e `int-web-01`. Solo se entra por `jump-01`, al que no llega nada desde Internet. Aquí vive el activo crítico no alcanzable (`Subscriber Registry`).
- **Host de pruebas aislado:** `tst-report-01`, con la aplicación `legacy-report-tool`.
- **Detalle deliberado:** `db-cust-01` (donde vive `Customer PII DB`) no tiene ninguna entrada por red. A sus datos solo se llega **a través de una identidad**, `svc-customer-profile`, o de `svc-billing`, que está sobre-privilegiada a propósito.

## El gancho: CVE-2021-44228, Log4Shell (la historia)

**Qué es.** Una vulnerabilidad real de ejecución remota de código (CVSS 10.0, explotación masiva conocida) en `log4j-core`, una librería de logging muy extendida. Se hizo pública en diciembre de 2021 y se explotó en Internet en cuestión de horas. Lo que la hizo dramática no fue su gravedad, sino que casi nadie sabía **dónde la tenía**: la librería rara vez se usa directamente, sino enterrada como dependencia de otras. Aquí el CVE es real; el resto del entorno (librerías intermedias, aplicaciones, servidores) es sintético.

**La historia que contar.**
1. Llega el aviso: vulnerabilidad crítica en una librería de logging, ya explotada.
2. Ninguna aplicación depende de `log4j-core` directamente: dependen de `platform-commons` y de `service-kit`, que dependen de `observability-sdk`, que depende de `log4j-core`. Sin grafo, es una búsqueda manual de semanas en repositorios.
3. Se inserta el CVE en el grafo (`01_zero_day_insert.cypher`) y se pregunta qué se ve afectado.

**Lo que debe salir (calculado fuera de Neo4j):**

| Qué | Resultado |
|---|---|
| Aplicaciones afectadas | 6 de 9: `online-banking-web`, `payments-gateway`, `payments-core`, `customer-profile-service`, `provisioning-engine`, `staff-intranet` |
| Nivel de dependencia | 3 niveles (`payments-gateway`, `payments-core`) y 4 niveles (el resto) |
| Hosts expuestos afectados | 2: `dmz-web-01`, `dmz-api-01`: lo urgente |
| Afectada pero **no expuesta** | `customer-profile-service`, `payments-core`, `provisioning-engine`, `staff-intranet` |
| Servicios de negocio afectados | 4 de 5: Card Payments, Online Banking, Staff Intranet, Subscriber Provisioning |
| No afectadas | `selfcare-portal`, `billing-engine`, `legacy-report-tool` |
| Librería a arreglar primero | `log4j-core` (6 apps); por encima, `service-kit` es la que arrastra a 4 apps |
| Riesgo contextual | Log4Shell pasa a ser lo más alto: 45,0 en `dmz-web-01` y `dmz-api-01`; 37,5 en `app-cust-01` |

## Escenarios que cubre (criterios de aceptación, todos verificados por el validador)

- **Priorización:** `SYN-0002` (CVSS 9.8) en `tst-report-01`, aislado y sin acceso a datos, puntúa 9,8. `SYN-0003` (CVSS 5.0, explotada) en `dmz-web-01` y `dmz-portal-01`, expuestos y con camino a un activo crítico, puntúa 22,5. En CVSS puro `SYN-0002` es la primera; con contexto, `SYN-0003` supera a todas las demás de la carga base, con `SYN-0008` (22,0) justo detrás.
- **Caminos de ataque:** 11 caminos de entrada a activo crítico (profundidad ≤ 10). 9 terminan por identidad y 2 por red (`db-pay-01`); 7 llegan a `Customer PII DB` sin ningún camino de red hasta su host. `Subscriber Registry` no es alcanzable.
- **Blast radius distinto:** `dmz-web-01` (6 hosts, 4 identidades, 4 almacenes, 6 caminos a activos críticos) frente a `dmz-portal-01` (3 hosts, 2 identidades, 3 almacenes, 1 camino).
- **Puntos de estrangulamiento:** `app-pay-01` está en 8 de 11 caminos (73 %) y `app-cust-01` en 6 (55 %); entre las identidades, `svc-billing` en 4 de 11 (36 %).
- **What-if:** quitar `svc-billing → Customer PII DB` deja a `dmz-portal-01` sin camino a ningún activo crítico.
- **Comunidades (WCC como fallback de Louvain):** una zona principal de 9 hosts, la zona aislada de 4 (`jump-01`, `app-prov-01`, `db-sub-01`, `int-web-01`) y dos hosts sueltos (`db-cust-01`, `tst-report-01`).

## Cómo cargar

1. Sube la carpeta `data/` a un repo público y fija `baseUrl` (ver `.env.example` y `00_load_live.cypher`, PASO 0).
2. Ejecuta `00_load_live.cypher` por segmentos en el Query tool de Aura y compara la verificación con la salida de `validate_dataset.py`.
3. En directo, `01_zero_day_insert.cypher`; para repetir, `02_zero_day_reset.cypher`.
