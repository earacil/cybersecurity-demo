# Contexto para IA — léeme primero

> Si eres una IA (u otra persona) que retoma este proyecto sin haber visto la conversación original, este documento te da el contexto operativo que necesitas. Los demás `.md` son la fuente de verdad del contenido; este fichero es el mapa y las reglas para moverte entre ellos.

## Misión

Construir una **demo genérica, reutilizable y lo más simple posible de ciberseguridad sobre Neo4j**, con sabor a **banca y telecomunicaciones**: un dataset sintético pequeño + queries Cypher (y GDS como complemento) + una perspectiva de Bloom que, juntos, muestren los **tres casos de uso donde Neo4j es más fuerte en ciberseguridad**: seguridad de la cadena de suministro de software (preparación ante un día cero), priorización de vulnerabilidades y gestión de exposición, y análisis de caminos de ataque. Debe poder presentarse a cualquier cliente sin modificaciones salvo una capa de personalización deliberada.

## Restricciones duras (no negociables salvo que la persona lo pida explícitamente)

1. **Cero nombres de empresas, partners o personas** en ningún fichero del proyecto (ni clientes, ni la organización ante la que se presentará la primera sesión, ni partners). La demo es completamente genérica. Si se detecta alguno, es un error a corregir. La referencia a la sesión concreta vive en `CurrentFocus.md` y, si procede, en el `Context.md` del cliente dentro de `Customers/`, apuntando aquí, nunca al revés.
2. **Idioma**: todos los identificadores del modelo (labels, tipos de relación, propiedades) van **en inglés**. La prosa de los `.md` va **en español**, salvo que la persona indique lo contrario.
3. **El dataset es y debe seguir siendo sintético y pequeño.** Nada de datos reales de ningún cliente ni entorno. Nada de cargar NVD completo: la simplicidad es un requisito.
4. **Enfoque defensivo.** Se mide exposición, se prioriza y se cortan caminos; no hay código de explotación, payloads ni procedimientos ofensivos.
5. **No copiar código ni datos de los repositorios de referencia.** Ninguno de ellos muestra licencia (ver «Fuentes»); se usan solo como inspiración de modelo y de narrativa. Las queries y el dataset se escriben desde cero.
6. ~~Solo guía y contexto.~~ **LEVANTADA el 29-oct-2026**: era una restricción inicial para montar el esqueleto. Ahora se construyen dataset, queries, Bloom y dashboards, por este orden (dataset primero).
7. **Nada está validado.** Ni el modelo, ni el guion. Todo Cypher **nuevo o modificado** se trata como «a validar» hasta que la persona lo pruebe en Aura o Desktop real (el entorno del agente no tiene Neo4j ni GDS).

## Decisiones cerradas por la persona (27-oct-2026)

- Sabor a banca y telecom.
- Lo más simple posible.
- El GraphGist de phishing se descarta (obsoleto): no hay ángulo de inteligencia de amenazas ni dominios/IP/registradores.
- Los tres casos de uso típicos y potentes de Neo4j en ciberseguridad son el núcleo, como en la demo de referencia.
- Los algoritmos GDS propuestos se quedan en la lista, ordenados por fiabilidad esperada, para analizarlos más adelante (ver abajo).
- Nombre del repo: `cybersecurity-demo`.
- Sin nodo de política de acceso (`IAMPolicy`): se mantiene solo `Identity → DataStore` por claridad. Puede mencionarse de palabra en la narrativa.
- Orden de los bloques: cadena de suministro → priorización → caminos de ataque. Se perfilará según se avance.
- Identificadores de vulnerabilidad **sintéticos** (tipo `SYN-0002`…), sin cargar NVD. **Un único CVE real como gancho: `CVE-2021-44228` (Log4Shell)**, aparte de la carga base (decidido el 29-oct-2026).
- Fórmula de riesgo: la propuesta de abajo (CVSS × alcanzabilidad × impacto × explotación conocida), con pesos provisionales que se ajustan al escribir la query.
- GDS: **un algoritmo de centralidad y uno de comunidades** (no más). Elección provisional: betweenness (centralidad) y Louvain (comunidades); a confirmar al probarlos con el dataset.
- Primera sesión prevista: una organización concreta (anotada solo en `CurrentFocus.md`). La demo sigue siendo genérica.

## Decisiones cerradas el 29-oct-2026

- Claves de `MERGE`: `Library (name, version)`, `Application.name`, `Host.name` (se elimina `Host.id`), y `name` en el resto; `Vulnerability.id`. Pensado para que las cargas sean legibles.
- Profundidad máxima de camino variable: **10**.
- Dependencias de librerías sin ciclos (lo comprueba el validador). `DataStore` se alcanza por `STORES` (red) o por `RUNS_AS` → `HAS_ACCESS_TO` (identidad); el «camino solo por identidad» es el que no tiene ruta de red hasta el host que guarda el dato.
- Gancho de la narrativa: **`CVE-2021-44228` (Log4Shell), real**, sobre `log4j-core 2.14.1`; todo lo demás es sintético, incluidas las librerías intermedias. Va en CSV aparte y se inserta en directo con `data/01_zero_day_insert.cypher`; `data/02_zero_day_reset.cypher` lo elimina para repetir la demo. La carga base (`data/00_load_live.cypher`) no lo contiene. Historia en `data/README.md`. Log4Shell es un identificador técnico, no un nombre de cliente o partner.
- Terminología: «joya» en el código es `crown_jewel`; en la prosa se dice **activo crítico** (definido en el glosario de `data/README.md`).
- Generador `data/generate_dataset.py` como fuente única de verdad; `data/validate_dataset.py` independiente; carga con `LOAD CSV` en `data/00_load_live.cypher`.
- Sin Docker: la persona ejecuta las queries en su instancia AuraDB (carga, lectura, dashboards y Bloom). Credenciales en `.env` local (ignorado por git).
- El handle de GitHub de la persona (`earacil`) puede aparecer en las URL; no cuenta como nombre de tercero.

## Hechos, supuestos y recomendaciones

**Confirmado en las fuentes** (leídas el 27-oct-2026; detalle en `data-model/NOTAS_DISENO.md`):
- Los tres casos de uso de la página de ciberseguridad de Neo4j (priorización y exposición, caminos de ataque, cadena de suministro) comparten un modelo común y tienen cada uno un repositorio de ejemplo con notebooks.
- Ni la página, ni el blog, ni ninguno de los tres repositorios usan GDS: todo es Cypher (patrones, `EXISTS`, longitud variable). Los algoritmos GDS de esta demo son **propuesta nuestra**.
- Los repositorios mezclan datos reales (CVE de NVD, catálogo KEV de CISA) con infraestructura sintética diminuta (3 apps, 3 hosts…).
- Los repositorios no tienen licencia visible.

**Supuestos míos** (a confirmar):
- Que un dataset de unas pocas decenas de nodos baste para contar bien los tres casos.
- Que el hilo conductor «sale una vulnerabilidad nueva» (ver `RUNBOOK_DEMO.md`) funcione mejor que tres bloques sueltos.

**Recomendaciones**: ver «Decisiones abiertas».

## Algoritmos GDS: selección provisional (27-29 oct 2026)

> Decisión de la persona: **uno de centralidad y uno de comunidades**. La elección concreta es **propuesta mía, sin evidencia en las fuentes** (ninguna usa GDS) y hay que probarla con el dataset. La demo debe funcionar **entera en Cypher puro**; GDS es un complemento y su fallo no puede romper la sesión. Ojo: los tres casos son de **postura y exposición** (prevenir), no de detección en vivo de un ataque (eso es SIEM).

| Papel | Algoritmo | Para qué | Cautela |
|---|---|---|---|
| **Centralidad** (elegido, provisional) | Betweenness (`gds.betweenness`) | Puntos de estrangulamiento: hosts e identidades por los que pasan más caminos | Calcula sobre todos los pares de nodos, no solo entrada→dato crítico. Se contrasta con el recuento en Cypher de caminos de entrada a activo crítico que pasan por cada nodo |
| **Comunidades** (elegido, provisional) | Louvain (`gds.louvain`) sobre los hosts conectados por `CAN_REACH` | Agrupar hosts en zonas naturales y ver qué caminos cruzan de una zona a otra: candidatos a reglas de microsegmentación | Describe cómo se agrupa la red, no el riesgo; se interpreta junto con los caminos. Alternativa más simple: WCC |
| Alternativa de centralidad | PageRank (`gds.pageRank`) sobre el grafo invertido | Criticidad de identidades y librerías compartidas | Orientativa; «qué librería comparte más aplicaciones» ya sale con un recuento en Cypher |
| Base (no GDS obligatorio) | Alcanzabilidad y caminos más cortos (`gds.bfs`, `gds.shortestPath.*` o Cypher) | *Blast radius* y camino de entrada a activo crítico | Deterministas y explicables; son la parte fiable de la demo |

## Estado exacto del proyecto ahora mismo

| Fichero/carpeta | Estado | Contenido |
|---|---|---|
| `README.md` | 🟡 borrador | Qué es, por qué un grafo, 3 ángulos, estructura, estado |
| `CONTEXTO_IA.md` | 🟡 borrador | Este fichero |
| `GUIA_EJECUCION.md` | 🟡 borrador sin queries; **local, ignorada por git** | Guion personal con mensajes por bloque. Las queries y comandos se copiarán cuando existan |
| `RUNBOOK_DEMO.md` | 🟡 borrador | Bloques y tiempos de la hora; sin comandos |
| `data-model/SCHEMA.md` | 🟡 borrador | 7 nodos y 8 relaciones propuestos (sin `IAMPolicy`, confirmado) |
| `data-model/NOTAS_DISENO.md` | 🟡 borrador | Qué aporta cada fuente, limitaciones, qué es propuesta |
| `AURA_SETUP.md` | 🟡 esqueleto | Requisitos previstos |
| `data/` | 🟢 CSV generados y validados (29-oct-2026) | 18 CSV, `generate_dataset.py`, `validate_dataset.py`, `00_load_live.cypher`, `01_zero_day_insert.cypher`, `02_zero_day_reset.cypher` (a validar en Aura) y `README.md` con la historia del gancho y los resultados esperados |
| `queries/` | ⬜ esqueletos | 3 `.cypher` con cabecera e índice, **sin sentencias** |
| `bloom/`, `dashboards/` | ⬜ vacío | Solo `README.md` |
| `.env` | 🟡 creado, sin credenciales | Plantilla a rellenar (ignorado por git) |

## Fórmula de riesgo (aceptada por la persona; pesos provisionales)

`riesgo = CVSS × alcanzabilidad × impacto × explotación`, con alcanzabilidad 1,5 si el host está expuesto a Internet, 1,25 si es alcanzable desde un host expuesto y 1,0 si está aislado; impacto 2,0 si llega a un almacén crítico y 1,0 si no; explotación 1,5 si `known_exploited` y 1,0 si no. Es una **heurística de demo, no un estándar**. Los factores 1,5 y 2,0 salen de los repositorios de referencia; el resto es nuestro. Comprobación: una «Critical» de 9,8 aislada puntúa 9,8; una «Medium» de 5,0 expuesta, con acceso a un almacén crítico y explotada, puntúa 22,5. Se ajustará al escribir la query.

## Decisiones abiertas

1. ~~**CVE real como gancho**~~ Cerrada (29-oct-2026): Log4Shell (`CVE-2021-44228`), aparte de la carga base.
2. **Dashboards**: cuántos y de qué. Se decide al tener las queries.
3. **Confirmar betweenness y Louvain** tras probarlos con el dataset (o cambiar a PageRank / WCC).
4. **Orden de los bloques**: fijado (cadena de suministro → priorización → caminos de ataque), a perfilar según se avance.

## Próximos pasos, en orden, con criterio de aceptación

### 1. Cerrar decisiones abiertas y revisar `data-model/SCHEMA.md`
Criterio: la persona confirma; `SCHEMA.md` queda sin «a decidir».

### 2. Dataset sintético (`data/`), pequeño
Orden de magnitud: unos 12-15 hosts, 8-10 aplicaciones, 12-15 librerías, 15-25 vulnerabilidades, 4-5 identidades, 4-5 almacenes de datos y 4-5 servicios de negocio. Mínimos para que los tres casos tengan algo que mostrar:
- **Priorización:** una vulnerabilidad de CVSS alto en un host aislado que quede *por debajo* de otra de CVSS medio en un host expuesto con acceso a datos críticos; al menos una marcada como explotada (`known_exploited`).
- **Caminos de ataque:** un camino de varios saltos desde un host expuesto a un almacén crítico; al menos un camino que solo exista **a través de una identidad** (no por red); 1-2 puntos de estrangulamiento claros; un almacén crítico **no alcanzable** (para enseñar qué está bien protegido); *blast radius* distinto entre dos hosts de entrada.
- **Cadena de suministro:** dependencias transitivas de 2-3 niveles; una librería compartida por varias aplicaciones; una vulnerabilidad nueva que se **inserta en directo** sobre una librería profunda y devuelve aplicaciones, hosts expuestos y servicios de negocio afectados; una aplicación afectada que **no** está expuesta.
- Consistencia estricta y un `validate_dataset.py` independiente del generador, con resultados esperados calculados fuera de Neo4j (como en `data-lineage-fs-demo`).

### 3. Queries (`queries/`)
Un fichero por caso de uso, literales cambiables marcados `← CAMBIA`, caminos acotados, y fallback en Cypher puro para lo que use GDS. Todo «a validar» hasta probarlo en Aura.

### 4. Bloom, dashboards, runbook y guía
Perspectiva exportada del Aura real (sin inventar estilos), dashboards con las queries marcadas, guion con comandos y ensayo con cronómetro.

## Mapa de ficheros

```
cybersecurity-demo/
├── CONTEXTO_IA.md          ← este fichero (léelo primero)
├── README.md               ← punto de entrada para humanos
├── GUIA_EJECUCION.md       ← guía personal (LOCAL, en .gitignore; no existe en un clon limpio)
├── RUNBOOK_DEMO.md         ← guion de la hora (plantilla pública)
├── AURA_SETUP.md           ← preparación de Aura (esqueleto)
├── .gitignore · .env.example
├── data-model/             ← SCHEMA.md (borrador) · NOTAS_DISENO.md
├── data/                   ← README.md (plan del dataset)
├── queries/                ← README.md + 01..03 .cypher (esqueletos sin sentencias)
├── bloom/                  ← README.md
└── dashboards/             ← README.md
```

## Fuentes (leídas el 27-oct-2026)

- Blog de Neo4j: *Bolster your cybersecurity by visualizing attack graphs with Neo4j & G.V()* — https://neo4j.com/blog/developer/how-to-bolster-your-cybersecurity/. Su repositorio de datos (`gdotv/neo4j_cybersecurity`) se pudo ver solo en parte: el README es de una línea y los CSV y el zip están bloqueados para lectura automática; dice ser una adaptación del dataset de KubeHound. Sin licencia visible.
- Neo4j Developer: *Cybersecurity* y sus tres subpáginas (priorización y exposición, caminos de ataque, cadena de suministro) — https://neo4j.com/developer/industry-use-cases/cybersecurity/
- Repositorios de ejemplo enlazados por esas subpáginas (organización `neo4j-field`; las URL antiguas redirigen): `cyber-vpem`, `cyber-apa`, `cyber-sbom`. Revisados README, cargadores y notebooks; en `cyber-apa` y `cyber-sbom` faltan las últimas celdas (salida de imagen en base64 que cortó la lectura). Sin licencia visible en ninguno.
- Estructura del proyecto: `../data-lineage-fs-demo/`.
- Descartado: GraphGist *Cyber security and attack analysis* (ejemplo antiguo).

## Cómo verificar que un cambio no rompe nada

1. `grep -ri` por nombres de cualquier cliente, partner u organización conocidos: debe salir limpio.
2. Si se toca `data-model/SCHEMA.md`, revisar que `RUNBOOK_DEMO.md`, `GUIA_EJECUCION.md`, `data/README.md` y `queries/README.md` sigan usando los mismos nombres de nodo y relación (se mantienen sincronizados a mano).
3. Cualquier Cypher nuevo se marca como no validado hasta ejecutarlo en una instancia real; decirlo en el propio fichero o en el mensaje de entrega.
