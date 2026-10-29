# Cybersecurity Demo — Neo4j para ciberseguridad

> Estado: **estructura, contexto y guion en borrador (27-oct-2026). Sin dataset sintético y sin Cypher todavía.** Todo lo que describe el modelo y el guion es una **propuesta a validar**.
>
> **¿Eres una IA retomando este proyecto?** Lee primero [`CONTEXTO_IA.md`](CONTEXTO_IA.md): tiene las restricciones duras, el estado exacto, las decisiones abiertas y los próximos pasos.

## Qué es esto

Demo genérica, reutilizable y simple de **ciberseguridad sobre Neo4j**, con sabor a banca y telecomunicaciones. Un *Cybersecurity Knowledge Graph* pequeño conecta datos que normalmente viven en silos (software y dependencias, vulnerabilidades, servidores, red, identidades, datos críticos y servicios de negocio) para responder tres preguntas que una vista tabular contesta mal. **Sin personalizar a ningún cliente concreto**, salvo que se indique lo contrario al prepararla para una reunión específica.

## Por qué un grafo (resumen, según las fuentes)

- **Los atacantes piensan en grafos**: un ataque es una ruta de recurso en recurso hasta un activo valioso. El defensor conoce su propio sistema mejor y, con un grafo, puede ver lo mismo que el atacante.
- **La severidad sola no basta**: una vulnerabilidad «Critical» (9.8) en un servidor de pruebas aislado puede ser menos peligrosa que una «Medium» (5.0) en un servidor de producción expuesto con acceso a datos críticos.
- **Las dependencias son recursivas**: una librería vulnerable enterrada a varios niveles solo se encuentra recorriendo el grafo de dependencias.
- **Pocos puntos concentran muchos caminos**: cortar un host, una identidad o una librería compartida puede eliminar la mayoría de las rutas de ataque.

Detalle, fuentes y limitaciones en [`data-model/NOTAS_DISENO.md`](data-model/NOTAS_DISENO.md).

## Los 3 casos de uso de la demo (propuesta)

Cada uno se corresponde con un fichero de `queries/`, no con una entidad del modelo. Hilo conductor: *sale una vulnerabilidad nueva → dónde está → cuál importa → hasta dónde llegaría un atacante → dónde corto*.

1. **Cadena de suministro y preparación ante un día cero** — qué aplicaciones y servidores contienen una librería vulnerable, aunque esté a varios niveles de dependencia. → `queries/01_supply_chain_zero_day.cypher`
2. **Priorización de vulnerabilidades y gestión de exposición** — severidad técnica + alcanzabilidad + impacto de negocio = riesgo real. → `queries/02_vulnerability_prioritization.cypher`
3. **Análisis de caminos de ataque** — de los puntos de entrada expuestos a los activos críticos, *blast radius* y puntos de estrangulamiento, con GDS como complemento. → `queries/03_attack_paths_gds.cypher`

Además: **Bloom** (visualización, usada dentro de los casos 2 y 3) y un **cierre corto de productivización** (ingesta idempotente, cargas periódicas de SBOM y vulnerabilidades, informe de riesgo; sin remediación automática). Ver `RUNBOOK_DEMO.md`.

## Estructura del proyecto

```
cybersecurity-demo/
├── README.md                     ← este fichero
├── CONTEXTO_IA.md                 ← léelo primero si eres una IA: reglas, estado, decisiones abiertas, próximos pasos
├── GUIA_EJECUCION.md              ← guía personal con los mensajes de cada bloque (LOCAL, ignorada por git)
├── RUNBOOK_DEMO.md                ← guion de la hora, con timing (plantilla pública)
├── AURA_SETUP.md                  ← esqueleto: preparar Aura (carga desde GitHub y Aura Graph Analytics)
├── .gitignore                     ← excluye credenciales y artefactos locales; los CSV/.cypher/.json SÍ se versionan
├── .env.example                   ← plantilla de variables sin secretos
├── data-model/
│   ├── SCHEMA.md                  ← borrador: 7 nodos y 8 relaciones
│   └── NOTAS_DISENO.md            ← qué dice cada fuente, qué es propuesta, limitaciones
├── data/                          ← (vacío) dataset sintético pequeño; ver data/README.md
├── queries/                       ← esqueletos .cypher por caso de uso (solo cabeceras); ver queries/README.md
├── dashboards/                    ← (vacío) exports de Aura Dashboards
└── bloom/                         ← (vacío) perspectiva de Bloom
```

## Estado actual / próximos pasos

- [x] Estructura de carpetas creada (misma que `data-lineage-fs-demo`)
- [x] Fuentes revisadas (páginas de Neo4j, blog y repositorios de ejemplo)
- [x] Contexto IA, README, modelo simplificado, notas de diseño, runbook y guía en borrador
- [ ] Cerrar las decisiones abiertas de `CONTEXTO_IA.md`
- [ ] Generar el dataset sintético pequeño (CSV + generador + validador + carga)
- [ ] Escribir las queries de los 3 casos y validarlas en Aura
- [ ] Probar los dos algoritmos GDS elegidos (centralidad y comunidades) con el dataset
- [ ] Perspectiva de Bloom y dashboards
- [ ] Completar guion y guía con comandos y ensayar con cronómetro

## Uso con un cliente concreto

Esta carpeta se mantiene **sin nombre de cliente ni de partner**. Si se usa para preparar una reunión con una organización específica, la referencia a esa preparación (fecha, asistentes, contexto) debe vivir en `CurrentFocus.md` y en el `Context.md` del cliente dentro de `Customers/`, apuntando aquí, no al revés.
