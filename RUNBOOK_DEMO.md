# Guion de demo — plantilla genérica (1 hora) · BORRADOR

> Estado: **borrador sin comandos.** Estructura, tiempos tentativos y mensajes; no hay dataset ni queries todavía. La versión extendida (para leer durante la sesión) es `GUIA_EJECUCION.md`, local y ignorada por git. Ensayar con cronómetro cuando exista todo.
>
> Hilo conductor: *sale una vulnerabilidad nueva → ¿dónde está? (cadena de suministro) → ¿cuál importa? (priorización) → ¿hasta dónde llegaría un atacante? (caminos) → ¿dónde corto?* Bloom no es un bloque aparte: se usa dentro de priorización y caminos.

| Bloque | Duración | Contenido | Herramienta | Caso |
|---|---|---|---|---|
| Intro | 5 min | Los atacantes piensan en grafos; fatiga de vulnerabilidades; tres preguntas que cuesta contestar | — | — |
| El modelo | 7 min | 7 tipos de nodo, capas (software, infraestructura, identidad, datos, negocio); dataset sintético con sabor a banca y telecom; cómo se carga | Bloom (esquema) | — |
| Cadena de suministro y día cero | 10 min | Una vulnerabilidad nueva se inserta en directo sobre una librería profunda: aplicaciones, hosts expuestos y servicios de negocio afectados | Query tool + Bloom | 1 |
| Priorización y exposición | 13 min | CVSS frente a alcanzabilidad e impacto: por qué la «Medium» expuesta gana a la «Critical» aislada | Bloom + Query tool (+ dashboard) | 2 |
| Caminos de ataque | 16 min | Del punto de entrada a los activos críticos, *blast radius*, puntos de estrangulamiento; GDS como complemento (centralidad y comunidades) con fallback en Cypher | Bloom + Query tool (GDS) | 3 |
| Cierre | 4 min | Ingesta idempotente y periódica, informe de riesgo, sin remediación automática | — | — |
| Q&A | 5 min | — | — | — |

## Preparación (antes de la sesión) — PENDIENTE

Se detallará cuando existan los ficheros. Previsto, por analogía con `data-lineage-fs-demo`:

1. Instancia AuraDB (con Aura Graph Analytics si se muestra GDS; ver `AURA_SETUP.md`).
2. Parámetro `baseUrl` apuntando a una etiqueta o SHA del repo, no a `main`.
3. Pre-cargar el dataset base; dejar la vulnerabilidad de día cero para insertarla en directo.
4. Verificar recuentos esperados.
5. Importar la perspectiva de Bloom y los dashboards.
6. Revisar sesiones de Aura Graph Analytics olvidadas de un ensayo.

## Notas

- El dataset es sintético; dejarlo explícito al abrir la demo.
- Enfoque defensivo: se mide exposición y se cortan caminos; no se explota nada. Aclarar que son casos de postura y exposición, no detección de un ataque en curso (eso es SIEM).
- Plan B: lo que use GDS tiene fallback en Cypher puro.
- Al preparar una sesión para una organización concreta, anotar fecha, asistentes y ajustes en `CurrentFocus.md` y en el `Context.md` del cliente (no en este fichero).
