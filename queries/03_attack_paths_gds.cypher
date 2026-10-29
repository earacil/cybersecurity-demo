// =====================================================================================
// 03_attack_paths_gds.cypher — Caso 3 · Análisis de caminos de ataque
// Demo de ciberseguridad con Neo4j · ESQUELETO
//
// ESTADO: SIN SENTENCIAS. Por instrucción de la persona (27-oct-2026) no se construye Cypher todavía.
//         Todo Cypher que se añada aquí es "a validar" hasta probarse en Aura (ver CONTEXTO_IA.md, restricción 7).
//
// PRERREQUISITO (futuro): dataset cargado desde data/.
//
// ÍNDICE PREVISTO
//   1. Caminos de hosts expuestos a almacenes críticos (acotados), incluido un salto por identidad
//   2. Blast radius de un host
//   3. Almacenes críticos no alcanzables
//   4. Puntos de estrangulamiento: recuento de caminos por nodo (Cypher)
//   5. GDS (a validar; ver CONTEXTO_IA.md): centralidad (betweenness, provisional) y comunidades (Louvain sobre CAN_REACH, provisional)
//   6. Fallback en Cypher puro si GDS no está disponible
// =====================================================================================
