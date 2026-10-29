# Preparar la demo en Aura — ESQUELETO

> Estado: **esqueleto.** Nada de esto está probado para este proyecto. Se completará al cerrar el dataset y las queries. Mientras tanto, la referencia validada es [`../data-lineage-fs-demo/AURA_SETUP.md`](../data-lineage-fs-demo/AURA_SETUP.md); los límites por plan (tamaño, TTL, nº de sesiones) cambian, así que hay que confirmarlos en la consola de Aura antes de cada demo.

## Previsto

- **Instancia AuraDB** de Neo4j 5 o superior. Si se usan caminos cuantificados (como en el blog de referencia), confirmar la versión mínima.
- **Aura Graph Analytics (GDS serverless)** si el caso 3 usa algoritmos (la elección de algoritmos está abierta; la demo debe funcionar entera en Cypher puro). Sesión implícita, sin credenciales de la Aura API, como en la demo de referencia. Las sesiones se facturan por minuto.
- **Carga de CSV desde GitHub**: parámetro `baseUrl` con la ruta base (con `/` final), ver `.env.example`. Supone un repo público `earacil/cybersecurity-demo` (nombre confirmado el 27-oct-2026) que **todavía no está creado**.
- **Parámetros del Query tool**: solo `baseUrl`; se pierden al refrescar la página.
- **Credenciales**: nunca en el repo; solo `.env` local (ignorado por git).

## Pendiente de redactar

1. Requisitos exactos y activación de Aura Graph Analytics.
2. Flujo de carga por segmentos.
3. Memoria de las proyecciones GDS.
4. Problemas típicos y plan B si GDS no está disponible (fallback en Cypher puro).
