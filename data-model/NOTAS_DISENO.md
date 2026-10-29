# Notas de diseño — conocimiento del proyecto

> Fuentes leídas el 27-oct-2026. Separa lo que dicen las fuentes de lo que es propuesta propia. Todo lo propio está sin validar.

## Qué es real y qué es sintético

- **De las fuentes**: el vocabulario (recurso, ataque, activo crítico, camino), los tres casos de uso, el modelo común que comparten (vulnerabilidad → librería → aplicación → host → identidad → datos) y la idea de puntuar el riesgo con contexto.
- **Sintético, diseñado para esta demo**: todo el dataset (activos, aplicaciones, librerías, vulnerabilidades, identidades, almacenes y servicios de negocio, con sabor a banca y telecom). No representa el entorno de ningún cliente.
- Debe quedar explícito en cualquier presentación: «un dataset de ejemplo de ciberseguridad», no acceso a datos reales.

## Qué aporta cada fuente

### Neo4j Developer — «Cybersecurity» y sus tres subpáginas
Todas son páginas de tipo solución: describen el concepto y enlazan un repositorio con la implementación. **Ninguna contiene Cypher ni nombra algoritmos GDS.**

- **Priorización y exposición (VPEM)**: critica el CVSS como puntuación estática y sin contexto. La alcanzabilidad rebaja el riesgo si el servidor no tiene IP pública ni ruta desde un punto externo; el *blast radius* lo escala si la aplicación llega, por identidad y permisos, a servicios sensibles; se prioriza por riesgo agregado y por explotación en el mundo real (catálogo KEV de CISA). Sugiere crear tickets solo para vulnerabilidades con un camino verificado a activos críticos.
- **Caminos de ataque (APA)**: añade `CAN_REACH` (movimiento lateral entre hosts), `RUNS_AS` (qué permisos hereda el atacante) y `HAS_ACCESS_TO` (último salto hasta el servicio cloud). Define punto de estrangulamiento («un servidor o identidad que es pasarela de varios caminos») y *blast radius*; sugiere microsegmentación y respuesta automática. Dice que se resuelve con «algoritmos de grafos» sin nombrar ninguno.
- **Cadena de suministro (SBOM)**: `DEPENDENCY_OF` recursiva, `BUILT_FROM` y `RUNNING_AS`; menciona CycloneDX y SPDX en una sola frase y el caso Log4j («de semanas a segundos»); habla de una «librería chokepoint» cuya actualización resuelve el riesgo de muchas apps.

### Repositorios de ejemplo (`cyber-vpem`, `cyber-apa`, `cyber-sbom`)
- **Un solo grafo compartido**: `cyber-apa` y `cyber-sbom` extienden el grafo de `cyber-vpem`. Es la razón de que los tres casos se puedan contar sobre el mismo dataset pequeño.
- **Datos**: CVE reales de NVD (más de 323.000 ficheros candidatos entre 2000 y 2025) y KEV real, más una infraestructura sintética diminuta (3 aplicaciones, 3 hosts, 1 identidad, 1 bucket). Para esta demo se descarta cargar NVD.
- **Puntuación de riesgo de `cyber-vpem`**: CVSS × 1,5 si hay IP pública × 2,0 si hay acceso a un servicio cloud; máximo 30; sin normalizar. El flag KEV se carga pero no entra en la fórmula.
- **Sin GDS**: todo es Cypher (patrones, `EXISTS`, `OPTIONAL MATCH`, longitud variable acotada a 3 saltos en SBOM) y `networkx` solo para dibujar.
- **Defectos a no heredar**: la query de día cero de `cyber-sbom` se detiene en `Application` y no llega al host ni a la exposición a Internet, aunque el texto promete «todos los servidores»; el cargador de `cyber-apa` hace `MATCH` de hosts que pueden no existir y deja de crear las aristas en silencio; la query de `cyber-sbom` no filtra por la librería que pregunta el texto.
- **Licencia**: ninguno de los tres muestra licencia, así que **no se copia código ni datos**.
- **Lectura incompleta**: las últimas celdas de `apa.ipynb` y `sbom.ipynb` no se pudieron leer (la salida base64 de una imagen cortó la descarga). Es ahí donde puede estar el cálculo de puntos de estrangulamiento.

### Blog — «Bolster your cybersecurity by visualizing attack graphs with Neo4j & G.V()»
- Autora: Amber Lennox. Publicado el 26-sep-2025.
- **Tesis**: los atacantes ven el sistema como un grafo; el defensor, que conoce mejor el suyo, debe adoptar esa vista; cortar unos pocos recursos compartidos elimina la mayoría de los caminos.
- **Modelo**: descripción de KubeHound de un clúster Kubernetes, muy simplificada. Para esta demo se usa solo el vocabulario y la idea del activo crítico, no el modelo de Kubernetes.
- **Consultas**: cuatro patrones de camino de longitud variable. Los fragmentos tienen comillas y flechas tipográficas y no se pueden ejecutar tal cual.
- **Dataset** (`gdotv/neo4j_cybersecurity`): README de una línea; los CSV y el zip (33 KB) no se pudieron revisar porque la lectura automática está bloqueada. Dice ser una adaptación del dataset de KubeHound (Datadog). Sin licencia visible.

### Descartado
- **GraphGist «Cyber security and attack analysis»**: ejemplo antiguo y pequeño de investigación de phishing por infraestructura compartida. Se excluye por decisión de la persona (27-oct-2026); con él desaparecen los nodos de dominio, IP y registrador.

## Decisiones de diseño tomadas hasta ahora

- **Misma estructura de proyecto que `data-lineage-fs-demo`**, por petición de la persona.
- **Tres casos de uso como ángulos**, organizados por pregunta de negocio y no por tipo de nodo.
- **Un único grafo pequeño** para los tres casos (7 nodos, 8 relaciones), con sabor a banca y telecom.
- **Cypher puro como base; GDS como complemento** y con fallback.
- **Identificadores en inglés, prosa en español.**
- **Nada de datos ni Cypher todavía.**

## Antes de usar esta demo con un cliente concreto

- Personalizar nombres de aplicaciones, servicios y herramientas del cliente (scanner, CMDB, repositorio de SBOM, SIEM) en una copia o capa aparte.
- Confirmar qué fuentes de datos existen de verdad (inventario, scanner de vulnerabilidades, IAM, reglas de red, SBOM) antes de asumir que el dataset encaja.
- Validar todo el Cypher y los algoritmos GDS en un entorno real (Aura) antes de cualquier demo en vivo.
- Revisar que ningún nombre, cifra o captura de un cliente real se haya colado en el dataset.
