#!/usr/bin/env python3
"""
Valida los CSV de esta carpeta de forma INDEPENDIENTE al generador (solo lee CSV) y calcula, fuera de
Neo4j, los resultados esperados que luego deben coincidir con las queries en Aura.

Comprueba:
  1. Unicidad de claves y enumeraciones válidas.
  2. Integridad referencial (ninguna relación apunta a un nodo inexistente).
  3. Dependencias sin ciclos; CAN_REACH sin autobucles.
  4. Criterios de aceptación (ver ../CONTEXTO_IA.md, «Próximos pasos», punto 2).
  5. Recuentos de nodos y relaciones y resultados esperados de las queries (se imprimen).

Uso:  python3 validate_dataset.py      (código de salida != 0 si algo falla)

Definiciones usadas para el cálculo esperado (las mismas que deben usar las queries):
  · Profundidad máxima de camino variable: MAX_DEPTH = 10.
  · Alcanzabilidad del host: 1.5 si internet_exposed; 1.25 si es alcanzable por CAN_REACH desde un host
    expuesto (1..MAX_DEPTH saltos); 1.0 si no.
  · Impacto del host: 2.0 si, desde ese host, se llega a un activo crítico (crown_jewel = true) por CAN_REACH*0..MAX_DEPTH
    seguido de STORES o de RUNS_AS -> HAS_ACCESS_TO; 1.0 si no.
  · Explotación: 1.5 si known_exploited; 1.0 si no.
  · riesgo = cvss_score x alcanzabilidad x impacto x explotación   (heurística de demo, no un estándar)
"""
import csv
import sys
from collections import defaultdict, deque
from pathlib import Path

D = Path(__file__).parent
MAX_DEPTH = 10
ZERO_ID = "CVE-2021-44228"  # el gancho (Log4Shell); no debe estar en la carga base
errors = []


def rd(name):
    with open(D / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def check(cond, msg):
    if not cond:
        errors.append(msg)


def truthy(v):
    check(v in ("true", "false"), f"booleano inválido: {v!r}")
    return v == "true"


# ---------------------------------------------------------------------------------------
# Carga
# ---------------------------------------------------------------------------------------
vulns, libs, apps = rd("vulnerabilities.csv"), rd("libraries.csv"), rd("applications.csv")
hosts, idents, stores = rd("hosts.csv"), rd("identities.csv"), rd("data_stores.csv")
services = rd("business_services.csv")
affects, lib_deps, app_deps = rd("affects.csv"), rd("lib_depends_on.csv"), rd("app_depends_on.csv")
runs_on, supports, can_reach = rd("runs_on.csv"), rd("supports.csv"), rd("can_reach.csv")
runs_as, has_access, stores_rel = rd("runs_as.csv"), rd("has_access_to.csv"), rd("stores.csv")
zd_vuln, zd_affects = rd("zero_day_vulnerability.csv"), rd("zero_day_affects.csv")

# ---------------------------------------------------------------------------------------
# 1. Claves únicas y enumeraciones
# ---------------------------------------------------------------------------------------
for label, rows, keyf in [
    ("vulnerabilities.id", vulns, lambda r: r["id"]),
    ("libraries (name,version)", libs, lambda r: (r["name"], r["version"])),
    ("applications.name", apps, lambda r: r["name"]),
    ("hosts.name", hosts, lambda r: r["name"]),
    ("identities.name", idents, lambda r: r["name"]),
    ("data_stores.name", stores, lambda r: r["name"]),
    ("business_services.name", services, lambda r: r["name"]),
]:
    vals = [keyf(r) for r in rows]
    check(len(vals) == len(set(vals)), f"{label}: duplicados")

V = {v["id"]: v for v in vulns}
L = {(l["name"], l["version"]) for l in libs}
A = {a["name"]: a for a in apps}
H = {h["name"]: h for h in hosts}
I = {i["name"]: i for i in idents}
S = {s["name"]: s for s in stores}
B = {s["name"]: s for s in services}

check(len({l["name"] for l in libs}) == len(libs), "libraries: se espera una versión por nombre en este dataset")
for a in apps:
    check(a["tier"] in {"P0", "P1", "P2", "P3"}, f"tier inválido: {a['name']}")
for h in hosts:
    check(h["environment"] in {"Production", "Test"}, f"environment inválido: {h['name']}")
    truthy(h["internet_exposed"])
for i in idents:
    check(i["type"] in {"ServiceAccount", "Role", "User"}, f"type inválido: {i['name']}")
for s in stores:
    check(s["data_class"] in {"PII", "Financial", "Subscriber", "Operational"}, f"data_class inválida: {s['name']}")
    truthy(s["crown_jewel"])
for s in services:
    check(s["criticality"] in {"High", "Medium", "Low"}, f"criticality inválida: {s['name']}")
for v in vulns + zd_vuln:
    try:
        c = float(v["cvss_score"])
        check(0.0 <= c <= 10.0, f"cvss fuera de rango: {v['id']}")
    except ValueError:
        errors.append(f"cvss no numérico: {v['id']}")
    truthy(v["known_exploited"])
for r in can_reach:
    check(r["port"].isdigit(), f"puerto inválido: {r}")

# ---------------------------------------------------------------------------------------
# 2. Integridad referencial
# ---------------------------------------------------------------------------------------
lk = lambda n, v: (n, v)
for r in affects + zd_affects:
    check(r["vulnerability_id"] in V or r in zd_affects, f"affects: vulnerabilidad inexistente {r}")
    check(lk(r["library_name"], r["library_version"]) in L, f"affects: librería inexistente {r}")
for r in zd_affects:
    check(r["vulnerability_id"] in {v["id"] for v in zd_vuln}, f"zero_day_affects: id inexistente {r}")
for r in lib_deps:
    check(lk(r["from_name"], r["from_version"]) in L and lk(r["to_name"], r["to_version"]) in L,
          f"lib_depends_on: librería inexistente {r}")
for r in app_deps:
    check(r["application"] in A and lk(r["library_name"], r["library_version"]) in L, f"app_depends_on: {r}")
for r in runs_on:
    check(r["application"] in A and r["host"] in H, f"runs_on: {r}")
for r in supports:
    check(r["application"] in A and r["business_service"] in B, f"supports: {r}")
for r in can_reach:
    check(r["from_host"] in H and r["to_host"] in H, f"can_reach: {r}")
    check(r["from_host"] != r["to_host"], f"can_reach: autobucle {r}")
for r in runs_as:
    check(r["host"] in H and r["identity"] in I, f"runs_as: {r}")
for r in has_access:
    check(r["identity"] in I and r["data_store"] in S, f"has_access_to: {r}")
for r in stores_rel:
    check(r["host"] in H and r["data_store"] in S, f"stores: {r}")

# Cada relación sin duplicados
for label, rows in [("affects", affects), ("lib_depends_on", lib_deps), ("app_depends_on", app_deps),
                    ("runs_on", runs_on), ("supports", supports), ("can_reach", can_reach),
                    ("runs_as", runs_as), ("has_access_to", has_access), ("stores", stores_rel)]:
    keys = [tuple(r.values()) for r in rows]
    check(len(keys) == len(set(keys)), f"{label}: filas duplicadas")

# Base sin el gancho
check(ZERO_ID not in V, "el gancho CVE-2021-44228 NO debe estar en vulnerabilities.csv (se inserta en directo)")
check(len(zd_vuln) == 1 and zd_vuln[0]["id"] == ZERO_ID, "zero_day_vulnerability.csv debe tener CVE-2021-44228")

# ---------------------------------------------------------------------------------------
# Estructuras derivadas
# ---------------------------------------------------------------------------------------
lib_out = defaultdict(set)  # (name,version) -> {(name,version)}
for r in lib_deps:
    lib_out[(r["from_name"], r["from_version"])].add((r["to_name"], r["to_version"]))
app_libs = defaultdict(set)
for r in app_deps:
    app_libs[r["application"]].add((r["library_name"], r["library_version"]))

# 3. Ciclos en DEPENDS_ON entre librerías
state = {}


def has_cycle(n):
    state[n] = 1
    for m in lib_out[n]:
        if state.get(m) == 1 or (state.get(m) is None and has_cycle(m)):
            return True
    state[n] = 2
    return False


check(not any(state.get(l) is None and has_cycle(l) for l in list(L)), "ciclo en DEPENDS_ON entre librerías")


def lib_closure(libset):
    """Librerías alcanzables (incluidas) y profundidad mínima desde el conjunto inicial."""
    depth = {l: 1 for l in libset}  # 1 = dependencia directa de la aplicación
    q = deque(libset)
    while q:
        n = q.popleft()
        for m in lib_out[n]:
            if m not in depth:
                depth[m] = depth[n] + 1
                q.append(m)
    return depth


app_closure = {a: lib_closure(app_libs[a]) for a in A}
app_host = {r["application"]: r["host"] for r in runs_on}
host_apps = defaultdict(list)
for a, h in app_host.items():
    host_apps[h].append(a)

exposed = {h for h, r in H.items() if r["internet_exposed"] == "true"}
adj = defaultdict(list)
for r in can_reach:
    adj[r["from_host"]].append(r["to_host"])
host_identities = defaultdict(list)
for r in runs_as:
    host_identities[r["host"]].append(r["identity"])
ident_stores = defaultdict(list)
for r in has_access:
    ident_stores[r["identity"]].append(r["data_store"])
host_stores = defaultdict(list)
for r in stores_rel:
    host_stores[r["host"]].append(r["data_store"])
crown = {n for n, s in S.items() if s["crown_jewel"] == "true"}


def hosts_reachable(start, include_self=True):
    """BFS por CAN_REACH hasta MAX_DEPTH saltos."""
    seen = {start: 0}
    q = deque([start])
    while q:
        n = q.popleft()
        if seen[n] == MAX_DEPTH:
            continue
        for m in adj[n]:
            if m not in seen:
                seen[m] = seen[n] + 1
                q.append(m)
    return set(seen) if include_self else set(seen) - {start}


def blast(start):
    """Hosts, identidades y almacenes que alcanza un atacante que compromete `start`."""
    hs = hosts_reachable(start)
    ids = {i for h in hs for i in host_identities[h]}
    ds = {d for h in hs for d in host_stores[h]} | {d for i in ids for d in ident_stores[i]}
    return hs - {start}, ids, ds


reach_from_exposed = set()
for e in exposed:
    reach_from_exposed |= hosts_reachable(e, include_self=False)


def reach_factor(h):
    if h in exposed:
        return 1.5
    return 1.25 if h in reach_from_exposed else 1.0


def impact_factor(h):
    return 2.0 if blast(h)[2] & crown else 1.0


def risk_rows(vuln_rows, affect_rows):
    """(vuln, host) -> detalle de riesgo. Una fila por pareja vulnerabilidad-host."""
    by_lib = defaultdict(list)
    for r in affect_rows:
        by_lib[(r["library_name"], r["library_version"])].append(r["vulnerability_id"])
    vinfo = {v["id"]: v for v in vuln_rows}
    out = {}
    for a, closure in app_closure.items():
        h = app_host[a]
        for lb in closure:
            for vid in by_lib.get(lb, []):
                v = vinfo[vid]
                cvss = float(v["cvss_score"])
                rf, imp = reach_factor(h), impact_factor(h)
                ex = 1.5 if v["known_exploited"] == "true" else 1.0
                out[(vid, h)] = dict(vuln=vid, host=h, app=a, cvss=cvss, reach=rf, impact=imp, exploit=ex,
                                     risk=round(cvss * rf * imp * ex, 2))
    return out


base_risk = risk_rows(vulns, affects)
all_risk = risk_rows(vulns + zd_vuln, affects + zd_affects)

# ---------------------------------------------------------------------------------------
# Caminos de ataque: entrada expuesta -> activo crítico (crown jewel) (caminos simples, hasta MAX_DEPTH saltos)
# ---------------------------------------------------------------------------------------
paths = []  # (entry, [hosts], identity|None, datastore, route)


def dfs(entry, node, visited, trail):
    for d in host_stores[node]:
        if d in crown:
            paths.append((entry, trail, None, d, "network"))
    for i in host_identities[node]:
        for d in ident_stores[i]:
            if d in crown:
                paths.append((entry, trail, i, d, "identity"))
    if len(trail) - 1 >= MAX_DEPTH:
        return
    for m in adj[node]:
        if m not in visited:
            dfs(entry, m, visited | {m}, trail + [m])


for e in sorted(exposed):
    dfs(e, e, {e}, [e])

# ---------------------------------------------------------------------------------------
# 4. Criterios de aceptación
# ---------------------------------------------------------------------------------------
n_vuln_total = len(vulns) + len(zd_vuln)
check(12 <= len(hosts) <= 15, f"hosts fuera de rango: {len(hosts)}")
check(8 <= len(apps) <= 10, f"aplicaciones fuera de rango: {len(apps)}")
check(12 <= len(libs) <= 15, f"librerías fuera de rango: {len(libs)}")
check(15 <= n_vuln_total <= 25, f"vulnerabilidades fuera de rango: {n_vuln_total}")
check(4 <= len(idents) <= 5, f"identidades fuera de rango: {len(idents)}")
check(4 <= len(stores) <= 5, f"almacenes fuera de rango: {len(stores)}")
check(4 <= len(services) <= 5, f"servicios fuera de rango: {len(services)}")

# Priorización: CVSS alto aislado < CVSS medio expuesto con acceso a un activo crítico (y explotado)
contrast_hi = [r for r in base_risk.values() if r["cvss"] >= 9.0 and r["reach"] == 1.0 and r["impact"] == 1.0]
contrast_lo = [r for r in base_risk.values()
               if r["cvss"] <= 5.5 and r["reach"] == 1.5 and r["impact"] == 2.0 and r["exploit"] == 1.5]
check(bool(contrast_hi) and bool(contrast_lo), "falta el contraste de priorización (Critical aislada vs Medium expuesta)")
if contrast_hi and contrast_lo:
    check(max(r["risk"] for r in contrast_lo) > max(r["risk"] for r in contrast_hi),
          "el contraste no se cumple: la Medium expuesta debe puntuar más que la Critical aislada")
check(any(v["known_exploited"] == "true" for v in vulns), "ninguna vulnerabilidad base marcada como explotada")

# Caminos de ataque
check(any(len(p[1]) >= 3 for p in paths), "no hay ningún camino de 3+ hosts desde un host expuesto a un activo crítico")
node_hosts = {d: {h for h in H if d in host_stores[h]} for d in S}
identity_only = [p for p in paths if p[4] == "identity"
                 and not any(h in hosts_reachable(p[0]) for h in node_hosts[p[3]])]
check(bool(identity_only), "falta un camino que solo exista a través de una identidad")
reached_crowns = {p[3] for p in paths}
unreachable = sorted(crown - reached_crowns)
check(bool(unreachable), "falta un activo crítico no alcanzable desde ningún host expuesto")
blast_sizes = {e: tuple(len(x) for x in blast(e)) for e in sorted(exposed)}
check(len(set(blast_sizes.values())) > 1, "el blast radius debería diferir entre hosts de entrada")

# Cadena de suministro
max_depth = max((d for c in app_closure.values() for d in c.values()), default=0)
check(max_depth >= 3, "faltan dependencias transitivas de 3+ niveles")
dependents = defaultdict(set)
for a, c in app_closure.items():
    for lb in c:
        dependents[lb].add(a)
check(any(len(s) >= 3 for s in dependents.values()), "falta una librería compartida por 3+ aplicaciones")

zd_lib = (zd_affects[0]["library_name"], zd_affects[0]["library_version"])
zd_apps = sorted(a for a, c in app_closure.items() if zd_lib in c)
zd_hosts = sorted({app_host[a] for a in zd_apps})
zd_exposed = [h for h in zd_hosts if h in exposed]
zd_not_exposed_apps = [a for a in zd_apps if app_host[a] not in exposed]
zd_services = sorted({r["business_service"] for r in supports if r["application"] in zd_apps})
check(max(app_closure[a][zd_lib] for a in zd_apps) >= 3, "la librería del día cero debe estar a 3+ niveles de alguna app")
check(bool(zd_exposed), "el día cero debe alcanzar al menos un host expuesto")
check(bool(zd_not_exposed_apps), "debe haber una aplicación afectada por el día cero que NO esté expuesta")
check(len(zd_apps) < len(A), "el día cero debería dejar alguna aplicación sin afectar")

# Cada app tiene host; cada host de aplicación existe; ninguna librería huérfana
check(set(app_host) == set(A), "toda aplicación debe tener exactamente un RUNS_ON")
used_libs = {lb for c in app_closure.values() for lb in c}
check(used_libs == L, f"librerías sin ninguna aplicación que dependa de ellas: {sorted(L - used_libs)}")

# ---------------------------------------------------------------------------------------
# Salida
# ---------------------------------------------------------------------------------------
if errors:
    print("ERRORES:")
    for e in errors:
        print("  ✗", e)
    sys.exit(1)

print("✓ Dataset válido.\n")

print("=== RECUENTOS ESPERADOS TRAS LA CARGA BASE (sin CVE-2021-44228) ===")
for label, n in [("Vulnerability", len(vulns)), ("Library", len(libs)), ("Application", len(apps)),
                 ("Host", len(hosts)), ("Identity", len(idents)), ("DataStore", len(stores)),
                 ("BusinessService", len(services))]:
    print(f"  (:{label})".ljust(24), n)
print(f"  total nodos".ljust(24), len(vulns) + len(libs) + len(apps) + len(hosts) + len(idents) + len(stores) + len(services))
n_dep = len(lib_deps) + len(app_deps)
for label, n in [("AFFECTS", len(affects)), ("DEPENDS_ON", n_dep), ("RUNS_ON", len(runs_on)),
                 ("CAN_REACH", len(can_reach)), ("RUNS_AS", len(runs_as)),
                 ("HAS_ACCESS_TO", len(has_access)), ("STORES", len(stores_rel)), ("SUPPORTS", len(supports))]:
    print(f"  [:{label}]".ljust(24), n)
print(f"  total relaciones".ljust(24), len(affects) + n_dep + len(runs_on) + len(can_reach) + len(runs_as)
      + len(has_access) + len(stores_rel) + len(supports))
print(f"  (DEPENDS_ON: {len(app_deps)} app->lib + {len(lib_deps)} lib->lib)")

print("\n=== DÍA CERO CVE-2021-44228 (tras insertarlo) ===")
print(f"  librería afectada: {zd_lib[0]} {zd_lib[1]}")
print(f"  aplicaciones afectadas ({len(zd_apps)}/{len(A)}): {', '.join(zd_apps)}")
for a in zd_apps:
    print(f"      {a:26s} nivel {app_closure[a][zd_lib]}  host {app_host[a]:14s} expuesto={app_host[a] in exposed}")
print(f"  hosts afectados ({len(zd_hosts)}): {', '.join(zd_hosts)}")
print(f"  hosts EXPUESTOS afectados ({len(zd_exposed)}): {', '.join(zd_exposed)}")
print(f"  apps afectadas NO expuestas: {', '.join(zd_not_exposed_apps)}")
print(f"  servicios de negocio afectados ({len(zd_services)}/{len(B)}): {', '.join(zd_services)}")
print(f"  apps NO afectadas: {', '.join(sorted(set(A) - set(zd_apps)))}")

print("\n=== LIBRERÍAS COMPARTIDAS (nº de aplicaciones que dependen, directa o transitivamente) ===")
for lb, s in sorted(dependents.items(), key=lambda x: (-len(x[1]), x[0])):
    print(f"  {lb[0]:18s} {lb[1]:7s} {len(s)} apps")

print("\n=== PRIORIZACIÓN (carga base, sin CVE-2021-44228): por CVSS vs por riesgo contextual ===")
print("  Por CVSS (una fila por vulnerabilidad):")
for v in sorted(vulns, key=lambda v: -float(v["cvss_score"]))[:6]:
    print(f"    {v['id']}  {v['cvss_score']:>4s}  exploited={v['known_exploited']}")
print("  Por riesgo contextual (vulnerabilidad, host) — top 12:")
print(f"    {'vuln':15s} {'host':14s} {'cvss':>5s} {'reach':>5s} {'imp':>4s} {'expl':>4s} {'riesgo':>7s}")
for r in sorted(base_risk.values(), key=lambda r: (-r["risk"], r["vuln"], r["host"]))[:12]:
    print(f"    {r['vuln']:15s} {r['host']:14s} {r['cvss']:5.1f} {r['reach']:5.2f} {r['impact']:4.1f} {r['exploit']:4.1f} {r['risk']:7.2f}")
print("  Contraste pedagógico:")
for r in sorted(contrast_hi, key=lambda r: -r["risk"])[:2]:
    print(f"    Critical aislada: {r['vuln']} en {r['host']}  cvss {r['cvss']} -> riesgo {r['risk']}")
for r in sorted(contrast_lo, key=lambda r: -r["risk"])[:2]:
    print(f"    Medium expuesta : {r['vuln']} en {r['host']}  cvss {r['cvss']} -> riesgo {r['risk']}")
top_all = sorted(all_risk.values(), key=lambda r: (-r["risk"], r["vuln"], r["host"]))[:3]
print("  Con CVE-2021-44228 insertado, top 3: " + "; ".join(f"{r['vuln']}@{r['host']}={r['risk']}" for r in top_all))

print("\n=== CAMINOS DE ATAQUE (desde hosts expuestos hasta activos críticos; profundidad ≤ 10) ===")
print(f"  activos críticos (crown jewels): {', '.join(sorted(crown))}")
print(f"  activos críticos NO alcanzables desde ningún host expuesto: {', '.join(unreachable)}")
print(f"  caminos totales entrada->activo crítico: {len(paths)}")
by_entry = defaultdict(int)
for p in paths:
    by_entry[p[0]] += 1
for e in sorted(exposed):
    hs, ids, ds = blast(e)
    print(f"  blast radius {e:14s}: {len(hs)} hosts, {len(ids)} identidades, {len(ds)} almacenes "
          f"({len(ds & crown)} críticos) · {by_entry[e]} caminos a activos críticos")
print("  Caminos solo por identidad (el host que guarda el dato no es alcanzable por red):")
for p in identity_only[:6]:
    print("    " + " -> ".join(p[1]) + f" -[RUNS_AS]-> {p[2]} -[HAS_ACCESS_TO]-> {p[3]}")

print("\n  Puntos de estrangulamiento: nº de caminos entrada->activo crítico que pasan por cada nodo")
cnt = defaultdict(int)
for e, hs, i, d, route in paths:
    for n in set(hs[1:]):  # sin contar el host de entrada
        cnt[("Host", n)] += 1
    if i:
        cnt[("Identity", i)] += 1
for (kind, n), c in sorted(cnt.items(), key=lambda x: (-x[1], x[0]))[:8]:
    print(f"    {kind:8s} {n:22s} {c:3d}/{len(paths)} ({100*c/len(paths):.0f}%)")

print("\n  What-if: sin HAS_ACCESS_TO (svc-billing -> Customer PII DB), ¿llega dmz-portal-01 a un activo crítico?")
saved = ident_stores["svc-billing"][:]
before = bool(blast("dmz-portal-01")[2] & crown)
ident_stores["svc-billing"] = [d for d in saved if d != "Customer PII DB"]
after = bool(blast("dmz-portal-01")[2] & crown)
ident_stores["svc-billing"] = saved
print(f"    antes: {'sí' if before else 'no'} · después: {'sí' if after else 'no'}")
check(before and not after, "el what-if de svc-billing debería cortar el único camino de dmz-portal-01 a un activo crítico")
if errors:
    print("ERRORES:", *errors, sep="\n  ✗ ")
    sys.exit(1)

print("\n  Componentes conexas por CAN_REACH (ignorando dirección; fallback de comunidades / WCC):")
und = defaultdict(set)
for r in can_reach:
    und[r["from_host"]].add(r["to_host"])
    und[r["to_host"]].add(r["from_host"])
seen, comps = set(), []
for h in H:
    if h in seen:
        continue
    comp, q = {h}, deque([h])
    while q:
        n = q.popleft()
        for m in und[n]:
            if m not in comp:
                comp.add(m)
                q.append(m)
    seen |= comp
    comps.append(sorted(comp))
for c in sorted(comps, key=len, reverse=True):
    print(f"    ({len(c)}) {', '.join(c)}")
