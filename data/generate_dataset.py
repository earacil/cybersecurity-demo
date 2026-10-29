#!/usr/bin/env python3
"""
Generador del dataset sintético de la demo de ciberseguridad (banca + telecomunicaciones).

Fuente única de verdad del contenido: aquí se definen librerías, vulnerabilidades, aplicaciones,
hosts, identidades, almacenes y servicios de negocio, y se escriben los CSV de esta carpeta.
Los CSV son los artefactos que carga `00_load_live.cypher`; este script solo existe para mantenerlos
coherentes entre sí.

Uso:
    python3 generate_dataset.py     # reescribe los CSV
    python3 validate_dataset.py     # valida integridad, criterios de aceptación y calcula los
                                    # resultados esperados (independiente de este script: solo lee CSV)

Todo el contenido es SINTÉTICO. No representa a ningún cliente ni entorno real. Los identificadores de
vulnerabilidad son ficticios (SYN-xxxx), salvo el gancho CVE-2021-44228; no se carga NVD ni el catálogo KEV.

CLAVES DE MERGE (decididas el 29-oct-2026, para que la carga sea legible):
    Vulnerability.id · Library (name, version) · Application.name · Host.name ·
    Identity.name · DataStore.name · BusinessService.name

GANCHO DE LA NARRATIVA (CVE-2021-44228, Log4Shell; el único CVE real): NO está en los CSV base; vive en `zero_day_vulnerability.csv` y
`zero_day_affects.csv` y se inserta en directo (ver README.md de esta carpeta).
"""
import csv
from pathlib import Path

OUT = Path(__file__).parent

# --------------------------------------------------------------------------------------
# Servicios de negocio (BusinessService): name, criticality
# --------------------------------------------------------------------------------------
BUSINESS_SERVICES = [
    ("Card Payments", "High"),
    ("Online Banking", "High"),
    ("Subscriber Provisioning", "High"),
    ("Billing and Invoicing", "Medium"),
    ("Staff Intranet", "Low"),
]

# --------------------------------------------------------------------------------------
# Almacenes de datos (DataStore): name, data_class, crown_jewel
# --------------------------------------------------------------------------------------
DATA_STORES = [
    ("Customer PII DB", "PII", True),
    ("Card Ledger", "Financial", True),
    ("Subscriber Registry", "Subscriber", True),  # activo crítico NO alcanzable desde Internet (bien protegida)
    ("Billing DB", "Financial", False),
    ("Ops Log Archive", "Operational", False),
]

# --------------------------------------------------------------------------------------
# Identidades (Identity): name, type
# --------------------------------------------------------------------------------------
IDENTITIES = [
    ("svc-payments", "ServiceAccount"),
    ("svc-customer-profile", "ServiceAccount"),
    ("svc-billing", "ServiceAccount"),  # sobre-privilegiada a propósito: también lee PII
    ("svc-provisioning", "ServiceAccount"),
    ("role-monitoring", "Role"),
]

# --------------------------------------------------------------------------------------
# Hosts (Host): name, environment, internet_exposed
# --------------------------------------------------------------------------------------
HOSTS = [
    # Expuestos a Internet (puntos de entrada)
    ("dmz-web-01", "Production", True),
    ("dmz-api-01", "Production", True),
    ("dmz-portal-01", "Production", True),
    # Aplicaciones internas alcanzables desde la DMZ
    ("app-pay-01", "Production", False),
    ("app-cust-01", "Production", False),
    ("app-bill-01", "Production", False),
    # Bases de datos / observabilidad
    ("db-pay-01", "Production", False),
    ("db-cust-01", "Production", False),  # sin entradas de red: solo se llega a su dato por identidad
    ("db-bill-01", "Production", False),
    ("mon-01", "Production", False),
    # Zona aislada (telecom core / gestión): no alcanzable desde Internet
    ("jump-01", "Production", False),
    ("app-prov-01", "Production", False),
    ("db-sub-01", "Production", False),
    ("int-web-01", "Production", False),
    # Host de pruebas aislado
    ("tst-report-01", "Test", False),
]

# --------------------------------------------------------------------------------------
# Librerías (Library): name -> version. Una versión por librería; la clave es (name, version).
# --------------------------------------------------------------------------------------
LIBS = {
    "log4j-core": "2.14.1",      # librería de logging, muy profunda: aquí cae el día cero real CVE-2021-44228
    "observability-sdk": "3.0.2",  # intermedia (sintética) entre platform-commons y log4j-core
    "platform-commons": "5.2.0",
    "service-kit": "3.1.0",
    "http-server-lite": "4.8.1",
    "json-parse-fast": "1.9.0",
    "crypto-utils": "3.4.2",
    "db-connector": "6.0.3",
    "session-manager": "2.0.5",
    "template-engine": "3.3.0",
    "iso8583-codec": "1.5.2",    # mensajería de tarjetas (banca)
    "diameter-stack": "2.1.0",   # señalización (telecom)
    "xml-binding": "2.3.1",
    "pdf-render": "1.2.0",
}

# Dependencias librería -> librería (DEPENDS_ON). Sin ciclos.
LIB_DEPS = [
    ("service-kit", "platform-commons"),
    ("service-kit", "json-parse-fast"),
    ("platform-commons", "observability-sdk"),
    ("platform-commons", "crypto-utils"),
    ("observability-sdk", "log4j-core"),
    ("db-connector", "crypto-utils"),
    ("session-manager", "crypto-utils"),
    ("session-manager", "json-parse-fast"),
    ("diameter-stack", "crypto-utils"),
    ("pdf-render", "xml-binding"),
]

# --------------------------------------------------------------------------------------
# Aplicaciones (Application): name, tier, host, business_services, direct_libs
# --------------------------------------------------------------------------------------
APPLICATIONS = [
    ("online-banking-web", "P0", "dmz-web-01", ["Online Banking"],
     ["service-kit", "template-engine", "session-manager", "http-server-lite"]),
    ("payments-gateway", "P0", "dmz-api-01", ["Card Payments"],
     ["http-server-lite", "json-parse-fast", "platform-commons"]),
    ("payments-core", "P0", "app-pay-01", ["Card Payments"],
     ["platform-commons", "iso8583-codec", "db-connector"]),
    ("customer-profile-service", "P1", "app-cust-01", ["Online Banking"],
     ["service-kit", "db-connector", "json-parse-fast"]),
    ("selfcare-portal", "P1", "dmz-portal-01", ["Billing and Invoicing", "Subscriber Provisioning"],
     ["http-server-lite", "template-engine", "json-parse-fast"]),
    ("billing-engine", "P1", "app-bill-01", ["Billing and Invoicing"],
     ["json-parse-fast", "db-connector", "template-engine"]),
    ("provisioning-engine", "P0", "app-prov-01", ["Subscriber Provisioning"],
     ["service-kit", "diameter-stack", "db-connector"]),
    ("staff-intranet", "P2", "int-web-01", ["Staff Intranet"],
     ["service-kit", "template-engine", "session-manager"]),
    ("legacy-report-tool", "P3", "tst-report-01", [],
     ["pdf-render", "db-connector"]),
]

# --------------------------------------------------------------------------------------
# Red (CAN_REACH): from_host, to_host, port. Profundidad máxima de caminos en las queries: 10.
# --------------------------------------------------------------------------------------
CAN_REACH = [
    ("dmz-web-01", "app-cust-01", 8443),
    ("dmz-web-01", "app-pay-01", 8443),
    ("dmz-api-01", "app-pay-01", 8443),
    ("dmz-portal-01", "app-bill-01", 8443),
    ("app-pay-01", "db-pay-01", 5432),
    ("app-pay-01", "app-cust-01", 8443),
    ("app-cust-01", "app-bill-01", 8443),
    ("app-bill-01", "db-bill-01", 5432),
    ("app-pay-01", "mon-01", 9200),
    ("app-cust-01", "mon-01", 9200),
    ("app-bill-01", "mon-01", 9200),
    # Zona aislada: solo se entra por jump-01, al que no llega nada de la zona expuesta
    ("jump-01", "app-prov-01", 22),
    ("jump-01", "db-sub-01", 5432),
    ("jump-01", "int-web-01", 22),
    ("app-prov-01", "db-sub-01", 5432),
]

# Host -> identidad que hereda quien lo compromete (RUNS_AS)
RUNS_AS = [
    ("app-pay-01", "svc-payments"),
    ("app-cust-01", "svc-customer-profile"),
    ("app-bill-01", "svc-billing"),
    ("app-prov-01", "svc-provisioning"),
    ("mon-01", "role-monitoring"),
]

# Identidad -> almacén (HAS_ACCESS_TO)
HAS_ACCESS_TO = [
    ("svc-payments", "Card Ledger"),
    ("svc-customer-profile", "Customer PII DB"),
    ("svc-billing", "Billing DB"),
    ("svc-billing", "Customer PII DB"),  # exceso de permisos: abre un camino desde el portal hasta PII
    ("svc-provisioning", "Subscriber Registry"),
    ("role-monitoring", "Ops Log Archive"),
]

# Host -> almacén alojado físicamente (STORES)
STORES = [
    ("db-pay-01", "Card Ledger"),
    ("db-cust-01", "Customer PII DB"),
    ("db-bill-01", "Billing DB"),
    ("db-sub-01", "Subscriber Registry"),
    ("mon-01", "Ops Log Archive"),
]

# --------------------------------------------------------------------------------------
# Vulnerabilidades base (SYN-0002..): id, cvss_score, known_exploited, library, description
# CVE-2021-44228 (el gancho) NO va aquí.
# --------------------------------------------------------------------------------------
VULNS = [
    ("SYN-0002", 9.8, False, "xml-binding", "XML external entity processing allows remote code execution"),
    ("SYN-0003", 5.0, True, "template-engine", "Server-side template injection exposes request context"),
    ("SYN-0004", 6.5, False, "http-server-lite", "HTTP request smuggling through malformed headers"),
    ("SYN-0005", 5.3, False, "json-parse-fast", "Denial of service through deeply nested documents"),
    ("SYN-0006", 3.7, False, "crypto-utils", "Timing side channel in token comparison"),
    ("SYN-0007", 8.1, False, "db-connector", "Credentials written to connection debug logs"),
    ("SYN-0008", 8.8, False, "iso8583-codec", "Improper message length validation corrupts memory"),
    ("SYN-0009", 9.0, False, "diameter-stack", "Authentication bypass for signalling peers"),
    ("SYN-0010", 6.1, False, "session-manager", "Session fixation after privilege change"),
    ("SYN-0011", 4.3, False, "service-kit", "Information disclosure in default error pages"),
    ("SYN-0012", 5.5, False, "platform-commons", "Unsafe default configuration exposes admin endpoint"),
    ("SYN-0013", 7.8, False, "pdf-render", "Heap overflow when rendering crafted documents"),
    ("SYN-0014", 3.1, False, "observability-sdk", "Log level override through untrusted input"),
    ("SYN-0015", 6.5, False, "xml-binding", "Entity expansion exhausts memory"),
    ("SYN-0016", 4.0, False, "iso8583-codec", "Verbose errors leak message field names"),
    ("SYN-0017", 6.1, False, "template-engine", "Reflected cross-site scripting in default error template"),
    ("SYN-0018", 3.3, False, "observability-sdk", "Metrics endpoint accepts unescaped line breaks"),
]

# --------------------------------------------------------------------------------------
# Día cero (gancho): se inserta EN DIRECTO. Historia en README.md de esta carpeta.
# --------------------------------------------------------------------------------------
# ÚNICO identificador real del dataset: CVE-2021-44228 (Log4Shell). CVSS 10.0, explotación conocida.
ZERO_DAY = ("CVE-2021-44228", 10.0, True, "log4j-core",
            "Log4Shell: remote code execution through JNDI lookups in logged messages")


# --------------------------------------------------------------------------------------
def write_csv(name, header, rows):
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)
    print(f"  {name:34s} {len(rows):3d} filas")


def b(v):
    return "true" if v else "false"


def main():
    print(f"Escribiendo CSV en {OUT}")
    lib = lambda n: (n, LIBS[n])

    # Nodos
    write_csv("business_services.csv", ["name", "criticality"], BUSINESS_SERVICES)
    write_csv("data_stores.csv", ["name", "data_class", "crown_jewel"],
              [(n, c, b(j)) for n, c, j in DATA_STORES])
    write_csv("identities.csv", ["name", "type"], IDENTITIES)
    write_csv("hosts.csv", ["name", "environment", "internet_exposed"],
              [(n, e, b(x)) for n, e, x in HOSTS])
    write_csv("libraries.csv", ["name", "version"], [(n, v) for n, v in LIBS.items()])
    write_csv("applications.csv", ["name", "tier"], [(a[0], a[1]) for a in APPLICATIONS])
    write_csv("vulnerabilities.csv", ["id", "cvss_score", "known_exploited", "description"],
              [(i, f"{s:.1f}", b(k), d) for i, s, k, _, d in VULNS])

    # Relaciones
    write_csv("affects.csv", ["vulnerability_id", "library_name", "library_version"],
              [(i, *lib(l)) for i, _, _, l, _ in VULNS])
    write_csv("lib_depends_on.csv",
              ["from_name", "from_version", "to_name", "to_version"],
              [(*lib(a), *lib(c)) for a, c in LIB_DEPS])
    write_csv("app_depends_on.csv", ["application", "library_name", "library_version"],
              [(a[0], *lib(l)) for a in APPLICATIONS for l in a[4]])
    write_csv("runs_on.csv", ["application", "host"], [(a[0], a[2]) for a in APPLICATIONS])
    write_csv("supports.csv", ["application", "business_service"],
              [(a[0], s) for a in APPLICATIONS for s in a[3]])
    write_csv("can_reach.csv", ["from_host", "to_host", "port"], CAN_REACH)
    write_csv("runs_as.csv", ["host", "identity"], RUNS_AS)
    write_csv("has_access_to.csv", ["identity", "data_store"], HAS_ACCESS_TO)
    write_csv("stores.csv", ["host", "data_store"], STORES)

    # Gancho de día cero (aparte: se inserta en directo)
    i, s, k, l, d = ZERO_DAY
    write_csv("zero_day_vulnerability.csv", ["id", "cvss_score", "known_exploited", "description"],
              [(i, f"{s:.1f}", b(k), d)])
    write_csv("zero_day_affects.csv", ["vulnerability_id", "library_name", "library_version"],
              [(i, *lib(l))])


if __name__ == "__main__":
    main()
