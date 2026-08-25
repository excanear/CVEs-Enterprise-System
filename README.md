# CVEs Enterprise System

## NÃO FINALIZADO.

**Enterprise Attack Surface Intelligence & Exposure Validation Platform**

Uma plataforma de Attack Surface Management (ASM) *cloud-native*, orientada a eventos e organizada como uma federação de oito microsserviços Python (FastAPI) construídos em arquitetura hexagonal/DDD, um dashboard em Next.js 16 / React 19 e uma CLI enterprise-grade — tudo isso rodando sobre Kafka, PostgreSQL, Neo4j, Redis e OpenSearch, com observabilidade completa (OpenTelemetry, Prometheus, Grafana, Jaeger) e deploy nativo em Kubernetes.

O sistema descobre ativos expostos na internet, analisa runtime e bundles JavaScript de aplicações web, valida exposições reais (reduzindo falsos positivos), constrói um grafo de superfície de ataque, correlaciona evidências com IA e gera relatórios executivos/técnicos/de compliance — de ponta a ponta, para múltiplos tenants.

---

## Sumário

- [Visão geral](#visão-geral)
- [Arquitetura](#arquitetura)
- [Serviços](#serviços)
- [Bibliotecas compartilhadas](#bibliotecas-compartilhadas)
- [Dashboard](#dashboard)
- [CLI](#cli)
- [Infraestrutura & observabilidade](#infraestrutura--observabilidade)
- [Segurança](#segurança)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Como rodar localmente](#como-rodar-localmente)
- [Testes e qualidade](#testes-e-qualidade)
- [CI/CD](#cicd)
- [Deploy em Kubernetes](#deploy-em-kubernetes)
- [Stack tecnológica](#stack-tecnológica)

---

## Visão geral

O CVEs Enterprise System modela o pipeline completo de Attack Surface Management como um fluxo de eventos entre serviços independentes, cada um dono do seu próprio *bounded context* (no sentido de Domain-Driven Design):

1. **Descobrir** — mapear subdomínios, hosts e ativos expostos de uma organização.
2. **Analisar** — inspecionar runtime de aplicações web (via browser headless) e estaticamente decompor bundles JavaScript.
3. **Validar** — confirmar ativamente quais exposições são reais, eliminando falsos positivos através de um pipeline de 5 estágios.
4. **Correlacionar** — agrupar evidências, ranquear caminhos de ataque e priorizar exposições usando técnicas de ML (clustering DBSCAN) e IA generativa.
5. **Modelar em grafo** — representar toda a superfície de ataque (ativos, cadeias de confiança, propagação de exposição, dependências) em Neo4j.
6. **Reportar** — gerar relatórios executivos, técnicos, de compliance, de evidências e de remediação.

Cada etapa é um serviço HTTP independente que publica e consome eventos de domínio via Kafka, com persistência própria em PostgreSQL (e Neo4j para o grafo), garantindo desacoplamento, escalabilidade horizontal independente por serviço e isolamento de falhas.

## Arquitetura

```
                                   ┌──────────────────┐
                                   │     Dashboard     │  Next.js 16 · React 19
                                   │  (BFF via API routes) │
                                   └─────────┬─────────┘
                                             │ REST
        ┌─────────────┬─────────────┬───────┴───────┬─────────────┬─────────────┐
        ▼             ▼             ▼               ▼             ▼             ▼
 ┌─────────────┐┌─────────────┐┌──────────────┐┌─────────────┐┌─────────────┐┌─────────────┐
 │    Scan     ││  Discovery  ││   Runtime     ││     JS      ││  Exposure   ││    Asset    │
 │Orchestrator ││   Engine    ││  Analysis     ││ Intelligence││ Validation  ││    Graph    │
 │             ││             ││   Engine      ││   Engine    ││   Engine    ││   Engine    │
 └──────┬──────┘└──────┬──────┘└───────┬───────┘└──────┬──────┘└──────┬──────┘└──────┬──────┘
        │              │               │               │              │              │
        └──────────────┴───────────────┴───────┬───────┴──────────────┴──────────────┘
                                                 │
                                          ┌──────▼──────┐
                                          │    Kafka    │  event bus (Avro/Pydantic v2)
                                          └──────┬──────┘
                                                 │
                              ┌──────────────────┼──────────────────┐
                              ▼                                     ▼
                     ┌─────────────────┐                  ┌──────────────────┐
                     │  AI Correlation │                  │    Reporting     │
                     │      Layer      │                  │      Engine      │
                     └─────────────────┘                  └──────────────────┘

  Persistência:  PostgreSQL (por serviço, com Row-Level Security multi-tenant) · Neo4j (grafo)
  Cache/filas:   Redis
  Busca:         OpenSearch
  Observabilidade: OpenTelemetry Collector → Prometheus / Grafana / Jaeger
```

Princípios de design aplicados de forma consistente em todos os serviços:

- **Arquitetura hexagonal / DDD** — cada serviço segue a mesma estrutura interna: `domain/` (entidades e regras de negócio puras, sem I/O), `application/` (casos de uso / comandos), `infrastructure/` (adapters: banco, Kafka, HTTP externos) e `interface/` (routers FastAPI).
- **Event-driven** — comunicação assíncrona entre serviços via Kafka, com schemas de evento imutáveis e versionados (`libs/event-schemas`), incluindo padrão *Outbox* para consistência transacional (`OutboxMixin` em `libs/db-base`).
- **Multi-tenant desde a base** — isolamento de dados via Row-Level Security (RLS) no PostgreSQL, propagado por um `TenantContext` compartilhado (`libs/security`).
- **Observabilidade nativa** — tracing distribuído, métricas e logs estruturados (`structlog`) em todos os serviços, exportados via OpenTelemetry.
- **Segurança em profundidade** — proteção contra SSRF em todo scanning ativo, autenticação JWT/API Key, RBAC, rate limiting, containers non-root com `seccomp` e `cap_drop: ALL`, rede segmentada (`infra-net` / `backend-net` / `scanner-net`) e egress controlado via proxy Squid.

## Serviços

Todos os serviços são aplicações **FastAPI** assíncronas em **Python 3.12**, publicados como pacotes independentes no workspace `uv` e cada um com seu próprio `Dockerfile` e manifests Kubernetes em `k8s/services/`.

| Serviço | Módulo | Porta | Responsabilidade |
|---|---|---|---|
| **Scan Orchestrator** | `scan_orchestrator` | `8003` | Orquestração distribuída de scans: agendamento (cron), pools de workers, fila de execução e retries. |
| **Discovery Engine** | `discovery_engine` | — | Descoberta de subdomínios, hosts e ativos expostos (DNS, HTTP, parsing HTML). |
| **Runtime Analysis Engine** | `runtime_analysis` | `8004` | Análise dinâmica de aplicações web via instrumentação de browser headless (Playwright): sessões, chamadas de API observadas, tráfego WebSocket. |
| **JS Intelligence Engine** | `js_intelligence` | `8005` | Análise estática de bundles JavaScript: AST (tree-sitter), reconstrução de source maps, inferência de rotas e grafo de dependências. |
| **Exposure Validation Engine** | `exposure_validation` | `8006` | Pipeline de validação ativa em 5 estágios para reduzir falsos positivos de exposição. |
| **Asset Graph Engine** | `asset_graph` | `8007` | Grafo de superfície de ataque em Neo4j: caminhos de ataque, cadeias de confiança, propagação de exposição, relações de infraestrutura. |
| **AI Correlation Layer** | `ai_correlation` | `8008` | Clusterização de evidências (DBSCAN/scikit-learn), ranking determinístico de caminhos de ataque, priorização de exposições e geração de planos de remediação via LLM (OpenAI). |
| **Reporting Engine** | `reporting` | `8009` | Geração de relatórios executivos, técnicos, de compliance, evidências e remediação (Jinja2 + WeasyPrint → PDF). |

### API — endpoints principais

<details>
<summary><b>Scan Orchestrator</b> — <code>/api/v1</code></summary>

```
POST   /scans                        cria e agenda um novo scan
GET    /scans                        lista scans
GET    /scans/{scan_id}              status de um scan
DELETE /scans/{scan_id}              cancela um scan
POST   /scans/{scan_id}/retry        reexecuta um scan
GET    /workers/pools                pools de workers ativos
GET    /queue/depth                  profundidade da fila de execução
GET    /scheduler/jobs               jobs agendados (cron)
POST   /scheduler/jobs               cria job agendado
DELETE /scheduler/jobs/{job_id}      remove job agendado
```
</details>

<details>
<summary><b>Discovery Engine</b> — <code>/api/v1</code></summary>

```
POST  /discovery/jobs                       inicia job de descoberta
GET   /discovery/jobs                       lista jobs
GET   /discovery/jobs/{job_id}              status de um job
GET   /discovery/jobs/{job_id}/assets       ativos descobertos no job
GET   /discovery/assets                     lista ativos
GET   /discovery/assets/{asset_id}          detalhe de um ativo
PATCH /discovery/assets/{asset_id}/status   atualiza status do ativo
```
</details>

<details>
<summary><b>Runtime Analysis Engine</b> — <code>/runtime-analysis</code></summary>

```
POST /sessions                        inicia sessão de análise dinâmica
GET  /sessions                        lista sessões
GET  /sessions/{session_id}           status da sessão
GET  /sessions/{session_id}/result    resultado consolidado
GET  /sessions/{session_id}/apis      chamadas de API observadas
GET  /sessions/{session_id}/websockets tráfego WebSocket capturado
```
</details>

<details>
<summary><b>JS Intelligence Engine</b> — <code>/js-intelligence</code></summary>

```
POST /jobs                    inicia análise de bundle JS
GET  /jobs                    lista jobs
GET  /jobs/{job_id}           status
GET  /jobs/{job_id}/result    resumo de resultados
GET  /jobs/{job_id}/routes    rotas inferidas
GET  /jobs/{job_id}/bundles   bundles analisados
GET  /jobs/{job_id}/graph     grafo de dependências
```
</details>

<details>
<summary><b>Exposure Validation Engine</b> — <code>/exposure-validation</code></summary>

```
POST /jobs                   inicia validação de exposição
GET  /jobs                   lista jobs
GET  /jobs/{job_id}          status
GET  /jobs/{job_id}/result   resultado da validação
GET  /jobs/{job_id}/evidence quebra detalhada de evidências
```
</details>

<details>
<summary><b>Asset Graph Engine</b> — <code>/graph</code></summary>

```
POST /ingest                    ingere dados no grafo
GET  /assets                    ativos no grafo
GET  /attack-paths              caminhos de ataque calculados
GET  /trust-chains              cadeias de confiança
GET  /exposure-propagation      propagação de exposição entre ativos
GET  /dependencies               risco de dependências
GET  /infra                     relações de infraestrutura
GET  /stats                     estatísticas agregadas do grafo
```
</details>

<details>
<summary><b>AI Correlation Layer</b> — <code>/correlation</code></summary>

```
POST /sessions                          dispara correlação completa para um tenant
GET  /sessions/{id}                     status da sessão
GET  /clusters                          clusters de evidências
GET  /attack-paths/ranked               caminhos de ataque ranqueados
GET  /exposures/prioritized             exposições priorizadas
GET  /remediation/{cluster_id}          plano de remediação
GET  /risk-summary                      dashboard de risco agregado
```
</details>

<details>
<summary><b>Reporting Engine</b> — <code>/reports</code></summary>

```
POST /reports                     gera um novo relatório (executive, technical, compliance, evidence, remediation)
GET  /reports                     lista relatórios
GET  /reports/{report_id}         status/metadados
GET  /reports/{report_id}/download download do relatório (PDF)
...  + endpoints de compliance mapping, evidence export e remediation guidance
```
</details>

## Bibliotecas compartilhadas

Publicadas como membros do workspace `uv` em `libs/`, usadas por todos os serviços:

| Biblioteca | Propósito |
|---|---|
| `cves-db-base` | `AsyncSessionFactory`, `DeclarativeBase`, `OutboxMixin` (padrão Outbox transacional), `RLSMiddleware` (Row-Level Security multi-tenant), `CursorPagination`. |
| `cves-event-schemas` | Schemas de eventos de domínio imutáveis (Pydantic v2, compatíveis com Avro) para todos os *bounded contexts*: orquestração, descoberta, runtime, JS, validação, grafo, correlação e ativos. |
| `cves-kafka-client` | Cliente Kafka compartilhado (producer/consumer assíncronos, baseado em `confluent-kafka`). |
| `cves-observability` | Instrumentação padrão de OpenTelemetry, logging estruturado (`structlog`) e métricas. |
| `cves-rule-engine` | Motor de regras enterprise: regras em YAML, políticas de detecção, scoring de risco, supressão, correlação e validadores customizados. |
| `cves-security` | JWT, API keys, RBAC, contexto de tenant, proteção contra SSRF e rate limiting — usados por todos os serviços. |

## Dashboard

Aplicação web em **Next.js 16 (App Router) + React 19 + TypeScript**, atuando como front-end/BFF do sistema, consumindo os oito serviços de backend via variáveis de ambiente dedicadas (`RAE_BASE_URL`, `JSI_BASE_URL`, `EVE_BASE_URL`, `AGE_BASE_URL`, `ACL_BASE_URL`, `RE_BASE_URL`, `SO_BASE_URL`).

Principais módulos de UI (`src/app` / `src/components`):

- **Attack Surface** — visão consolidada da superfície de ataque.
- **Asset Graph** — visualização interativa do grafo (`@xyflow/react` + `@dagrejs/dagre`).
- **Exposure** — exposições validadas e priorizadas.
- **Runtime Analytics** — resultados de análise dinâmica.
- **Evidence** — evidências correlacionadas.
- **Remediation** — planos de remediação sugeridos.

Stack de UI: Tailwind CSS v4, Radix UI (Accordion, Tooltip, Select, Progress, ScrollArea), Recharts para gráficos, TanStack Query para data-fetching/cache, `lucide-react` para ícones.

## CLI

Uma CLI enterprise (`cves`) construída com **Typer** + **Rich** + **Textual**, publicada como pacote `cves-cli` (`cli/`), com interface TUI, autenticação (API key, OIDC, keyring do SO), sistema de plugins via entry points e múltiplos formatos de saída.

Grupos de comando (`cli/src/cves_cli/commands/`):

```
cves auth        # autenticação: login, API keys, cache de tokens
cves context      # gerenciamento de contexto/perfis de configuração
cves scan         # dispara e acompanha scans (Scan Orchestrator)
cves discover     # jobs de descoberta de ativos
cves analyze      # análise de runtime / JS
cves graph        # consultas ao Asset Graph
cves correlate    # correlação de evidências e IA
cves report       # geração e download de relatórios
cves workers      # gerenciamento de pools de workers
cves health       # health checks dos serviços
cves plugin       # gerenciamento de plugins de terceiros
```

Recursos notáveis: saída em `table | json | yaml | csv`, modo `--ci` (sem cores, saída JSON), autocomplete dinâmico, TUI para acompanhar scans/descobertas em tempo real (`textual`), e um sistema de plugins de terceiros registrados via `[project.entry-points."cves.plugins"]`.

Instalação:

```bash
cd cli
pip install -e .
cves --help
```

## Infraestrutura & observabilidade

`docker-compose.infra.yml` sobe todo o ambiente de desenvolvimento local:

| Componente | Papel |
|---|---|
| **PostgreSQL** | Persistência transacional por serviço (multi-tenant via RLS). |
| **Kafka + Zookeeper + Schema Registry** | Backbone de eventos assíncronos entre serviços. |
| **Redis** | Cache e filas leves. |
| **Neo4j** | Grafo de superfície de ataque (Asset Graph Engine). |
| **OpenSearch** | Indexação e busca. |
| **OpenTelemetry Collector** | Coleta de traces/métricas de todos os serviços. |
| **Jaeger** | Visualização de tracing distribuído. |
| **Prometheus + Grafana** | Métricas e dashboards (`infra/grafana/dashboards/platform-overview.json` já incluído). |
| **Squid** | Proxy de egress controlado para a rede de scanning (`scanner-net`), isolando tráfego de scan ativo. |

Todos os containers de aplicação rodam como usuário não-root (`user: "1001:1001"`), com `cap_drop: ALL`, `no-new-privileges` e perfis `seccomp` dedicados (`infra/seccomp/python-service.json`).

> **Nota:** `scan-orchestrator` e `discovery-engine` não são iniciados por este compose (voltado a infra + os demais serviços/dashboard) — eles são executados separadamente ou via os manifests em `k8s/services/`.

## Segurança

- **Autenticação:** JWT (`libs/security/jwt.py`) e API Keys (`api_key.py`).
- **Autorização:** RBAC (`rbac.py`).
- **Multi-tenancy:** contexto de tenant propagado ponta a ponta (`tenant_context.py`) e reforçado por Row-Level Security no PostgreSQL.
- **Anti-SSRF:** validação dedicada (`ssrf.py`) em todo componente que realiza requisições ativas a alvos externos (Discovery, Runtime Analysis, Exposure Validation).
- **Rate limiting:** `rate_limit.py`, aplicado nas APIs.
- **Supply chain:** SBOM (`make sbom`), scan de licenças (`make licenses`), SAST com Bandit e Semgrep, auditoria de dependências (`pip-audit`), secret scanning (Gitleaks) e CodeQL no CI, `Scorecard` (OpenSSF) via GitHub Actions.
- **Runtime hardening:** containers non-root, `cap_drop: ALL`, seccomp profiles, `NetworkPolicies` do Kubernetes (`k8s/networkpolicies/`) segmentando tráfego entre serviços.

## Estrutura do repositório

```
.
├── cli/                        # CLI enterprise (Typer + Rich + Textual)
├── libs/                       # bibliotecas compartilhadas (workspace uv)
│   ├── db-base/
│   ├── event-schemas/
│   ├── kafka-client/
│   ├── observability/
│   ├── rule-engine/
│   └── security/
├── services/                   # 8 microsserviços + dashboard
│   ├── scan-orchestrator/
│   ├── discovery-engine/
│   ├── runtime-analysis-engine/
│   ├── js-intelligence-engine/
│   ├── exposure-validation-engine/
│   ├── asset-graph-engine/
│   ├── ai-correlation-layer/
│   ├── reporting-engine/
│   └── dashboard/               # Next.js 16 + React 19
│       (cada serviço Python segue domain/application/infrastructure/interface)
├── infra/                      # Grafana, Squid, perfis seccomp
├── k8s/                        # manifests de produção (services, infra, keda, rbac, observability, operators)
├── tests/                      # unit, integration, contract, e2e, event_driven, performance, async
├── docker-compose.infra.yml    # ambiente de desenvolvimento local
├── Makefile                    # automação de todo o ciclo de dev/CI/CD
└── pyproject.toml              # workspace uv raiz
```

## Como rodar localmente

Pré-requisitos: **Python 3.12+**, [**uv**](https://docs.astral.sh/uv/), **Docker** + **Docker Compose**, **Node.js** (para o dashboard).

```bash
# 1. Clonar o repositório
git clone https://github.com/excanear/CVEs-Enterprise-System.git
cd CVEs-Enterprise-System

# 2. Instalar dependências de todo o workspace Python (libs + services)
make install

# 3. Subir a infraestrutura local (Postgres, Kafka, Redis, Neo4j, OpenSearch,
#    OTel Collector, Jaeger, Prometheus, Grafana) + serviços de backend + dashboard
make infra-up

# 4. Acompanhar logs
make logs
```

Após subir, os serviços ficam disponíveis em `localhost`:

| Serviço | URL |
|---|---|
| Dashboard | http://localhost:3000 |
| Runtime Analysis Engine | http://localhost:8004 |
| JS Intelligence Engine | http://localhost:8005 |
| Exposure Validation Engine | http://localhost:8006 |
| Asset Graph Engine | http://localhost:8007 |
| AI Correlation Layer | http://localhost:8008 |
| Reporting Engine | http://localhost:8009 |
| Grafana | http://localhost:3001 |
| Jaeger UI | http://localhost:16686 |
| Prometheus | http://localhost:9090 |
| Neo4j Browser | http://localhost:7474 |

Para derrubar o ambiente: `make infra-down`. Para resetar volumes: `make infra-reset`.

## Testes e qualidade

O projeto usa `pytest` com marcadores dedicados por camada de teste (`tests/`: `unit`, `integration`, `contract`, `event_driven`, `async_tests`, `e2e`, `performance`):

```bash
make test              # unit + integration
make test-unit         # unit, async, contract, event-driven (sem infra)
make test-integration  # requer docker-compose.infra.yml no ar
make test-e2e           # testes Playwright end-to-end (requer app rodando)
make test-performance   # testes de carga com Locust
make coverage           # relatório de cobertura
make coverage-gate       # falha se cobertura abaixo do limiar definido
```

Qualidade e segurança de código:

```bash
make lint        # ruff
make type        # mypy --strict
make format       # formatação automática
make bandit       # SAST Python
make semgrep      # SAST multi-linguagem
make audit         # pip-audit (vulnerabilidades de dependências)
make secrets       # detecção de segredos
make sbom          # geração de SBOM
make licenses       # auditoria de licenças
make ci            # pipeline completo local (mesma sequência do CI)
```

## CI/CD

Workflows em `.github/workflows/`:

- **`ci.yml`** — secret scanning (Gitleaks), lint, type-check, SAST, auditoria de dependências, testes e *coverage gate* em todo push/PR.
- **`build.yml`** — build das imagens Docker de todos os serviços.
- **`codeql.yml`** — análise estática de segurança (CodeQL).
- **`dependency-review.yml`** — revisão de dependências em PRs.
- **`scorecard.yml`** — pontuação de segurança da supply chain (OpenSSF Scorecard).
- **`deploy-staging.yml`** / **`deploy-production.yml`** (via `_reusable-deploy.yml`) — deploy automatizado para Kubernetes.
- **`dependabot.yml`** — atualização automática de dependências.

## Deploy em Kubernetes

Manifests completos em `k8s/`:

```
k8s/services/          # Deployments/Services por microsserviço + dashboard
k8s/infra/              # Postgres, Kafka, Redis, Neo4j, OpenSearch, Squid
k8s/observability/      # OTel Collector, Prometheus, Grafana, Jaeger
k8s/networkpolicies/    # segmentação de rede entre serviços
k8s/rbac/               # ServiceAccounts, Roles, RoleBindings
k8s/keda/               # autoscaling orientado a eventos (KEDA) para consumidores Kafka
k8s/operators/          # operators customizados
```

Comandos relevantes do Makefile:

```bash
make k8s-apply-staging     # aplica manifests no namespace de staging
make k8s-images             # build & push das imagens para o registry
make k8s-rollout-status     # acompanha rollout dos deployments
```

## Stack tecnológica

**Backend:** Python 3.12 · FastAPI · SQLAlchemy 2.0 (async) · asyncpg · Pydantic v2 · Alembic · confluent-kafka · Redis · Neo4j driver · Playwright · tree-sitter · scikit-learn · Jinja2 + WeasyPrint · structlog

**Frontend:** Next.js 16 · React 19 · TypeScript · Tailwind CSS v4 · Radix UI · TanStack Query · Recharts · @xyflow/react

**CLI:** Typer · Rich · Textual · httpx · PyJWT · keyring

**Dados & mensageria:** PostgreSQL · Kafka + Schema Registry · Redis · Neo4j · OpenSearch

**Observabilidade:** OpenTelemetry · Prometheus · Grafana · Jaeger

**Infra & DevOps:** Docker · Kubernetes · KEDA · uv (gerenciador de pacotes/workspace) · GitHub Actions · Gitleaks · CodeQL · Semgrep · Bandit · OpenSSF Scorecard

---

<p align="center"><sub>Enterprise Attack Surface Intelligence & Exposure Validation Platform</sub></p>
