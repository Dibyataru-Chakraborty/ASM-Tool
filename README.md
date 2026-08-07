# 🛡️ Digi Samurai ASM Platform — Enterprise Attack Surface Management Platform

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-v0.139.2-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-v14-black?logo=nextdotjs&logoColor=white)](https://nextjs.org)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue?logo=docker&logoColor=white)](https://docker.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-v16-4169E1?logo=postgresql&logoColor=white)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-v7-DC382D?logo=redis&logoColor=white)](https://redis.io)
[![Nginx](https://img.shields.io/badge/Nginx-Reverse_Proxy-009639?logo=nginx&logoColor=white)](https://nginx.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Digi Samurai ASM Platform** is an enterprise-grade, multi-tenant **Attack Surface Management (ASM)** and automated penetration testing system. It continuously discovers, maps, monitors, and evaluates an organization's digital footprints—such as domains, subdomains, open ports, DNS configurations, SSL certificates, exposed credentials, and vulnerabilities.

The platform integrates industry-standard security tools, threat intelligence APIs, and AI-powered pentesting logic to provide actionable insight with verified proof-of-concepts (PoCs).

---

## 🏗️ Architecture Overview

```text
                     +───────────────────────────────────────+
                     │          Web Browser / Client         │
                     +───────────────────┬───────────────────+
                                          │ HTTP / HTTPS (Port 80/443)
                                          ▼
                     +───────────────────────────────────────+
                     │         Nginx Reverse Proxy           │
                     +─────────┬───────────────────┬─────────+
                               │                   │
                     Port 3000 │                   │ Port 8000
                               ▼                   ▼
           +───────────────────────────+       +───────────────────────────+
           │    Next.js Frontend       │       │      FastAPI Backend      │
           │ (Digi Samurai UI Theme)   │       │                           │
           +───────────────────────────+       +───┬───┬───────────────┬───+
                                                   │   │               │
                                                   │   │               │
    +───────────────────────────────────+          │   │               │
    │      pd_installer container       ├──────────┘   │               │
    │ (Downloads Subfinder, Nuclei...)  │              │               │
    +───────────────────────────────────+              │               │
                                                       ▼               ▼
                                              +─────────────+   +─────────────+
                                              │ Local DB    │   │ Redis Cache │
                                              │ PostgreSQL  │   │  & Broker   │
                                              +──────┬──────+   +─────────────+
                                                     │
                                                     ▼ (Port 8080)
                                              +─────────────+
                                              │   Adminer   │
                                              │ DB Console  │
                                              +─────────────+
```

### Core Services
1. **Frontend**: Next.js App Router UI designed with a premium custom **maroon, white, and dark** palette, smooth light/dark mode transitions, and interactive dashboard charts.
2. **Backend**: FastAPI REST API providing high-concurrency request handling, Role-Based Access Control (RBAC), and integration with discovery services.
3. **Database**: Pinned local PostgreSQL database (`postgres` service) storing tracked assets, domains, subdomains, vulnerabilities, scan histories, and user credentials. All connections are local and secure.
4. **Database Console (Adminer)**: Visual dashboard running at `http://localhost:8080` mapped to the local Postgres database, fully customized with the Digi Samurai theme.
5. **Cache & Broker**: Redis serving as a caching layer for DNS/WHOIS data and a backend for asynchronous task coordination.
6. **Nginx Reverse Proxy**: Single entry point handling TLS, routing `/api/v1` to the backend, serving Next.js pages, serving domain screenshots, and enforcing rate limiting.
7. **ProjectDiscovery Installer**: Docker helper that downloads and updates binaries (like `subfinder`, `dnsx`, `naabu`, `httpx`, `nuclei`, `gowitness`) into a shared volume accessible by the backend scanner.

---

## ⚡ Capabilities Matrix

| Security Phase / Vector | Underlying Tool / Binary | Responsible Backend Service | Description |
| :--- | :--- | :--- | :--- |
| **Subdomain Reconnaissance** | `subfinder`, `dnsx` | [discovery_service.py](backend/app/services/discovery_service.py) | Finds subdomains using passive intelligence feeds and confirms active DNS mapping. |
| **Service & Port Analysis** | `naabu`, `nmap` | [port_scan_service.py](backend/app/services/port_scan_service.py) | Rapid port scanning and service detection on target networks. |
| **Technology Profiling** | `httpx` | [discovery_service.py](backend/app/services/discovery_service.py) | Identifies server software, framework stacks, and active protocols. |
| **Visual Reconnaissance** | `gowitness` (Chrome headless) | [discovery_service.py](backend/app/services/discovery_service.py) | Captures full-page screenshots of active subdomains, mounted locally. |
| **Threat Intelligence** | Shodan, Censys, VirusTotal | [discovery_service.py](backend/app/services/discovery_service.py) | Enriches discovered IPs/domains with external vulnerability feeds & reputational analysis. |
| **Secret Detection** | Custom Regex Engine | [discovery_service.py](backend/app/services/discovery_service.py) | Scans cloud storage files and git repositories for leaked credentials/API keys. |
| **Vulnerability Scanning** | `nuclei` | [ai_vulnerability_service.py](backend/app/services/ai_vulnerability_service.py) | Performs targeted, template-driven vulnerability assessments on services. |
| **Service-Version Enrichment** | `nmap` + AI Grounding | [gemini_service_assessment.py](backend/app/services/gemini_service_assessment.py) | Checks detected product versions, cited CVE applicability, and lifecycle status without replacing scanner evidence. |
| **Shannon AI Pentester** | Google Gemini (or Open AI/Claude) | [ai_vulnerability_service.py](backend/app/services/ai_vulnerability_service.py) | Multi-phase agentic pentesting logic simulating crawling, exploit verification, and PoC generation. |

---

## 📂 Codebase Anatomy

```text
Digi Samurai ASM Tool (Root)
 ├── docker-compose.yml ────── Orchestrates the full docker service stack
 ├── adminer.css ───────────── Custom stylesheet for the database console
 ├── digi_samurai.php ──────── Adminer plugin for logo branding & password toggling
 ├── backend/
 │    ├── app/
 │    │    ├── api/v1/ ─────── API routers:
 │    │    │    ├── auth/ ──── RBAC user registration & token generation
 │    │    │    ├── scans/ ── Scan initiation, logging, and history
 │    │    │    ├── shannon/  Shannon AI pentester execution
 │    │    │    └── router.py  Main application API router mapping
 │    │    ├── models/ ─────── SQLAlchemy models (Domain, Scan, User, Vulnerability)
 │    │    ├── repositories/ ─ Database queries and transaction layer
 │    │    ├── services/ ───── Service tier (Discovery, Port scan, AI vulnerability services)
 │    │    ├── config.py ───── Pydantic settings parsing environment variables
 │    │    └── main.py ─────── FastAPI app initialization & CORS middleware
 │    └── requirements.txt ─── Backend python dependencies
 ├── frontend/
 │    ├── app/ ─────────────── React pages (Dashboard, Scan Manager, Shannon Agent logs)
 │    ├── components/ ──────── Shared UI components (Data Tables, Alerts, Graphs)
 │    └── package.json ─────── Frontend dependencies (Next.js, Tailwind, React, Lucide)
 ├── nginx/
 │    └── nginx.conf ───────── Reverse proxy config, rate-limiting, and TLS routing
 └── scripts/
      └── install_pd_tools.sh ─ Script running inside docker-compose to download Go binaries
```

---

## ⚙️ Environment Configuration

The application requires environment files (`.env`) inside both the `backend/` and `frontend/` folders. Check the templates for instructions:
* Backend Template: [backend/.env.example](backend/.env.example)
* Frontend Template: [frontend/.env.example](frontend/.env.example)

### Key Environment Variables

#### Backend (`backend/.env`)
| Variable | Category | Description | Default / Example |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | Database | Connection string for local PostgreSQL database. | `postgresql://asm_user:asm_password@postgres:5432/asm_db` |
| `SECRET_KEY` | Security | Session signing key. Generate via `python -c "import secrets; print(secrets.token_hex(32))"`. | `[cryptographic-hex-string]` |
| `JWT_SECRET_KEY` | Security | JWT signing key. Generate via `python -c "import secrets; print(secrets.token_hex(32))"`. | `[cryptographic-hex-string]` |
| `REDIS_URL` | Task Queue | Connection URL for Redis cache database. | `redis://redis:6379/0` |
| `GEMINI_API_KEY` | AI Agent | API Key for Google Gemini (required for Shannon AI pentester). | `[your-gemini-key]` |
| `SHODAN_API_KEY` | Threat Intel | Shodan API key for port scan data & active IP enrichment. | `[your-shodan-key]` |
| `VIRUSTOTAL_API_KEY` | Threat Intel | VirusTotal API key for IP and domain reputation. | `[your-virustotal-key]` |
| `BOOTSTRAP_SUPER_ADMIN_EMAIL` | Security | Initial Super Admin email created on startup. | `xhunter101@proton.me` |
| `BOOTSTRAP_SUPER_ADMIN_PASSWORD`| Security | Initial Super Admin password. (Escape `$` using `$$` in compose). | `2P8t!b9NV#md$$kzfmqnf` |

#### Frontend (`frontend/.env`)
| Variable | Description | Default |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_URL` | URL pointing to the backend FastAPI application. | `http://localhost:8000` |
| `NEXT_PUBLIC_APP_NAME` | Title shown across the user interface. | `Digi Samurai ASM Platform` |

---

## 🛢️ Database Dashboard (Adminer)

A dedicated, customized database administration dashboard is available to inspect and query the local PostgreSQL database in real-time.

* **URL**: [http://localhost:8080](http://localhost:8080)
* **Logins/Credentials**:
  - **System**: `PostgreSQL`
  - **Server**: `postgres`
  - **Username**: `asm_user`
  - **Password**: `asm_password`
  - **Database**: `asm_db`

The dashboard is custom-styled with the **Digi Samurai** theme (maroon, white, and dark) and features a password-visibility toggle on the login page.

---
## 🚀 Getting Started

### Prerequisites
Make sure you have [Docker](https://docs.docker.com/engine/install/) and **Docker Compose (v2.0+)** installed on your system.

### 1. Copy and Edit Configuration
Generate environment files from the provided templates:

```bash
# Setup backend configuration
cp backend/.env.example backend/.env

# Setup frontend configuration
cp frontend/.env.example frontend/.env
```

Open both `.env` files and fill in the required credentials, local DB links, and API keys.

### 2. Build and Start the Stack
Start all components in detached mode:

```bash
docker compose up -d --build
```

> [!NOTE]
> The `--build` flag compiles your latest code changes into the Docker images. Run this command whenever you update frontend or backend source files.

### 3. Verify System Health
Check the container status to verify all services started successfully:

```bash
docker compose ps
```

All services (`asm_postgres`, `asm_adminer`, `asm_redis`, `asm_backend`, `asm_frontend`, `asm_nginx`) should display `running` or `healthy`.

---

## 🛠️ Operations & Troubleshooting

### Handy Service Commands
* **Stop the stack**: `docker compose down`
* **Restart the services**: `docker compose restart`
* **View real-time logs**: `docker compose logs -f --tail=100`
* **Check specific container logs** (e.g., backend): `docker compose logs -f backend`

### Troubleshooting Common Issues

#### 1. Database Connection Failures
* **Error**: `asyncpg.exceptions.InvalidPasswordError` or `ConnectionRefusedError`.
* **Fix**: Ensure `DATABASE_URL` in `backend/.env` is configured to connect to the local postgres container: `postgresql://asm_user:asm_password@postgres:5432/asm_db`.

#### 2. Dollar Sign in Super Admin Password
* **Error**: Login fails or the password appears truncated in logs.
* **Fix**: Docker Compose treats `$` as a variable expansion. Escape any dollar sign inside the `BOOTSTRAP_SUPER_ADMIN_PASSWORD` variable in `backend/.env` by doubling it up (`$$`), for example: `2P8t!b9NV#md$$kzfmqnf`.

#### 3. Port Collisions (Port 80/443/3000/8000/8080 already in use)
* **Error**: `Bind for 0.0.0.0:80 failed: port is already allocated`.
* **Fix**: Locate what service is holding the port. You can change port bindings inside `docker-compose.yml` (e.g., mapping nginx to alternative host ports like `8080:80` or changing other mapped ports).

#### 3. Alembic Database Migration Issues
* **Error**: `alembic.util.exc.CommandError: Can't locate revision` or database out of sync.
* **Fix**: Access the backend shell and force migration upgrade manually:
  ```bash
  docker compose exec backend alembic upgrade head
  ```

#### 4. ProjectDiscovery Binaries Missing/Not Executing
* **Error**: Backend logs report `subfinder command not found` or `nuclei not found`.
* **Fix**: The `pd_installer` container compiles these tools during initial boot into the `pd_tools` volume. Check if the container ran successfully by running `docker logs asm_pd_installer`. If it failed, restart it:
  ```bash
  docker compose start pd_installer
  ```

---

## 🔌 API Documentation Map

When the stack is running, you can access interactive documentation pages:
* **Swagger UI**: [http://localhost/docs](http://localhost/docs)
* **ReDoc**: [http://localhost/redoc](http://localhost/redoc)

### Primary API Endpoints
| HTTP Verb | Path | Request/Response Model | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/login` | Access token response | Authenticates users and issues JWT access/refresh tokens. |
| `POST` | `/api/v1/scans/run` | Scan instance details | Initiates an automated recon and technology profiling scan. |
| `GET` | `/api/v1/scans/history` | List of past scan tasks | Returns scan configurations, schedules, and result sets. |
| `POST` | `/api/v1/shannon/pentest` | AI agent status model | Runs AI Agentic Pentesting workflows on target domain. |
| `GET` | `/api/v1/dashboard/stats` | Dashboard statistics JSON | Aggregates vulnerability status counts and asset maps. |

---

## 🛡️ Security Disclaimer

This software is designed solely for authorized security audits, internal threat surface mapping, and research assessments. Scanning public targets without prior written authorization from the system owners is illegal and subject to criminal prosecution. The authors and contributors assume no liability for misuse, damages, or legal consequences resulting from this tool.
