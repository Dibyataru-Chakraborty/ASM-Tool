"""Optional extended reconnaissance stages for the real ASM pipeline.

The service normalizes only factual tool output. Discovery-only results are
used as additional inputs for probing/Nuclei and are not converted directly
into vulnerabilities.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from pathlib import Path
from typing import Any, Callable, Iterable, Optional
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from app.config import settings


logger = logging.getLogger(__name__)
RunCommand = Callable[..., Any]

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9-])"
)
_DIRB_RE = re.compile(
    r"\+\s+(https?://\S+)\s+\(CODE:(\d{3})\|SIZE:(\d+)\)",
    re.IGNORECASE,
)
_XSS_VULNERABLE_RE = re.compile(
    r"(?:vulnerable\s+webpage|payload\s+generated|potentially\s+vulnerable)",
    re.IGNORECASE,
)
_CVE_RE = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b",
    re.IGNORECASE,
)


def hostname_from(value: str) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw.split("/")[0].split(":")[0]).rstrip(".")


def in_scope_host(host: str, target: str) -> bool:
    normalized = hostname_from(host)
    root = hostname_from(target)
    return bool(normalized and root and (normalized == root or normalized.endswith(f".{root}")))


def normalize_url(value: str, target: str) -> Optional[str]:
    raw = (value or "").strip().rstrip(".,;)]}")
    if not raw.startswith(("http://", "https://")):
        return None
    parsed = urlparse(raw)
    if not parsed.hostname or not in_scope_host(parsed.hostname, target):
        return None
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()
    port = parsed.port
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname
    normalized = urlunparse((scheme, netloc, parsed.path or "/", "", parsed.query, ""))
    return normalized[:4096]


def origin_url(value: str, target: str) -> Optional[str]:
    normalized = normalize_url(value, target)
    if not normalized:
        return None
    parsed = urlparse(normalized)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def urls_from_text(text: str, target: str) -> set[str]:
    output: set[str] = set()
    for match in _URL_RE.findall(text or ""):
        normalized = normalize_url(match, target)
        if normalized:
            output.add(normalized)
    return output


def hosts_from_text(text: str, target: str) -> set[str]:
    output: set[str] = set()
    for match in _HOST_RE.findall(text or ""):
        host = hostname_from(match)
        if in_scope_host(host, target):
            output.add(host)
    return output


def cap_urls(values: Iterable[str], maximum: int) -> list[str]:
    return sorted(set(values))[: max(0, maximum)]


def select_nuclei_targets(values: Iterable[str], target: str, maximum: int) -> list[str]:
    """Prioritize origins and parameterized endpoints for a bounded scan."""
    normalized = {
        candidate
        for value in values
        if (candidate := normalize_url(value, target))
    }
    origins = {
        origin
        for value in normalized
        if (origin := origin_url(value, target))
    }
    parameterized = {
        value for value in normalized
        if urlparse(value).query and value not in origins
    }
    other_paths = normalized - origins - parameterized
    prioritized = [
        *sorted(origins),
        *sorted(parameterized),
        *sorted(other_paths),
    ]
    return prioritized[: max(0, maximum)]


def build_dirsearch_command(
    executable: Path,
    url: str,
    report: Path,
    max_rate: int,
) -> list[str]:
    """Build a dirsearch v0.5-compatible JSON report command."""
    return [
        str(executable),
        "-u",
        url,
        "-O",
        "json",
        "-o",
        str(report),
        "--quiet-mode",
        "--max-rate",
        str(max_rate),
        "--timeout",
        "8",
        "--retries",
        "1",
    ]


def parse_json_file(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def collect_additional_subdomains(
    *,
    target: str,
    temp_path: Path,
    tools: dict[str, Path],
    run_command: RunCommand,
) -> set[str]:
    """Collect passive in-scope hostnames from optional discovery sources."""
    discovered: set[str] = set()

    if settings.sublist3r_enabled and "sublist3r" in tools:
        output_file = temp_path / "passive-subdomains.txt"
        result = run_command(
            [
                str(tools["sublist3r"]),
                "-d",
                target,
                "-o",
                str(output_file),
            ],
            "additional passive asset discovery",
            300,
            continue_on_error=True,
        )
        if output_file.is_file():
            discovered.update(hosts_from_text(output_file.read_text(errors="replace"), target))
        discovered.update(hosts_from_text(result.stdout, target))

    if settings.uncover_enabled and "uncover" in tools:
        result = run_command(
            [
                str(tools["uncover"]),
                "-q",
                f"hostname:{target}",
                "-e",
                settings.uncover_engine,
                "-f",
                "host",
                "-j",
                "-silent",
                "-l",
                str(settings.uncover_limit),
            ],
            "external asset search",
            180,
            continue_on_error=True,
        )
        for line in (result.stdout or "").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                discovered.update(hosts_from_text(line, target))
                continue
            if isinstance(row, dict):
                for key in ("host", "hostname", "domain"):
                    value = str(row.get(key) or "")
                    if in_scope_host(value, target):
                        discovered.add(hostname_from(value))

    return discovered


def _parse_katana_output(text: str, target: str) -> set[str]:
    urls: set[str] = set()
    for line in (text or "").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            urls.update(urls_from_text(line, target))
            continue
        if not isinstance(row, dict):
            continue
        candidates: list[str] = []
        request = row.get("request")
        response = row.get("response")
        if isinstance(request, dict):
            candidates.extend(str(request.get(key) or "") for key in ("endpoint", "url"))
        if isinstance(response, dict):
            candidates.extend(str(response.get(key) or "") for key in ("url", "endpoint"))
        candidates.extend(str(row.get(key) or "") for key in ("url", "endpoint", "request_url"))
        for candidate in candidates:
            normalized = normalize_url(candidate, target)
            if normalized:
                urls.add(normalized)
    return urls


def _parse_dirsearch_report(path: Path, target: str) -> set[str]:
    payload = parse_json_file(path)
    urls: set[str] = set()
    if payload is None:
        return urls

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key.lower() in {"url", "full_url", "location"} and isinstance(item, str):
                    normalized = normalize_url(item, target)
                    if normalized:
                        urls.add(normalized)
                else:
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    return urls


def _parse_wappalyzer_output(text: str, target: str) -> dict[str, set[str]]:
    technology_by_host: dict[str, set[str]] = {}
    raw = (text or "").strip()
    if not raw:
        return technology_by_host
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return technology_by_host

    # Wappalyzer Next returns {"https://host": {"Technology": {...}}}.
    if isinstance(payload, dict) and any(
        str(key).startswith(("http://", "https://")) for key in payload
    ):
        for source_url, detected in payload.items():
            host = hostname_from(str(source_url))
            if not in_scope_host(host, target) or not isinstance(detected, dict):
                continue
            names: set[str] = set()
            for name, details in detected.items():
                if not name:
                    continue
                version = details.get("version") if isinstance(details, dict) else None
                names.add(f"{name} {version}".strip() if version else str(name))
            if names:
                technology_by_host.setdefault(host, set()).update(names)
        return technology_by_host

    rows = payload if isinstance(payload, list) else [payload]
    for row in rows:
        if not isinstance(row, dict):
            continue
        host = hostname_from(str(row.get("url") or row.get("hostname") or ""))
        if not in_scope_host(host, target):
            continue
        technologies = row.get("technologies") or row.get("applications") or []
        names: set[str] = set()
        if isinstance(technologies, dict):
            for name, details in technologies.items():
                version = details.get("version") if isinstance(details, dict) else None
                names.add(f"{name} {version}".strip() if version else str(name))
        elif isinstance(technologies, list):
            for item in technologies:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("technology")
                    version = item.get("version")
                    if name:
                        names.add(f"{name} {version}".strip() if version else str(name))
                elif item:
                    names.add(str(item))
        if names:
            technology_by_host.setdefault(host, set()).update(names)
    return technology_by_host


def collect_additional_urls(
    *,
    target: str,
    initial_urls: list[str],
    temp_path: Path,
    tools: dict[str, Path],
    run_command: RunCommand,
) -> tuple[list[str], dict[str, set[str]]]:
    """Run URL/crawl/path discovery and return in-scope candidates."""
    discovered: set[str] = {
        normalized
        for value in initial_urls
        if (normalized := normalize_url(value, target))
    }
    technologies: dict[str, set[str]] = {}

    if settings.waybackurls_enabled and "waybackurls" in tools:
        shell = (
            f"printf '%s\\n' {shlex.quote(target)} | "
            f"{shlex.quote(str(tools['waybackurls']))}"
        )
        result = run_command(
            ["/bin/bash", "-lc", shell],
            "historical URL discovery",
            300,
            continue_on_error=True,
        )
        discovered.update(urls_from_text(result.stdout, target))

    if settings.paramspider_enabled and "paramspider" in tools:
        output_file = temp_path / "parameterized-urls.txt"
        result = run_command(
            [
                str(tools["paramspider"]),
                "-d",
                target,
                "-s",
            ],
            "parameter discovery",
            420,
            continue_on_error=True,
        )
        discovered.update(urls_from_text(result.stdout, target))
        if output_file.is_file():
            discovered.update(urls_from_text(output_file.read_text(errors="replace"), target))
        for candidate in temp_path.rglob("*.txt"):
            if "param" in candidate.name.lower() or target in candidate.name.lower():
                try:
                    discovered.update(urls_from_text(candidate.read_text(errors="replace"), target))
                except OSError:
                    pass

    seed_urls = cap_urls(
        (
            root
            for value in initial_urls
            if (root := origin_url(value, target))
        ),
        100,
    )
    seed_file = temp_path / "extended-url-seeds.txt"
    seed_file.write_text("\n".join(seed_urls) + ("\n" if seed_urls else ""), encoding="utf-8")

    if settings.katana_enabled and seed_urls and "katana" in tools:
        result = run_command(
            [
                str(tools["katana"]),
                "-list",
                str(seed_file),
                "-jsonl",
                "-silent",
                "-depth",
                str(settings.katana_depth),
                "-js-crawl",
                "-known-files",
                "all",
                "-field-scope",
                "rdn",
                "-rate-limit",
                "25",
                "-max-domain-pages",
                "250",
            ],
            "application crawling",
            600,
            continue_on_error=True,
        )
        discovered.update(_parse_katana_output(result.stdout, target))

    limited_roots = cap_urls(
        (
            root
            for value in initial_urls
            if (root := origin_url(value, target))
        ),
        max(
            settings.dirsearch_max_targets,
            settings.dirb_max_targets,
            settings.dirbuster_max_targets,
            settings.wappalyzer_max_targets,
        ),
    )

    if settings.dirsearch_enabled and "dirsearch" in tools:
        for index, url in enumerate(limited_roots[: settings.dirsearch_max_targets], start=1):
            report = temp_path / f"content-discovery-{index}.json"
            run_command(
                build_dirsearch_command(
                    tools["dirsearch"],
                    url,
                    report,
                    settings.dirsearch_max_rate,
                ),
                "web content discovery",
                settings.dirsearch_timeout_seconds,
                continue_on_error=True,
            )
            discovered.update(_parse_dirsearch_report(report, target))

    if settings.dirb_enabled and "dirb" in tools:
        for url in limited_roots[: settings.dirb_max_targets]:
            result = run_command(
                [str(tools["dirb"]), url, "-S", "-r"],
                "secondary content discovery",
                300,
                continue_on_error=True,
            )
            for found_url, _, _ in _DIRB_RE.findall(result.stdout or ""):
                normalized = normalize_url(found_url, target)
                if normalized:
                    discovered.add(normalized)

    if settings.dirbuster_enabled and "dirbuster" in tools:
        wordlist = Path("/usr/local/pd_tools/src/DirBuster/directory-list-2.3-small.txt")
        if not wordlist.is_file():
            matches = list(Path("/usr/local/pd_tools/src/DirBuster").rglob("directory-list-2.3-small.txt"))
            wordlist = matches[0] if matches else wordlist
        if wordlist.is_file():
            for index, url in enumerate(limited_roots[: settings.dirbuster_max_targets], start=1):
                report = temp_path / f"legacy-content-discovery-{index}.txt"
                run_command(
                    [
                        str(tools["dirbuster"]),
                        "-H",
                        "-u",
                        url,
                        "-l",
                        str(wordlist),
                        "-g",
                        "-R",
                        "-t",
                        "5",
                        "-r",
                        str(report),
                    ],
                    "legacy content discovery",
                    600,
                    continue_on_error=True,
                )
                if report.is_file():
                    discovered.update(urls_from_text(report.read_text(errors="replace"), target))

    if settings.wappalyzer_enabled and "wappalyzer" in tools:
        for url in limited_roots[: settings.wappalyzer_max_targets]:
            result = run_command(
                [
                    str(tools["wappalyzer"]),
                    "-i",
                    url,
                    "--scan-type",
                    "fast",
                    "-oJ",
                ],
                "additional technology fingerprinting",
                90,
                continue_on_error=True,
            )
            parsed = _parse_wappalyzer_output(result.stdout, target)
            for host, names in parsed.items():
                technologies.setdefault(host, set()).update(names)

    # LazyRecon is intentionally opt-in because it is a wrapper around many of
    # the same tools and can require root/masscan. Any in-scope URLs it writes
    # are still normalized when explicitly enabled.
    if settings.lazyrecon_enabled and "lazyrecon" in tools:
        lazy_dir = temp_path / "meta-recon"
        lazy_dir.mkdir(parents=True, exist_ok=True)
        result = run_command(
            [str(tools["lazyrecon"]), target],
            "legacy meta-reconnaissance",
            settings.lazyrecon_timeout_seconds,
            continue_on_error=True,
        )
        discovered.update(urls_from_text(result.stdout, target))
        for candidate in lazy_dir.rglob("*"):
            if candidate.is_file() and candidate.stat().st_size <= 5_000_000:
                try:
                    discovered.update(urls_from_text(candidate.read_text(errors="replace"), target))
                except OSError:
                    pass

    return cap_urls(discovered, settings.max_discovered_urls), technologies

def _xssvibes_findings(
    output: str,
    parameterized_urls: list[str],
    target: str,
) -> list[dict[str, Any]]:
    """
    Parse xss_vibes stdout.

    We intentionally do not store the actual injected payload.
    """

    clean = re.sub(
        r"\x1b\[[0-9;]*m",
        "",
        output or "",
    )

    allowed = {
        normalized
        for value in parameterized_urls
        if (normalized := normalize_url(value, target))
    }

    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for match in re.finditer(
        r"VULNERABLE:\s*(https?://[^\s]+)",
        clean,
        re.IGNORECASE,
    ):
        matched_at = normalize_url(
            match.group(1),
            target,
        )

        if not matched_at:
            continue

        if matched_at not in allowed:
            continue

        if matched_at in seen:
            continue

        seen.add(matched_at)

        findings.append({
            "source": "xss_vibes",
            "title":
                "Potential reflected cross-site scripting identified",

            "description": (
                "xss_vibes reported that a generated test payload "
                "was reflected on this parameterized endpoint. "
                "Payload contents are intentionally not persisted "
                "by the ASM. Manual verification of browser "
                "execution is recommended."
            ),

            "severity": "Medium",
            "cve_id": None,
            "cvss_score": None,
            "matched_at": matched_at,
        })

    return findings
def _nikto_findings(
    payload: Any,
    base_url: str,
    target: str,
) -> list[dict[str, Any]]:
    """
    Normalize Nikto JSON findings.

    Nikto does not provide a trustworthy CVSS value for every
    observation, so unknown-severity findings remain Info.
    """

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def visit(value: Any) -> None:

        if isinstance(value, list):
            for item in value:
                visit(item)
            return

        if not isinstance(value, dict):
            return

        message = str(
            value.get("msg")
            or value.get("message")
            or value.get("description")
            or ""
        ).strip()

        uri = str(
            value.get("url")
            or value.get("uri")
            or value.get("path")
            or ""
        ).strip()

        looks_like_finding = bool(
            message
            and (
                uri
                or any(
                    key in value
                    for key in (
                        "id",
                        "osvdb",
                        "OSVDB",
                        "method",
                    )
                )
            )
        )

        if looks_like_finding:

            if uri:
                raw_match = urljoin(
                    base_url.rstrip("/") + "/",
                    uri.lstrip("/"),
                )
            else:
                raw_match = base_url

            matched_at = (
                normalize_url(raw_match, target)
                or base_url
            )

            reference_text = json.dumps(
                value.get("references")
                or value.get("refs")
                or "",
                ensure_ascii=False,
            )

            cves = sorted({
                match.upper()
                for match in _CVE_RE.findall(
                    message + " " + reference_text
                )
            })

            identity = (
                matched_at,
                message,
            )

            if identity not in seen:

                seen.add(identity)

                title_text = re.sub(
                    r"\s+",
                    " ",
                    message,
                ).strip()

                if len(title_text) > 180:
                    title_text = (
                        title_text[:177] + "..."
                    )

                findings.append({
                    "source": "nikto",
                    "title":
                        f"Nikto: {title_text}",

                    "description": message,

                    # Do not invent CVSS severity.
                    "severity": "Info",

                    "cve_id": (
                        ", ".join(cves)[:50]
                        if cves
                        else None
                    ),

                    "cvss_score": None,

                    "matched_at": matched_at,
                })

        for child in value.values():
            if isinstance(
                child,
                (dict, list),
            ):
                visit(child)

    visit(payload)

    return findings

def _wpscan_vulnerabilities(payload: Any, url: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def consume(items: Any, component: str) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or "WordPress vulnerability").strip()
            references = item.get("references") or {}
            cves: list[str] = []
            if isinstance(references, dict):
                raw_cves = references.get("cve") or []
                if isinstance(raw_cves, str):
                    raw_cves = [raw_cves]
                cves = [
                    value.upper() if str(value).upper().startswith("CVE-") else f"CVE-{value}"
                    for value in raw_cves
                    if str(value).strip()
                ]
            rows.append({
                "source": "wpscan",
                "title": title,
                "description": json.dumps({
                    "component": component,
                    "fixed_in": item.get("fixed_in"),
                    "references": references,
                    "url": url,
                }, ensure_ascii=False),
                "severity": "Info",
                "cve_id": ", ".join(cves)[:50] if cves else None,
                "cvss_score": None,
                "matched_at": url,
            })

    if not isinstance(payload, dict):
        return rows
    version = payload.get("version") or {}
    if isinstance(version, dict):
        consume(version.get("vulnerabilities"), "WordPress core")
    for key, label in (("plugins", "WordPress plugin"), ("themes", "WordPress theme")):
        components = payload.get(key) or {}
        if isinstance(components, dict):
            for name, details in components.items():
                if isinstance(details, dict):
                    consume(details.get("vulnerabilities"), f"{label}: {name}")
    main_theme = payload.get("main_theme") or {}
    if isinstance(main_theme, dict):
        consume(main_theme.get("vulnerabilities"), "WordPress active theme")
    return rows


def run_specialized_assessments(
    *,
    target: str,
    urls: list[str],
    technologies_by_host: dict[str, set[str]],
    temp_path: Path,
    tools: dict[str, Path],
    run_command: RunCommand,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, set[str]]]:
    """Run conditional CMS/XSS/secret checks.

    Returns normalized vulnerabilities, redacted secret metadata, and extra
    technology names. Missing CVSS values remain null and are never fabricated.
    """
    vulnerabilities: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    extra_technologies: dict[str, set[str]] = {}

    def technology_text(url: str) -> str:
        return " ".join(technologies_by_host.get(hostname_from(url), set())).lower()

    wordpress_urls = cap_urls(
        (
            root
            for url in urls
            if "wordpress" in technology_text(url)
            if (root := origin_url(url, target))
        ),
        settings.wpscan_max_targets,
    )
    if settings.wpscan_enabled and "wpscan" in tools:
        for index, url in enumerate(wordpress_urls, start=1):
            report = temp_path / f"cms-security-{index}.json"
            command = [
                str(tools["wpscan"]),
                "--url",
                url,
                "--format",
                "json",
                "--output",
                str(report),
                "--no-update",
                "--random-user-agent",
                "--max-threads",
                "5",
            ]
            if settings.wpscan_api_token:
                command.extend(["--api-token", settings.wpscan_api_token])
            run_command(
                command,
                "CMS security assessment",
                settings.wpscan_timeout_seconds,
                continue_on_error=True,
            )
            vulnerabilities.extend(_wpscan_vulnerabilities(parse_json_file(report), url))

    droop_targets: list[tuple[str, str]] = []
    for url in urls:
        text = technology_text(url)
        for cms in ("drupal", "joomla", "moodle", "silverstripe"):
            if cms in text:
                root = origin_url(url, target)
                if root:
                    droop_targets.append((root, cms))
                break
    if settings.droopescan_enabled and "droopescan" in tools:
        for index, (url, cms) in enumerate(
            sorted(set(droop_targets))[: settings.droopescan_max_targets],
            start=1,
        ):
            report = temp_path / f"cms-enumeration-{index}.json"
            result = run_command(
                [
                    str(tools["droopescan"]),
                    "scan",
                    cms,
                    "-u",
                    url,
                    "--output",
                    "json",
                    "--hide-progressbar",
                    "--threads",
                    "4",
                ],
                "CMS enumeration",
                settings.droopescan_timeout_seconds,
                continue_on_error=True,
            )
            payload = None
            try:
                payload = json.loads(result.stdout or "")
            except json.JSONDecodeError:
                pass
            if payload:
                host = hostname_from(url)
                extra_technologies.setdefault(host, set()).add(cms.capitalize())
                versions = payload.get("version") if isinstance(payload, dict) else None
                if isinstance(versions, dict):
                    version_values = versions.get("finds") or []
                elif isinstance(versions, list):
                    version_values = versions
                elif versions:
                    version_values = [versions]
                else:
                    version_values = []
                for version in version_values:
                    if str(version).strip():
                        extra_technologies[host].add(
                            f"{cms.capitalize()} {str(version).strip()}"
                        )
            if report.is_file():
                report.unlink(missing_ok=True)

    # XSStrike is active and disabled by default. A finding is persisted only
    # when the tool explicitly reports vulnerability-oriented output.
    parameterized_urls = [url for url in urls if parse_qsl(urlparse(url).query, keep_blank_values=True)]
    if settings.xsstrike_enabled and "xsstrike" in tools:
        for url in parameterized_urls[: settings.xsstrike_max_targets]:
            result = run_command(
                [str(tools["xsstrike"]), "-u", url, "--skip"],
                "authorized active input validation assessment",
                settings.xsstrike_timeout_seconds,
                continue_on_error=True,
            )
            combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
            if _XSS_VULNERABLE_RE.search(combined):
                excerpt = re.sub(r"\x1b\[[0-9;]*m", "", combined)[-3000:]
                vulnerabilities.append({
                    "source": "xsstrike",
                    "title": "Potential cross-site scripting identified",
                    "description": excerpt,
                    "severity": "Medium",
                    "cve_id": None,
                    "cvss_score": None,
                    "matched_at": url,
                })
    
    # ---------------------------------------------------------
    # XSS Vibes
    # ---------------------------------------------------------

    if (
        settings.xssvibes_enabled
        and "xssvibes" in tools
        and parameterized_urls
    ):

        xss_input = (
            temp_path / "xss-vibes-input.txt"
        )

        selected_xss_urls = (
            parameterized_urls[
                :settings.xssvibes_max_targets
            ]
        )

        xss_input.write_text(
            "\n".join(selected_xss_urls) + "\n",
            encoding="utf-8",
        )

        result = run_command(
            [
                str(tools["xssvibes"]),

                "-f",
                str(xss_input),

                "-t",
                str(
                    max(
                        1,
                        min(
                            10,
                            settings.xssvibes_threads,
                        ),
                    )
                ),
            ],
            "authorized reflected-XSS assessment",
             settings.xssvibes_timeout_seconds,
             continue_on_error=True,
        )

        combined = "\n".join(
            part
            for part in (
                result.stdout,
                result.stderr,
            )
            if part
        )

        vulnerabilities.extend(
            _xssvibes_findings(
                combined,
                selected_xss_urls,
                target,
            )
        )
    
    # ---------------------------------------------------------
    # Nikto
    # ---------------------------------------------------------

    if (
        settings.nikto_enabled
        and "nikto" in tools
    ):

        nikto_targets = cap_urls(
            (
                root
                for url in urls
                if (
                    root :=
                    origin_url(url, target)
                )
            ),
            settings.nikto_max_targets,
        )

        # Give Nikto enough time to exit before
        # subprocess timeout terminates it.
        per_host_maxtime = max(
            60,
            settings.nikto_timeout_seconds - 30,
        )

        for index, url in enumerate(
            nikto_targets,
            start=1,
        ):

            report = (
                temp_path /
                f"nikto-{index}.json"
            )

            run_command(
                [
                    str(tools["nikto"]),

                    "-h",
                    url,

                    "-Format",
                    "json",

                    "-output",
                    str(report),

                    "-nointeractive",

                    "-nocheck",

                    "-timeout",
                    "10",

                    "-maxtime",
                    f"{per_host_maxtime}s",
                ],

                "web server security assessment",

                settings.nikto_timeout_seconds,

                continue_on_error=True,
            )

            payload = parse_json_file(
                report
            )

            if payload is not None:

                vulnerabilities.extend(
                    _nikto_findings(
                        payload,
                        url,
                        target,
                    )
                )
    
    if settings.secretfinder_enabled and "secretfinder" in tools:
        javascript_urls = [
            url for url in urls
            if urlparse(url).path.lower().endswith((".js", ".mjs"))
        ]
        for url in javascript_urls[: settings.secretfinder_max_javascript_urls]:
            result = run_command(
                [str(tools["secretfinder"]), "-i", url, "-o", "cli"],
                "client-side secret pattern analysis",
                90,
                continue_on_error=True,
            )
            clean = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout or "")
            for line in clean.splitlines():
                line = line.strip()
                if not line or len(line) > 2000:
                    continue
                lowered = line.lower()
                if not any(token in lowered for token in ("key", "token", "secret", "authorization", "password")):
                    continue
                # Never persist the full potentially sensitive value.
                redacted = line[:8] + "…" + line[-4:] if len(line) > 16 else "[redacted]"
                secrets.append({
                    "host": hostname_from(url),
                    "secret_type": "CLIENT_SIDE_SECRET_PATTERN",
                    "location": url,
                    "redacted": redacted,
                    "confidence": 0.5,
                })
                break

    return vulnerabilities, secrets, extra_technologies
