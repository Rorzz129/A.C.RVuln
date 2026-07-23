import re
from typing import Any
from urllib.parse import urljoin, urlparse


MAX_SCRIPTS = 15
MAX_SCRIPT_SIZE = 1_500_000
REQUEST_TIMEOUT = 8


TECHNOLOGY_PATTERNS = {
    "Vue.js": [
        r"\bVue\.version\s*=\s*[\"']([^\"']+)[\"']",
        r"\bversion\s*:\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]",
        r"\bvue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js\b",
        r"\b__VUE__\b",
        r"\bcreateApp\s*\(",
    ],
    "Nuxt": [
        r"\b__NUXT__\b",
        r"\b__NUXT_DATA__\b",
        r"\bnuxtApp\b",
        r"\bdefineNuxtPlugin\b",
        r"\buseNuxtApp\b",
        r"/_nuxt/",
    ],
    "React": [
        r"\bReact\.version\s*=\s*[\"']([^\"']+)[\"']",
        r"\breact(?:\.production)?(?:\.min)?\.js\b",
        r"\bcreateElement\s*\(",
        r"\bcreateRoot\s*\(",
        r"\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b",
    ],
    "Next.js": [
        r"\b__NEXT_DATA__\b",
        r"\bnext/router\b",
        r"\bnext/navigation\b",
        r"/_next/static/",
    ],
    "Angular": [
        r"\bVERSION\s*=\s*new\s+Version\([\"']([^\"']+)[\"']\)",
        r"\bngVersion\b",
        r"\bplatformBrowserDynamic\b",
        r"\bɵɵdefineComponent\b",
    ],
    "jQuery": [
        r"\bjQuery\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bjQuery\.fn\.jquery\s*=\s*[\"']([^\"']+)[\"']",
        r"\bjquery(?:[-.][0-9.]+)?(?:\.min)?\.js\b",
    ],
    "Axios": [
        r"\baxios\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\baxios\.VERSION\s*=\s*[\"']([^\"']+)[\"']",
        r"\baxios(?:\.min)?\.js\b",
    ],
    "Bootstrap": [
        r"\bBootstrap\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bbootstrap(?:\.bundle)?(?:\.min)?\.js\b",
    ],
    "Lodash": [
        r"\bVERSION\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\blodash(?:\.min)?\.js\b",
        r"\b_.templateSettings\b",
    ],
    "Moment.js": [
        r"\bversion\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\bmoment(?:\.min)?\.js\b",
        r"\bmoment\.utc\b",
    ],
    "Webpack": [
        r"\bwebpackJsonp\b",
        r"\b__webpack_require__\b",
        r"\bwebpackChunk[a-zA-Z0-9_$]*\b",
    ],
    "Svelte": [
        r"\bSvelteComponent\b",
        r"\bcreate_component\b",
        r"\binit\s*\(\s*this\s*,",
        r"\bdata-svelte-h\b",
    ],
    "Alpine.js": [
        r"\bAlpine\.version\s*=\s*[\"']([^\"']+)[\"']",
        r"\bAlpine\.start\s*\(",
        r"\balpine(?:\.min)?\.js\b",
    ],
    "HTMX": [
        r"\bhtmx\.version\s*=\s*[\"']([^\"']+)[\"']",
        r"\bhtmx(?:\.min)?\.js\b",
        r"\bhx-trigger\b",
    ],
}


VERSION_PATTERNS = {
    "Vue.js": [
        r"\bVue\.version\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\bvue@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bvue[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Nuxt": [
        r"\bNuxt\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bnuxt@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bnuxt[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "React": [
        r"\bReact\.version\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\breact@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\breact[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Next.js": [
        r"\bNext\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bnext@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bnext[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Angular": [
        r"\bVERSION\s*=\s*new\s+Version\([\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']\)",
        r"\bAngular\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "jQuery": [
        r"\bjQuery\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bjQuery\.fn\.jquery\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\bjquery[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Axios": [
        r"\baxios\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\baxios\.VERSION\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\baxios@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Bootstrap": [
        r"\bBootstrap\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bbootstrap[-.]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Lodash": [
        r"\bLodash\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\blodash@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Moment.js": [
        r"\bMoment\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        r"\bmoment@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "Alpine.js": [
        r"\bAlpine\.version\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\balpinejs@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
    "HTMX": [
        r"\bhtmx\.version\s*=\s*[\"']([0-9]+\.[0-9]+(?:\.[0-9]+)?)[\"']",
        r"\bhtmx@([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ],
}


def clean_version(version: Any) -> str | None:
    if version is None:
        return None

    value = str(version).strip()
    value = value.lstrip("vV")

    match = re.match(
        r"^([0-9]+(?:\.[0-9A-Za-z_-]+){1,4})",
        value,
    )

    if not match:
        return None

    return match.group(1)


def extract_script_sources(html: str, base_url: str) -> list[str]:
    sources = re.findall(
        r"<script[^>]+src=[\"']([^\"']+)[\"']",
        html,
        re.IGNORECASE,
    )

    results = []

    for source in sources:
        source = source.strip()

        if not source:
            continue

        full_url = urljoin(base_url, source)
        parsed = urlparse(full_url)

        if parsed.scheme not in {"http", "https"}:
            continue

        if full_url not in results:
            results.append(full_url)

        if len(results) >= MAX_SCRIPTS:
            break

    return results


def extract_version(
    technology: str,
    content: str,
    script_url: str,
) -> str | None:
    searchable = f"{script_url}\n{content}"

    for pattern in VERSION_PATTERNS.get(technology, []):
        match = re.search(
            pattern,
            searchable,
            re.IGNORECASE,
        )

        if match:
            return clean_version(match.group(1))

    return None


def detect_source_map(
    content: str,
    script_url: str,
) -> str | None:
    match = re.search(
        r"//#\s*sourceMappingURL\s*=\s*([^\s]+)",
        content,
        re.IGNORECASE,
    )

    if not match:
        match = re.search(
            r"/\*#\s*sourceMappingURL\s*=\s*([^\s*]+)",
            content,
            re.IGNORECASE,
        )

    if not match:
        return None

    source_map = match.group(1).strip()
    return urljoin(script_url, source_map)


def analyze_script(
    script_url: str,
    content: str,
) -> list[dict[str, Any]]:
    results = []

    for technology, patterns in TECHNOLOGY_PATTERNS.items():
        matched_pattern = None
        matched_value = None

        for pattern in patterns:
            match = re.search(
                pattern,
                content,
                re.IGNORECASE,
            )

            if match:
                matched_pattern = pattern
                matched_value = match.group(0)
                break

        if not matched_pattern:
            continue

        version = extract_version(
            technology,
            content,
            script_url,
        )

        evidence = matched_value or matched_pattern

        if len(evidence) > 160:
            evidence = evidence[:157] + "..."

        results.append(
            {
                "name": technology,
                "version": version,
                "source": "javascript",
                "confidence": "HIGH" if version else "MEDIUM",
                "evidence": [
                    f"JavaScript: {script_url}",
                    f"Signature: {evidence}",
                ],
            }
        )

    source_map = detect_source_map(
        content,
        script_url,
    )

    if source_map:
        results.append(
            {
                "name": "JavaScript Source Map",
                "version": None,
                "source": "javascript",
                "confidence": "HIGH",
                "evidence": [
                    f"Source map referenced: {source_map}",
                ],
                "metadata": {
                    "source_map_url": source_map,
                },
            }
        )

    return results


def merge_javascript_results(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged = {}

    confidence_order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    for result in results:
        name = str(result.get("name") or "").strip()

        if not name:
            continue

        key = name.casefold()
        current = merged.get(key)

        if current is None:
            merged[key] = result.copy()
            merged[key]["evidence"] = list(
                result.get("evidence") or []
            )
            continue

        current_version = current.get("version")
        new_version = result.get("version")

        if new_version and not current_version:
            current["version"] = new_version

        current_confidence = str(
            current.get("confidence") or "LOW"
        ).upper()

        new_confidence = str(
            result.get("confidence") or "LOW"
        ).upper()

        if confidence_order.get(
            new_confidence,
            0,
        ) > confidence_order.get(
            current_confidence,
            0,
        ):
            current["confidence"] = new_confidence

        current_evidence = current.setdefault(
            "evidence",
            [],
        )

        for evidence in result.get("evidence") or []:
            if evidence not in current_evidence:
                current_evidence.append(evidence)

        if result.get("metadata"):
            current_metadata = current.setdefault(
                "metadata",
                {},
            )

            current_metadata.update(
                result["metadata"]
            )

    return list(merged.values())


def scan_javascript_technologies(
    session: Any,
    html: str,
    base_url: str,
    port: int | None = None,
) -> list[dict[str, Any]]:
    script_urls = extract_script_sources(
        html,
        base_url,
    )

    detections = []

    for script_url in script_urls:
        try:
            response = session.get(
                script_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={
                    "Accept": (
                        "application/javascript,"
                        "text/javascript,"
                        "*/*;q=0.8"
                    )
                },
            )
        except Exception:
            continue

        if response.status_code >= 400:
            continue

        content_type = str(
            response.headers.get(
                "Content-Type",
                "",
            )
        ).lower()

        valid_content_type = (
            "javascript" in content_type
            or "ecmascript" in content_type
            or script_url.lower().split("?")[0].endswith(".js")
        )

        if not valid_content_type:
            continue

        content_length = response.headers.get(
            "Content-Length"
        )

        if content_length:
            try:
                if int(content_length) > MAX_SCRIPT_SIZE:
                    continue
            except ValueError:
                pass

        raw_content = response.content

        if len(raw_content) > MAX_SCRIPT_SIZE:
            raw_content = raw_content[:MAX_SCRIPT_SIZE]

        try:
            content = raw_content.decode(
                response.encoding or "utf-8",
                errors="replace",
            )
        except Exception:
            content = raw_content.decode(
                "utf-8",
                errors="replace",
            )

        script_results = analyze_script(
            response.url,
            content,
        )

        for result in script_results:
            result["port"] = port

        detections.extend(script_results)

    return merge_javascript_results(
        detections
    )