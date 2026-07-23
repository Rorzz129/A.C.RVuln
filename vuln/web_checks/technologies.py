import re
from html import unescape
from typing import Any
from urllib.parse import urlparse

from web_checks.common import create_session, normalize_url, request
from web_checks.javascript import scan_javascript_technologies


CONFIDENCE_ORDER={
    "LOW":1,
    "MEDIUM":2,
    "HIGH":3
}


HEADER_SIGNATURES={
    "server":{
        "apache":"Apache HTTP Server",
        "nginx":"nginx",
        "microsoft-iis":"Microsoft IIS",
        "openresty":"OpenResty",
        "caddy":"Caddy",
        "cloudflare":"Cloudflare",
        "gunicorn":"Gunicorn",
        "uvicorn":"Uvicorn",
        "tomcat":"Apache Tomcat",
        "lighttpd":"lighttpd",
        "litespeed":"LiteSpeed",
        "envoy":"Envoy",
        "traefik":"Traefik"
    },
    "x-powered-by":{
        "php":"PHP",
        "asp.net":"ASP.NET",
        "express":"Express",
        "next.js":"Next.js",
        "nextjs":"Next.js",
        "nuxt":"Nuxt",
        "servlet":"Java Servlet",
        "plesk":"Plesk"
    },
    "x-generator":{
        "wordpress":"WordPress",
        "joomla":"Joomla",
        "drupal":"Drupal",
        "ghost":"Ghost"
    },
    "x-drupal-cache":{
        "hit":"Drupal",
        "miss":"Drupal"
    },
    "x-shopify-stage":{
        "production":"Shopify"
    },
    "x-wix-request-id":{
        "":"Wix"
    },
    "x-nextjs-cache":{
        "":"Next.js"
    },
    "x-vercel-cache":{
        "":"Vercel"
    },
    "x-amz-cf-id":{
        "":"Amazon CloudFront"
    }
}


COOKIE_SIGNATURES={
    "phpsessid":"PHP",
    "laravel_session":"Laravel",
    "xsrf-token":"Laravel",
    "csrftoken":"Django",
    "sessionid":"Django",
    "_rails_session":"Ruby on Rails",
    "jsessionid":"Java",
    "asp.net_sessionid":"ASP.NET",
    "connect.sid":"Express",
    "wordpress_logged_in":"WordPress",
    "wordpress_sec":"WordPress",
    "woocommerce_cart_hash":"WooCommerce",
    "woocommerce_items_in_cart":"WooCommerce",
    "prestashop":"PrestaShop",
    "magento":"Magento",
    "shopify":"Shopify"
}


HTML_SIGNATURES={
    "WordPress":[
        r"/(?:wp-content|wp-includes)/",
        r"\bwp-json\b",
        r"\bwp-emoji-release\b"
    ],
    "WooCommerce":[
        r"/wp-content/plugins/woocommerce/",
        r"\bwoocommerce-(?:page|product|cart)\b",
        r"\bwc-ajax\b"
    ],
    "Joomla":[
        r"/media/system/js/",
        r"/components/com_[a-z0-9_]+/",
        r"\bjoomla-script-options\b"
    ],
    "Drupal":[
        r"/sites/(?:default|all)/files/",
        r"\bdrupalSettings\b",
        r"\bdata-drupal-selector\b"
    ],
    "Laravel":[
        r"\blaravel_session\b",
        r'<meta[^>]+name=["\']csrf-token["\']',
        r"\bLaravel\b"
    ],
    "Django":[
        r"\bcsrfmiddlewaretoken\b",
        r"\b__admin_media_prefix__\b",
        r"/static/admin/(?:css|js)/"
    ],
    "Ruby on Rails":[
        r"\bauthenticity_token\b",
        r"\brails-ujs\b",
        r"\bturbo-rails\b"
    ],
    "React":[
        r"\bdata-reactroot\b",
        r"\b__REACT_DEVTOOLS_GLOBAL_HOOK__\b",
        r"\breact(?:\.production)?(?:\.min)?\.js\b"
    ],
    "Vue.js":[
        r"\b__VUE__\b",
        r"\bdata-v-[a-f0-9]{6,}\b",
        r"/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js"
    ],
    "Angular":[
        r'ng-version=["\'][^"\']+["\']',
        r"<app-root(?:\s|>)",
        r"\bangular(?:\.min)?\.js\b"
    ],
    "Next.js":[
        r"/_next/static/",
        r"\b__NEXT_DATA__\b",
        r"\bnext-route-announcer\b"
    ],
    "Nuxt":[
        r"/_nuxt/",
        r"\b__NUXT__\b",
        r"\bdata-n-head\b"
    ],
    "Svelte":[
        r"\bdata-svelte-h\b",
        r"/_app/immutable/"
    ],
    "Bootstrap":[
        r"\bbootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)\b"
    ],
    "jQuery":[
        r"\bjquery(?:[-.]\d+(?:\.\d+){1,3})?(?:\.min)?\.js\b"
    ],
    "Tailwind CSS":[
        r"\btailwind(?:\.min)?\.css\b",
        r"cdn\.tailwindcss\.com"
    ],
    "Font Awesome":[
        r"\bfont-?awesome(?:\.min)?\.css\b",
        r"use\.fontawesome\.com"
    ],
    "Shopify":[
        r"cdn\.shopify\.com",
        r"\bShopify\.theme\b"
    ],
    "Wix":[
        r"static\.wixstatic\.com",
        r"\bwix-code-sdk\b"
    ],
    "PrestaShop":[
        r"\bprestashop\b",
        r"/themes/[^/]+/assets/"
    ],
    "Magento":[
        r"\bMagento_[A-Za-z]+\b",
        r"/static/version\d+/frontend/",
        r"\bmage/cookies\b"
    ],
    "Ghost":[
        r"\bghost-url\b",
        r"/ghost/assets/"
    ],
    "Google Analytics":[
        r"googletagmanager\.com/gtag/js",
        r"google-analytics\.com/analytics\.js"
    ],
    "Google Tag Manager":[
        r"googletagmanager\.com/gtm\.js"
    ],
    "Cloudflare":[
        r"cdnjs\.cloudflare\.com",
        r"\b__cf_bm\b",
        r"/cdn-cgi/"
    ],
    "Vercel":[
        r"\bvercel\.app\b",
        r"/_vercel/"
    ],
    "Amazon CloudFront":[
        r"\bcloudfront\.net\b"
    ],
    "Alpine.js":[
        r"\balpine(?:\.min)?\.js\b",
        r"\bx-data(?:=|\s)"
    ],
    "HTMX":[
        r"\bhtmx(?:\.min)?\.js\b",
        r"\bhx-(?:get|post|put|delete|trigger)\b"
    ]
}


VERSION_PATTERNS={
    "WordPress":[
        r"WordPress\s*([0-9]+(?:\.[0-9]+){1,3})",
        r"(?:wp-includes|wp-content)/[^\"']+[?&]ver=([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "WooCommerce":[
        r"woocommerce[^\"']+[?&]ver=([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Joomla":[
        r"Joomla!?[^0-9]{0,20}([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Drupal":[
        r"Drupal\s*([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Angular":[
        r'ng-version=["\']([0-9]+(?:\.[0-9]+){1,3})["\']',
        r"angular[-.@]([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Bootstrap":[
        r"bootstrap(?:\.bundle)?[-.@]([0-9]+(?:\.[0-9]+){1,3})",
        r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)\?[^\"']*(?:ver|v)=([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "jQuery":[
        r"jquery[-.@]([0-9]+(?:\.[0-9]+){1,3})",
        r"jquery(?:\.min)?\.js\?[^\"']*(?:ver|v)=([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "React":[
        r"react(?:\.production)?(?:\.min)?\.js\?[^\"']*(?:ver|v)=([0-9]+(?:\.[0-9]+){1,3})",
        r"react@([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Vue.js":[
        r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js\?[^\"']*(?:ver|v)=([0-9]+(?:\.[0-9]+){1,3})",
        r"vue@([0-9]+(?:\.[0-9]+){1,3})",
        r"vue[-.]([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Next.js":[
        r"next@([0-9]+(?:\.[0-9]+){1,3})",
        r"next[-.]([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Nuxt":[
        r"nuxt@([0-9]+(?:\.[0-9]+){1,3})",
        r"nuxt[-.]([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Font Awesome":[
        r"font-?awesome[-.@]([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "Alpine.js":[
        r"alpine(?:js)?[-.@]([0-9]+(?:\.[0-9]+){1,3})"
    ],
    "HTMX":[
        r"htmx[-.@]([0-9]+(?:\.[0-9]+){1,3})"
    ]
}


def clean_version(version:Any)->str|None:
    if version is None:
        return None

    value=str(version).strip()

    if not value:
        return None

    value=value.strip(" /()[]{};,")
    value=re.sub(r"^[vV]","",value)

    match=re.match(
        r"^([0-9]+(?:\.[0-9A-Za-z_-]+){0,4})",
        value
    )

    if not match:
        return None

    return match.group(1)


def extract_version(value:str)->str|None:
    if not value:
        return None

    patterns=[
        r"(?<![A-Za-z0-9])v?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})(?![A-Za-z0-9])",
        r"/([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})",
        r"\bversion[=/:\s-]+([0-9]+\.[0-9]+(?:\.[0-9]+){0,2})"
    ]

    for pattern in patterns:
        match=re.search(
            pattern,
            value,
            re.IGNORECASE
        )

        if match:
            return clean_version(
                match.group(1)
            )

    return None


def normalize_evidence(evidence:Any)->list[str]:
    if isinstance(evidence,list):
        values=evidence

    elif evidence:
        values=[str(evidence)]

    else:
        values=[]

    results=[]

    for value in values:
        value=str(value).strip()

        if value and value not in results:
            results.append(value)

    return results


def add_technology(
    technologies:dict[str,dict[str,Any]],
    name:str,
    version:str|None,
    evidence:str,
    confidence:str,
    port:int|None,
    source:str="web"
)->None:
    name=str(name or "").strip()

    if not name:
        return

    confidence=str(
        confidence or "LOW"
    ).upper()

    if confidence not in CONFIDENCE_ORDER:
        confidence="LOW"

    version=clean_version(version)
    key=name.casefold()

    candidate={
        "name":name,
        "version":version,
        "port":port,
        "source":source,
        "confidence":confidence,
        "evidence":[evidence] if evidence else []
    }

    current=technologies.get(key)

    if current is None:
        technologies[key]=candidate
        return

    current_evidence=normalize_evidence(
        current.get("evidence")
    )

    for item in candidate["evidence"]:
        if item not in current_evidence:
            current_evidence.append(item)

    current["evidence"]=current_evidence

    current_version=clean_version(
        current.get("version")
    )

    if version and not current_version:
        current["version"]=version

    elif (
        version
        and current_version
        and version!=current_version
    ):
        alternate_versions=current.setdefault(
            "alternate_versions",
            []
        )

        if version not in alternate_versions:
            alternate_versions.append(version)

    current_confidence=CONFIDENCE_ORDER.get(
        str(
            current.get("confidence") or "LOW"
        ).upper(),
        0
    )

    candidate_confidence=CONFIDENCE_ORDER.get(
        confidence,
        0
    )

    if candidate_confidence>current_confidence:
        current["confidence"]=confidence

    if (
        current.get("port") is None
        and port is not None
    ):
        current["port"]=port

    current_source=str(
        current.get("source") or ""
    )

    if source and source not in current_source.split(","):
        sources=[
            item.strip()
            for item in current_source.split(",")
            if item.strip()
        ]

        if source not in sources:
            sources.append(source)

        current["source"]=",".join(sources)


def detect_headers(
    technologies:dict[str,dict[str,Any]],
    headers:dict[str,str],
    port:int|None
)->None:
    normalized={
        str(key).lower():str(value)
        for key,value in headers.items()
    }

    for header,signatures in HEADER_SIGNATURES.items():
        value=normalized.get(header)

        if value is None:
            continue

        lowered=value.lower()

        for signature,name in signatures.items():
            if signature and signature not in lowered:
                continue

            version=extract_version(value)

            add_technology(
                technologies,
                name,
                version,
                f"{header}: {value}",
                "HIGH",
                port,
                "header"
            )


def detect_cookies(
    technologies:dict[str,dict[str,Any]],
    response:Any,
    port:int|None
)->None:
    cookie_names={
        str(cookie.name).lower()
        for cookie in response.cookies
    }

    raw_cookie_header=str(
        response.headers.get(
            "Set-Cookie",
            ""
        )
    ).lower()

    for signature,name in COOKIE_SIGNATURES.items():
        matched=False

        for cookie_name in cookie_names:
            if (
                cookie_name==signature
                or cookie_name.startswith(signature)
            ):
                matched=True
                break

        if not matched and signature in raw_cookie_header:
            matched=True

        if matched:
            add_technology(
                technologies,
                name,
                None,
                f"Cookie detected: {signature}",
                "MEDIUM",
                port,
                "cookie"
            )


def detect_meta_generator(
    technologies:dict[str,dict[str,Any]],
    html:str,
    port:int|None
)->None:
    patterns=[
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']'
    ]

    known_technologies={
        "wordpress":"WordPress",
        "joomla":"Joomla",
        "drupal":"Drupal",
        "ghost":"Ghost",
        "prestashop":"PrestaShop",
        "magento":"Magento",
        "shopify":"Shopify"
    }

    for pattern in patterns:
        matches=re.finditer(
            pattern,
            html,
            re.IGNORECASE
        )

        for match in matches:
            value=match.group(1).strip()
            lowered=value.casefold()

            for signature,name in known_technologies.items():
                if signature not in lowered:
                    continue

                add_technology(
                    technologies,
                    name,
                    extract_version(value),
                    f"Meta generator: {value}",
                    "HIGH",
                    port,
                    "meta"
                )


def detect_html(
    technologies:dict[str,dict[str,Any]],
    html:str,
    port:int|None
)->None:
    decoded=unescape(html)

    for name,patterns in HTML_SIGNATURES.items():
        detected_match=None

        for pattern in patterns:
            detected_match=re.search(
                pattern,
                decoded,
                re.IGNORECASE
            )

            if detected_match:
                break

        if not detected_match:
            continue

        version=None

        for version_pattern in VERSION_PATTERNS.get(
            name,
            []
        ):
            version_match=re.search(
                version_pattern,
                decoded,
                re.IGNORECASE
            )

            if version_match:
                version=clean_version(
                    version_match.group(1)
                )
                break

        evidence=detected_match.group(0)

        if len(evidence)>160:
            evidence=evidence[:157]+"..."

        confidence=(
            "HIGH"
            if version
            else "MEDIUM"
        )

        add_technology(
            technologies,
            name,
            version,
            f"HTML signature: {evidence}",
            confidence,
            port,
            "html"
        )


def detect_script_sources(
    technologies:dict[str,dict[str,Any]],
    html:str,
    port:int|None
)->None:
    script_sources=re.findall(
        r'<script[^>]+src=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE
    )

    stylesheet_sources=re.findall(
        r'<link[^>]+href=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE
    )

    resources=script_sources+stylesheet_sources

    resource_signatures={
        "jquery":"jQuery",
        "bootstrap":"Bootstrap",
        "react":"React",
        "vue":"Vue.js",
        "angular":"Angular",
        "fontawesome":"Font Awesome",
        "font-awesome":"Font Awesome",
        "tailwind":"Tailwind CSS",
        "alpine":"Alpine.js",
        "htmx":"HTMX",
        "_next":"Next.js",
        "_nuxt":"Nuxt"
    }

    for resource in resources:
        lowered=resource.lower()

        for signature,name in resource_signatures.items():
            if signature not in lowered:
                continue

            version=None

            for version_pattern in VERSION_PATTERNS.get(
                name,
                []
            ):
                version_match=re.search(
                    version_pattern,
                    resource,
                    re.IGNORECASE
                )

                if version_match:
                    version=clean_version(
                        version_match.group(1)
                    )
                    break

            if version is None:
                version=extract_version(resource)

            add_technology(
                technologies,
                name,
                version,
                f"Resource: {resource[:200]}",
                "HIGH" if version else "MEDIUM",
                port,
                "resource"
            )


def detect_web_technologies(
    url:str,
    verbose:bool=True
)->list[dict[str,Any]]:
    normalized_url=normalize_url(url)
    session=create_session()

    try:
        response=request(
            session,
            "GET",
            normalized_url
        )

        parsed=urlparse(response.url)

        port=(
            parsed.port
            or (
                443
                if parsed.scheme=="https"
                else 80
            )
        )

        technologies={}

        detect_headers(
            technologies,
            dict(response.headers),
            port
        )

        detect_cookies(
            technologies,
            response,
            port
        )

        content_type=str(
            response.headers.get(
                "Content-Type",
                ""
            )
        ).lower()

        if (
            "text/html" in content_type
            or not content_type
        ):
            html = response.text[:3_000_000]

            detect_meta_generator(
                technologies,
                html,
                port
            )

            detect_html(
                technologies,
                html,
                port
            )

            detect_script_sources(
                technologies,
                html,
                port
            )

            javascript_technologies = scan_javascript_technologies(
                session=session,
                html=html,
                base_url=response.url,
                port=port,
            )

            for technology in javascript_technologies:
                evidence = technology.get(
                    "evidence",
                    []
                )

                if isinstance(evidence, str):
                    evidence = [evidence]

                if not evidence:
                    evidence = [
                        "Technology detected in JavaScript"
                    ]

                for index, evidence_item in enumerate(evidence):
                    add_technology(
                        technologies=technologies,
                        name=technology.get(
                            "name",
                            "Unknown",
                        ),
                        version=technology.get(
                            "version",
                        ),
                        evidence=evidence_item,
                        confidence=technology.get(
                            "confidence",
                            "MEDIUM",
                        ),
                        port=technology.get(
                            "port",
                            port,
                        ),
                        source=technology.get(
                            "source",
                            "javascript",
                        ),
                    )

    finally:
        session.close()

    results=sorted(
        technologies.values(),
        key=lambda technology:(
            -CONFIDENCE_ORDER.get(
                technology.get(
                    "confidence",
                    "LOW"
                ),
                0
            ),
            technology.get(
                "name",
                ""
            ).casefold()
        )
    )

    if verbose:
        print(
            f"[+] Web technologies detected: "
            f"{len(results)}"
        )

        for technology in results:
            version=(
                technology.get("version")
                or "Unknown"
            )

            confidence=technology.get(
                "confidence",
                "LOW"
            )

            print(
                f"[+] {technology['name']} "
                f"{version} "
                f"({confidence})"
            )

    return results


if __name__=="__main__":
    target_url=input(
        "URL: "
    ).strip()

    for detected_technology in detect_web_technologies(
        target_url
    ):
        print(
            detected_technology
        )