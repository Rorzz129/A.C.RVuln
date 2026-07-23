from typing import Any
from web_checks.common import create_session,make_finding,normalize_url,request

HEADER_RULES={
    "Content-Security-Policy":{
        "id":"WEB-HEADER-001",
        "title":"Content-Security-Policy header missing",
        "severity":"MEDIUM",
        "recommendation":"Add a restrictive Content-Security-Policy header."
    },
    "Strict-Transport-Security":{
        "id":"WEB-HEADER-002",
        "title":"Strict-Transport-Security header missing",
        "severity":"MEDIUM",
        "https_only":True,
        "recommendation":"Enable HSTS with an appropriate max-age value."
    },
    "X-Content-Type-Options":{
        "id":"WEB-HEADER-003",
        "title":"X-Content-Type-Options header missing",
        "severity":"LOW",
        "recommendation":"Set X-Content-Type-Options to nosniff."
    },
    "X-Frame-Options":{
        "id":"WEB-HEADER-004",
        "title":"Clickjacking protection header missing",
        "severity":"LOW",
        "alternative":"Content-Security-Policy",
        "recommendation":"Set X-Frame-Options or use CSP frame-ancestors."
    },
    "Referrer-Policy":{
        "id":"WEB-HEADER-005",
        "title":"Referrer-Policy header missing",
        "severity":"LOW",
        "recommendation":"Define a restrictive Referrer-Policy."
    },
    "Permissions-Policy":{
        "id":"WEB-HEADER-006",
        "title":"Permissions-Policy header missing",
        "severity":"LOW",
        "recommendation":"Restrict unnecessary browser features with Permissions-Policy."
    }
}

def check_security_headers(url:str)->list[dict[str,Any]]:
    url=normalize_url(url)
    session=create_session()
    findings=[]
    try:
        response=request(session,"GET",url)
    finally:
        session.close()
    headers={key.lower():value for key,value in response.headers.items()}
    for header,rule in HEADER_RULES.items():
        if rule.get("https_only")and not response.url.startswith("https://"):
            continue
        header_key=header.lower()
        alternative=str(rule.get("alternative","")).lower()
        if header_key in headers:
            continue
        if alternative and alternative in headers:
            if header=="X-Frame-Options":
                csp=headers[alternative].lower()
                if"frame-ancestors" in csp:
                    continue
        findings.append(
            make_finding(
                rule["id"],
                rule["title"],
                rule["severity"],
                "Security Headers",
                response.url,
                f"HTTP response does not contain the {header} header.",
                rule["recommendation"]
            )
        )
    server=response.headers.get("Server")
    if server:
        findings.append(
            make_finding(
                "WEB-HEADER-007",
                "Server software information disclosed",
                "INFO",
                "Information Disclosure",
                response.url,
                f"Server: {server}",
                "Remove unnecessary software and version information from HTTP headers.",
                "HIGH"
            )
        )
    powered_by=response.headers.get("X-Powered-By")
    if powered_by:
        findings.append(
            make_finding(
                "WEB-HEADER-008",
                "Application technology disclosed",
                "LOW",
                "Information Disclosure",
                response.url,
                f"X-Powered-By: {powered_by}",
                "Remove the X-Powered-By header when it is not required.",
                "HIGH"
            )
        )
    return findings

if __name__=="__main__":
    for finding in check_security_headers("https://example.com"):
        print(finding)