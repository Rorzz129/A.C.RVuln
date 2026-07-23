from typing import Any
from web_checks.common import create_session,make_finding,normalize_url,request

INTERESTING_METHODS={
    "TRACE":{
        "id":"WEB-METHOD-001",
        "title":"HTTP TRACE method appears enabled",
        "severity":"MEDIUM",
        "recommendation":"Disable TRACE unless it is explicitly required."
    },
    "PUT":{
        "id":"WEB-METHOD-002",
        "title":"HTTP PUT method advertised",
        "severity":"INFO",
        "recommendation":"Ensure PUT endpoints require authentication and authorization."
    },
    "DELETE":{
        "id":"WEB-METHOD-003",
        "title":"HTTP DELETE method advertised",
        "severity":"INFO",
        "recommendation":"Ensure DELETE endpoints require authentication and authorization."
    },
    "CONNECT":{
        "id":"WEB-METHOD-004",
        "title":"HTTP CONNECT method advertised",
        "severity":"MEDIUM",
        "recommendation":"Disable CONNECT unless the server is intentionally operating as a proxy."
    }
}

def parse_allowed_methods(response:Any)->set[str]:
    methods=set()
    allow=response.headers.get("Allow","")
    cors_allow=response.headers.get("Access-Control-Allow-Methods","")
    for value in(allow,cors_allow):
        for method in value.split(","):
            method=method.strip().upper()
            if method:
                methods.add(method)
    return methods

def check_http_methods(url:str)->list[dict[str,Any]]:
    url=normalize_url(url)
    session=create_session()
    findings=[]
    try:
        response=request(
            session,
            "OPTIONS",
            url,
            headers={
                "Origin":"https://vulnscope.invalid",
                "Access-Control-Request-Method":"DELETE"
            }
        )
    finally:
        session.close()
    methods=parse_allowed_methods(response)
    for method,rule in INTERESTING_METHODS.items():
        if method not in methods:
            continue
        findings.append(
            make_finding(
                rule["id"],
                rule["title"],
                rule["severity"],
                "HTTP Methods",
                response.url,
                f"The server advertised the {method} method.",
                rule["recommendation"],
                "MEDIUM"
            )
        )
    return findings

if __name__=="__main__":
    for finding in check_http_methods("https://example.com"):
        print(finding)