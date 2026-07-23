from typing import Any
from urllib.parse import urljoin
from web_checks.common import create_session,get_origin,make_finding,normalize_url,request

PATH_RULES={
    "/.env":{
        "id":"WEB-PATH-001",
        "title":"Potential environment file exposure",
        "severity":"HIGH",
        "signatures":("APP_KEY=","DB_PASSWORD=","DATABASE_URL=","SECRET_KEY="),
        "recommendation":"Remove environment files from the public web root and deny access."
    },
    "/.git/HEAD":{
        "id":"WEB-PATH-002",
        "title":"Potential Git repository exposure",
        "severity":"HIGH",
        "signatures":("ref: refs/heads/","ref: refs/"),
        "recommendation":"Remove the .git directory from the public web root and deny access."
    },
    "/phpinfo.php":{
        "id":"WEB-PATH-003",
        "title":"PHP information page exposed",
        "severity":"MEDIUM",
        "signatures":("phpinfo()","PHP Version"),
        "recommendation":"Remove publicly accessible phpinfo pages."
    },
    "/server-status":{
        "id":"WEB-PATH-004",
        "title":"Server status page exposed",
        "severity":"MEDIUM",
        "signatures":("Apache Server Status","Server Version:"),
        "recommendation":"Restrict the server-status endpoint to authorized administrators."
    },
    "/swagger.json":{
        "id":"WEB-PATH-005",
        "title":"Swagger API specification exposed",
        "severity":"INFO",
        "signatures":('"swagger"','"paths"'),
        "recommendation":"Review whether public API documentation is intended."
    },
    "/openapi.json":{
        "id":"WEB-PATH-006",
        "title":"OpenAPI specification exposed",
        "severity":"INFO",
        "signatures":('"openapi"','"paths"'),
        "recommendation":"Review whether public API documentation is intended."
    },
    "/api-docs":{
        "id":"WEB-PATH-007",
        "title":"API documentation endpoint discovered",
        "severity":"INFO",
        "signatures":("swagger","openapi","api documentation"),
        "recommendation":"Ensure exposed API documentation contains no sensitive internal details."
    },
    "/robots.txt":{
        "id":"WEB-PATH-008",
        "title":"Robots file discovered",
        "severity":"INFO",
        "signatures":("User-agent:","Disallow:"),
        "recommendation":"Review robots.txt for sensitive or administrative paths."
    },
    "/security.txt":{
        "id":"WEB-PATH-009",
        "title":"Security contact file discovered",
        "severity":"INFO",
        "signatures":("Contact:","Expires:","Policy:"),
        "recommendation":"Keep the security contact information current."
    }
}

def body_matches(body:str,signatures:tuple[str,...])->bool:
    lowered=body.lower()
    return any(signature.lower()in lowered for signature in signatures)

def looks_like_soft_404(status_code:int,body:str,baseline_body:str)->bool:
    if status_code==404:
        return True
    if not body:
        return True
    normalized=body.strip()
    baseline=baseline_body.strip()
    if baseline and normalized==baseline:
        return True
    return False

def check_sensitive_paths(url:str)->list[dict[str,Any]]:
    url=normalize_url(url)
    origin=get_origin(url)
    session=create_session()
    findings=[]
    try:
        random_url=urljoin(origin,"/__vulnscope_not_found_9f8a7b6c")
        try:
            baseline_response=request(session,"GET",random_url)
            baseline_body=baseline_response.text[:20000]
        except Exception:
            baseline_body=""
        for path,rule in PATH_RULES.items():
            target=urljoin(origin,path)
            try:
                response=request(session,"GET",target)
            except Exception:
                continue
            body=response.text[:20000]
            if response.status_code not in{200,206}:
                continue
            if looks_like_soft_404(response.status_code,body,baseline_body):
                continue
            if not body_matches(body,rule["signatures"]):
                continue
            evidence=f"{target} returned HTTP {response.status_code} and matched an expected content signature."
            findings.append(
                make_finding(
                    rule["id"],
                    rule["title"],
                    rule["severity"],
                    "Sensitive Paths",
                    target,
                    evidence,
                    rule["recommendation"],
                    "HIGH"
                )
            )
    finally:
        session.close()
    return findings

if __name__=="__main__":
    for finding in check_sensitive_paths("https://example.com"):
        print(finding)