from typing import Any
from urllib.parse import urlparse
import requests

DEFAULT_TIMEOUT=10
USER_AGENT="VulnScope/1.0 Security Scanner"
SEVERITY_ORDER={
    "CRITICAL":5,
    "HIGH":4,
    "MEDIUM":3,
    "LOW":2,
    "INFO":1,
    "UNKNOWN":0
}

def normalize_url(url:Any)->str:
    value=str(url or "").strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if not value.startswith(("http://","https://")):
        value=f"https://{value}"
    parsed=urlparse(value)
    if not parsed.hostname:
        raise ValueError("Invalid URL")
    return value

def get_origin(url:str)->str:
    parsed=urlparse(normalize_url(url))
    default_port=443 if parsed.scheme=="https" else 80
    port=parsed.port
    if port and port!=default_port:
        return f"{parsed.scheme}://{parsed.hostname}:{port}"
    return f"{parsed.scheme}://{parsed.hostname}"

def create_session()->requests.Session:
    session=requests.Session()
    session.headers.update({
        "User-Agent":USER_AGENT,
        "Accept":"text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
    })
    return session

def request(
    session:requests.Session,
    method:str,
    url:str,
    **kwargs:Any
)->requests.Response:
    kwargs.setdefault("timeout",DEFAULT_TIMEOUT)
    kwargs.setdefault("allow_redirects",True)
    return session.request(method,url,**kwargs)

def make_finding(
    finding_id:str,
    title:str,
    severity:str,
    category:str,
    url:str,
    evidence:str,
    recommendation:str,
    confidence:str="HIGH"
)->dict[str,Any]:
    severity=str(severity or "UNKNOWN").upper()
    confidence=str(confidence or "UNKNOWN").upper()
    return{
        "id":finding_id,
        "title":title,
        "severity":severity,
        "confidence":confidence,
        "category":category,
        "url":url,
        "evidence":evidence,
        "recommendation":recommendation
    }

def deduplicate_findings(findings:list[dict[str,Any]])->list[dict[str,Any]]:
    results=[]
    seen=set()
    for finding in findings:
        if not isinstance(finding,dict):
            continue
        key=(
            str(finding.get("id","")).upper(),
            str(finding.get("url","")),
            str(finding.get("evidence",""))
        )
        if key in seen:
            continue
        seen.add(key)
        results.append(finding)
    return results

def sort_findings(findings:list[dict[str,Any]])->list[dict[str,Any]]:
    return sorted(
        findings,
        key=lambda finding:(
            SEVERITY_ORDER.get(
                str(finding.get("severity","UNKNOWN")).upper(),
                0
            ),
            str(finding.get("title",""))
        ),
        reverse=True
    )