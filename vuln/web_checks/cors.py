from typing import Any
from web_checks.common import create_session,make_finding,normalize_url,request

TEST_ORIGIN="https://vulnscope.invalid"

def check_cors(url:str)->list[dict[str,Any]]:
    url=normalize_url(url)
    session=create_session()
    findings=[]
    try:
        response=request(
            session,
            "GET",
            url,
            headers={"Origin":TEST_ORIGIN}
        )
    finally:
        session.close()
    allow_origin=response.headers.get("Access-Control-Allow-Origin","").strip()
    allow_credentials=response.headers.get(
        "Access-Control-Allow-Credentials",
        ""
    ).strip().lower()
    if not allow_origin:
        return findings
    if allow_origin=="*"and allow_credentials=="true":
        findings.append(
            make_finding(
                "WEB-CORS-001",
                "Wildcard CORS policy used with credentials",
                "HIGH",
                "CORS",
                response.url,
                "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true",
                "Use an explicit allowlist of trusted origins.",
                "HIGH"
            )
        )
    elif allow_origin==TEST_ORIGIN and allow_credentials=="true":
        findings.append(
            make_finding(
                "WEB-CORS-002",
                "Arbitrary CORS origin reflected with credentials",
                "HIGH",
                "CORS",
                response.url,
                f"The server reflected the supplied Origin {TEST_ORIGIN} and allowed credentials.",
                "Validate origins against an explicit trusted allowlist.",
                "HIGH"
            )
        )
    elif allow_origin==TEST_ORIGIN:
        findings.append(
            make_finding(
                "WEB-CORS-003",
                "Arbitrary CORS origin reflected",
                "MEDIUM",
                "CORS",
                response.url,
                f"The server reflected the supplied Origin {TEST_ORIGIN}.",
                "Validate origins against an explicit trusted allowlist.",
                "MEDIUM"
            )
        )
    elif allow_origin=="*":
        findings.append(
            make_finding(
                "WEB-CORS-004",
                "Wildcard CORS policy enabled",
                "LOW",
                "CORS",
                response.url,
                "Access-Control-Allow-Origin: *",
                "Restrict cross-origin access when the resource contains non-public data.",
                "HIGH"
            )
        )
    return findings

if __name__=="__main__":
    for finding in check_cors("https://example.com"):
        print(finding)