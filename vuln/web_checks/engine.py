from typing import Any,Callable
from web_checks.common import deduplicate_findings,normalize_url,sort_findings
from web_checks.cookies import check_cookies
from web_checks.cors import check_cors
from web_checks.http_methods import check_http_methods
from web_checks.security_headers import check_security_headers
from web_checks.sensitive_paths import check_sensitive_paths

WebCheck=Callable[[str],list[dict[str,Any]]]

CHECKS:tuple[WebCheck,...]=(
    check_security_headers,
    check_cookies,
    check_cors,
    check_http_methods,
    check_sensitive_paths
)

def scan_web_security(url:str,verbose:bool=True)->list[dict[str,Any]]:
    url=normalize_url(url)
    findings=[]
    failures=0
    if verbose:
        print(f"[+] Starting web security checks: {url}")
    for check in CHECKS:
        check_name=check.__name__.removeprefix("check_").replace("_"," ").title()
        if verbose:
            print(f"[>] {check_name}")
        try:
            results=check(url)
        except Exception as error:
            failures+=1
            if verbose:
                print(f"[!] {check_name} failed: {error}")
            continue
        if not isinstance(results,list):
            continue
        valid_results=[
            result for result in results
            if isinstance(result,dict)
        ]
        findings.extend(valid_results)
        if verbose:
            print(f"[+] {len(valid_results)} finding(s)")
    findings=deduplicate_findings(findings)
    findings=sort_findings(findings)
    if verbose:
        print(f"\n[+] Web findings: {len(findings)}")
        if failures:
            print(f"[!] Failed checks: {failures}")
    return findings