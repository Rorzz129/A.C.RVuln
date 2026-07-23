from typing import Any
from http.cookies import SimpleCookie
from web_checks.common import create_session,make_finding,normalize_url,request

def get_set_cookie_headers(response:Any)->list[str]:
    raw=getattr(response,"raw",None)
    headers=getattr(raw,"headers",None)
    if headers and hasattr(headers,"getlist"):
        values=headers.getlist("Set-Cookie")
        if values:
            return values
    value=response.headers.get("Set-Cookie")
    return[value]if value else[]

def parse_cookie_name(header:str)->str:
    cookie=SimpleCookie()
    try:
        cookie.load(header)
    except Exception:
        return"unknown"
    names=list(cookie.keys())
    return names[0]if names else"unknown"

def check_cookies(url:str)->list[dict[str,Any]]:
    url=normalize_url(url)
    session=create_session()
    findings=[]
    try:
        response=request(session,"GET",url)
    finally:
        session.close()
    headers=get_set_cookie_headers(response)
    for header in headers:
        cookie_name=parse_cookie_name(header)
        lowered=header.lower()
        if response.url.startswith("https://")and"; secure" not in lowered:
            findings.append(
                make_finding(
                    "WEB-COOKIE-001",
                    f'Cookie "{cookie_name}" missing Secure attribute',
                    "MEDIUM",
                    "Cookies",
                    response.url,
                    f"The cookie {cookie_name} was set without the Secure attribute.",
                    "Set the Secure attribute on cookies transmitted over HTTPS."
                )
            )
        if"; httponly" not in lowered:
            findings.append(
                make_finding(
                    "WEB-COOKIE-002",
                    f'Cookie "{cookie_name}" missing HttpOnly attribute',
                    "MEDIUM",
                    "Cookies",
                    response.url,
                    f"The cookie {cookie_name} was set without the HttpOnly attribute.",
                    "Set HttpOnly on cookies that do not require JavaScript access."
                )
            )
        if"; samesite=" not in lowered:
            findings.append(
                make_finding(
                    "WEB-COOKIE-003",
                    f'Cookie "{cookie_name}" missing SameSite attribute',
                    "LOW",
                    "Cookies",
                    response.url,
                    f"The cookie {cookie_name} was set without a SameSite attribute.",
                    "Set SameSite=Lax or SameSite=Strict when compatible."
                )
            )
        if"; samesite=none" in lowered and"; secure" not in lowered:
            findings.append(
                make_finding(
                    "WEB-COOKIE-004",
                    f'Cookie "{cookie_name}" uses SameSite=None without Secure',
                    "MEDIUM",
                    "Cookies",
                    response.url,
                    f"The cookie {cookie_name} uses SameSite=None without Secure.",
                    "Cookies using SameSite=None must also use the Secure attribute."
                )
            )
    return findings

if __name__=="__main__":
    for finding in check_cookies("https://example.com"):
        print(finding)