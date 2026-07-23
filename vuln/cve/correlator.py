from typing import Any
from cve.client import search_cves

ALIASES={
    "nginx":"nginx",
    "openssh":"OpenSSH",
    "apache httpd":"Apache HTTP Server"
}

def normalize_product(name:str)->str:
    return ALIASES.get(name.lower(),name)

def normalize_version(name:str,version:str)->str:
    if name.lower()=="openssh":
        return version.split(" ",1)[0]
    return version

def correlate_cves(technologies:list[dict[str,Any]])->list[dict[str,Any]]:
    vulnerabilities=[]
    seen=set()
    for technology in technologies:
        name=technology.get("name")
        version=technology.get("version")
        cpe=technology.get("cpe")
        if not name or not version or not cpe:
            continue
        name=normalize_product(name)
        version=normalize_version(name,version)
        print(f"[+] CVE search: {name} {version}")
        try:
            cves=search_cves(cpe)
        except Exception as error:
            print(f"[!] CVE search failed: {error}")
            continue
        for cve in cves:
            cve_id=cve.get("id")
            if cve_id in seen:
                continue
            seen.add(cve_id)
            cve["technology"]=name
            cve["version"]=version
            cve["cpe"]=cpe
            vulnerabilities.append(cve)
    vulnerabilities.sort(
        key=lambda vulnerability:(
            float(vulnerability.get("cvss",-1))
            if vulnerability.get("cvss")is not None
            else-1
        ),
        reverse=True
    )
    print(f"[+] Total unique CVEs: {len(vulnerabilities)}")
    return vulnerabilities