from typing import Any
from cve.cpe import search_cpe
from cve.client import search_cves

UNKNOWN_VERSIONS={"","unknown","none","null","n/a","na","-","*"}
SEVERITY_PRIORITY={
    "CRITICAL":4,
    "HIGH":3,
    "MEDIUM":2,
    "LOW":1,
    "NONE":0,
    "UNKNOWN":-1
}

def normalize_text(value:Any)->str:
    return str(value or "").strip()

def is_valid_version(version:Any)->bool:
    return normalize_text(version).lower()not in UNKNOWN_VERSIONS

def normalize_cpes(cpes:Any)->list[str]:
    if isinstance(cpes,str):
        cpes=[cpes]
    if not isinstance(cpes,list):
        return[]
    results=[]
    seen=set()
    for cpe in cpes:
        value=normalize_text(cpe)
        if not value or value in seen:
            continue
        seen.add(value)
        results.append(value)
    return results

def get_cvss(entry:dict[str,Any])->float:
    cve=entry.get("cve",{})
    if not isinstance(cve,dict):
        return-1.0
    try:
        return float(cve.get("cvss"))
    except(TypeError,ValueError):
        return-1.0

def get_severity_priority(entry:dict[str,Any])->int:
    cve=entry.get("cve",{})
    if not isinstance(cve,dict):
        return-1
    severity=normalize_text(cve.get("severity")).upper()or"UNKNOWN"
    return SEVERITY_PRIORITY.get(severity,-1)

def sort_vulnerabilities(vulnerabilities:list[dict[str,Any]])->None:
    vulnerabilities.sort(
        key=lambda entry:(
            get_cvss(entry),
            get_severity_priority(entry),
            normalize_text(entry.get("technology")),
            normalize_text(entry.get("version")),
            normalize_text(entry.get("port")),
            normalize_text(entry.get("cve",{}).get("id")if isinstance(entry.get("cve"),dict)else"")
        ),
        reverse=True
    )

def scan_technology_cves(technologies:list[dict[str,Any]])->list[dict[str,Any]]:
    if not isinstance(technologies,list):
        raise TypeError("Technologies must be a list")
    vulnerabilities=[]
    seen_results=set()
    scanned_technologies=set()
    skipped_unknown=[]
    failed=0
    for technology in technologies:
        if not isinstance(technology,dict):
            continue
        product=normalize_text(technology.get("name"))
        version=normalize_text(technology.get("version"))
        port=technology.get("port")
        source=normalize_text(technology.get("source"))
        if not product:
            continue
        if not is_valid_version(version):
            skipped_unknown.append({
                "technology":product,
                "version":None,
                "port":port,
                "reason":"VERSION_UNKNOWN"
            })
            print(f"[!] Skipping {product}: exact version unknown")
            continue
        technology_key=(product.lower(),version.lower(),str(port))
        if technology_key in scanned_technologies:
            continue
        scanned_technologies.add(technology_key)
        print(f"\n[+] Resolving CPE: {product} {version}")
        try:
            cpes=normalize_cpes(search_cpe(product,version))
        except Exception as error:
            print(f"[!] CPE resolution failed for {product} {version}: {error}")
            failed+=1
            continue
        if not cpes:
            print(f"[!] No exact CPE found for {product} {version}")
            continue
        for cpe in cpes:
            print(f"[+] CPE: {cpe}")
            try:
                cves=search_cves(cpe)
            except Exception as error:
                print(f"[!] CVE search failed for {cpe}: {error}")
                failed+=1
                continue
            for cve in cves:
                if not isinstance(cve,dict):
                    continue
                cve_id=normalize_text(cve.get("id"))
                if not cve_id:
                    continue
                result_key=(cve_id.upper(),product.lower(),version.lower(),str(port),cpe)
                if result_key in seen_results:
                    continue
                seen_results.add(result_key)
                vulnerabilities.append({
                    "technology":product,
                    "version":version,
                    "port":port,
                    "source":source or None,
                    "cpe":cpe,
                    "confidence":"CONFIRMED_CPE_MATCH",
                    "cve":cve
                })
    sort_vulnerabilities(vulnerabilities)
    print(f"\n[+] Confirmed CVEs: {len(vulnerabilities)}")
    if skipped_unknown:
        print(f"[!] {len(skipped_unknown)} technology(s) could not be checked because their exact version is unknown")
    if not vulnerabilities:
        print("[i] No confirmed CVE found")
        print("[i] This does not mean that the target has no web vulnerabilities")
    if failed:
        print(f"[!] {failed} scan operation(s) failed")
    return vulnerabilities