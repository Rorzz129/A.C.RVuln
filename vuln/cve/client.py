from typing import Any
from cve.parser import parse_cve
from cve.applicability import cve_applies_to_cpe
from cve.nvd_client import NVD_CVE_API_URL,nvd_get

MAX_RESULTS_PER_PAGE=2000
DEFAULT_LIMIT=100

def normalize_cpe(cpe:str)->str:
    return str(cpe or "").strip()

def normalize_limit(limit:Any)->int:
    try:
        value=int(limit)
    except(TypeError,ValueError):
        value=DEFAULT_LIMIT
    return max(1,value)

def get_cvss_score(vulnerability:dict[str,Any])->float:
    score=vulnerability.get("cvss")
    try:
        return float(score)
    except(TypeError,ValueError):
        return -1.0

def get_severity_priority(vulnerability:dict[str,Any])->int:
    priorities={
        "CRITICAL":4,
        "HIGH":3,
        "MEDIUM":2,
        "LOW":1,
        "NONE":0,
        "UNKNOWN":-1
    }
    severity=str(vulnerability.get("severity")or"UNKNOWN").upper()
    return priorities.get(severity,-1)

def sort_vulnerabilities(vulnerabilities:list[dict])->None:
    vulnerabilities.sort(
        key=lambda vulnerability:(
            get_cvss_score(vulnerability),
            get_severity_priority(vulnerability),
            str(vulnerability.get("published")or""),
            str(vulnerability.get("id")or"")
        ),
        reverse=True
    )

def fetch_cve_page(cpe:str,start_index:int,results_per_page:int)->dict[str,Any]:
    params={
        "cpeName":cpe,
        "isVulnerable":"",
        "resultsPerPage":results_per_page,
        "startIndex":start_index
    }
    data=nvd_get(NVD_CVE_API_URL,params)
    if not isinstance(data,dict):
        raise ValueError("Invalid response returned by NVD")
    return data

def search_cves(cpe:str,limit:int=DEFAULT_LIMIT,verbose:bool=False)->list[dict]:
    cpe=normalize_cpe(cpe)
    if not cpe:
        print("[!] CPE cannot be empty")
        return[]
    limit=normalize_limit(limit)
    print(f"[+] Searching CVEs for: {cpe}")
    vulnerabilities=[]
    seen_cves=set()
    rejected_cves=0
    invalid_cves=0
    parsing_errors=0
    applicability_errors=0
    duplicate_cves=0
    received_cves=0
    start_index=0
    total_results=None
    while len(vulnerabilities)<limit:
        remaining=limit-received_cves
        if remaining<=0:
            break
        results_per_page=min(remaining,MAX_RESULTS_PER_PAGE)
        try:
            data=fetch_cve_page(cpe,start_index,results_per_page)
        except Exception as error:
            print(f"[!] CVE request failed at index {start_index}: {error}")
            break
        items=data.get("vulnerabilities",[])
        if not isinstance(items,list):
            print("[!] Invalid vulnerability response from NVD")
            break
        if total_results is None:
            try:
                total_results=max(0,int(data.get("totalResults",len(items))))
            except(TypeError,ValueError):
                total_results=len(items)
            print(f"[+] NVD returned {total_results} matching CVE(s)")
        if not items:
            break
        received_cves+=len(items)
        for item in items:
            if not isinstance(item,dict):
                invalid_cves+=1
                continue
            cve_data=item.get("cve")
            if not isinstance(cve_data,dict):
                invalid_cves+=1
                continue
            cve_id=str(cve_data.get("id")or"UNKNOWN")
            if cve_id in seen_cves:
                duplicate_cves+=1
                continue
            try:
                applicable=cve_applies_to_cpe(cve_data,cpe)
            except Exception as error:
                applicability_errors+=1
                if verbose:
                    print(f"[!] Applicability check failed for {cve_id}: {error}")
                continue
            if not applicable:
                rejected_cves+=1
                if verbose:
                    print(f"[-] Rejected {cve_id}: not applicable to detected CPE")
                continue
            try:
                parsed_cve=parse_cve(cve_data)
            except Exception as error:
                parsing_errors+=1
                if verbose:
                    print(f"[!] Failed to parse {cve_id}: {error}")
                continue
            if not isinstance(parsed_cve,dict):
                parsing_errors+=1
                continue
            parsed_cve_id=str(parsed_cve.get("id")or"").strip()
            if not parsed_cve_id:
                invalid_cves+=1
                continue
            if parsed_cve_id in seen_cves:
                duplicate_cves+=1
                continue
            seen_cves.add(parsed_cve_id)
            parsed_cve["applicability"]="CONFIRMED_MATCH"
            parsed_cve["matched_cpe"]=cpe
            vulnerabilities.append(parsed_cve)
            if len(vulnerabilities)>=limit:
                break
        response_start=data.get("startIndex",start_index)
        response_count=data.get("resultsPerPage",len(items))
        try:
            next_index=int(response_start)+int(response_count)
        except(TypeError,ValueError):
            next_index=start_index+len(items)
        if next_index<=start_index:
            break
        start_index=next_index
        if total_results is not None and start_index>=total_results:
            break
        if len(items)<results_per_page:
            break
    sort_vulnerabilities(vulnerabilities)
    print(f"[+] {len(vulnerabilities)} applicable CVE(s) found")
    if rejected_cves:
        print(f"[-] {rejected_cves} false positive(s) rejected")
    if duplicate_cves:
        print(f"[-] {duplicate_cves} duplicate CVE(s) ignored")
    if invalid_cves:
        print(f"[!] {invalid_cves} invalid CVE record(s) ignored")
    if parsing_errors:
        print(f"[!] {parsing_errors} CVE parsing error(s)")
    if applicability_errors:
        print(f"[!] {applicability_errors} applicability check error(s)")
    return vulnerabilities

def print_results(vulnerabilities:list[dict])->None:
    if not vulnerabilities:
        print("[!] No applicable CVEs found")
        return
    for vulnerability in vulnerabilities:
        cve_id=vulnerability.get("id","UNKNOWN")
        severity=vulnerability.get("severity","UNKNOWN")
        cvss=vulnerability.get("cvss","N/A")
        applicability=vulnerability.get("applicability","UNKNOWN")
        print(f"{cve_id} | {severity} | {cvss} | {applicability}")

if __name__=="__main__":
    test_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    results=search_cves(test_cpe,limit=100,verbose=True)
    print_results(results)