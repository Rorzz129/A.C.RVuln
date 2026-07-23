import re
from typing import Any
from urllib.parse import unquote
from cve.nvd_client import NVD_CPE_API_URL,nvd_get

PRODUCT_ALIASES={
    "apache":["apache http server"],
    "apache httpd":["apache http server"],
    "apache http server":["apache http server"],
    "httpd":["apache http server"],
    "openssh":["openssh"],
    "open ssh":["openssh"],
    "nginx":["nginx"],
    "openresty":["openresty"],
    "openresty web app server":["openresty"],
    "php":["php"],
    "microsoft iis":["internet information services"],
    "iis":["internet information services"],
    "internet information services":["internet information services"],
    "postgres":["postgresql"],
    "postgresql":["postgresql"]
}

CPE_IDENTITIES={
    "apache http server":{
        ("apache","http_server")
    },
    "openssh":{
        ("openbsd","openssh")
    },
    "nginx":{
        ("f5","nginx"),
        ("nginx","nginx")
    },
    "openresty":{
        ("openresty","openresty")
    },
    "php":{
        ("php","php")
    },
    "internet information services":{
        ("microsoft","internet_information_services")
    },
    "postgresql":{
        ("postgresql","postgresql")
    }
}

UNKNOWN_VERSIONS={"","unknown","none","null","n/a","na","-","*"}
MAX_RESULTS_PER_PAGE=2000
DEFAULT_RESULT_LIMIT=1000
DEFAULT_MAX_RESULTS=5

def normalize_text(value:Any)->str:
    return str(value or "").strip()

def normalize_name(value:Any)->str:
    text=normalize_text(value).lower()
    text=unquote(text)
    text=re.sub(r"\\(.)",r"\1",text)
    text=text.replace("_"," ").replace("-"," ")
    text=re.sub(r"[^a-z0-9.+ ]"," ",text)
    return re.sub(r"\s+"," ",text).strip()

def normalize_product(product:Any)->str:
    value=normalize_name(product)
    if not value:
        return""
    for alias,canonical_names in PRODUCT_ALIASES.items():
        alias_value=normalize_name(alias)
        if value==alias_value:
            return canonical_names[0]
    return value

def normalize_version(version:Any)->str|None:
    value=normalize_text(version)
    if value.lower()in UNKNOWN_VERSIONS:
        return None
    value=value.split(" ",1)[0].strip()
    if value.lower().startswith("v")and len(value)>1 and value[1].isdigit():
        value=value[1:]
    return value or None

def get_search_queries(product:str)->list[str]:
    normalized=normalize_product(product)
    query_map={
        "apache http server":["Apache HTTP Server"],
        "openssh":["OpenSSH"],
        "nginx":["nginx"],
        "openresty":["OpenResty"],
        "php":["PHP"],
        "internet information services":["Microsoft Internet Information Services"],
        "postgresql":["PostgreSQL"]
    }
    queries=query_map.get(normalized,[product])
    results=[]
    seen=set()
    for query in queries:
        value=normalize_text(query)
        key=value.lower()
        if not value or key in seen:
            continue
        seen.add(key)
        results.append(value)
    return results

def split_cpe(cpe_name:str)->list[str]:
    if not isinstance(cpe_name,str)or not cpe_name.startswith("cpe:2.3:"):
        return[]
    parts=[]
    current=[]
    escaped=False
    for character in cpe_name:
        if escaped:
            current.append(character)
            escaped=False
            continue
        if character=="\\":
            current.append(character)
            escaped=True
            continue
        if character==":":
            parts.append("".join(current))
            current=[]
            continue
        current.append(character)
    parts.append("".join(current))
    return parts

def unescape_cpe_component(value:Any)->str:
    text=normalize_text(value)
    text=unquote(text)
    return re.sub(r"\\(.)",r"\1",text)

def get_cpe_components(cpe_name:str)->dict[str,str]:
    parts=split_cpe(cpe_name)
    if len(parts)<13:
        return{}
    return{
        "part":unescape_cpe_component(parts[2]),
        "vendor":unescape_cpe_component(parts[3]),
        "product":unescape_cpe_component(parts[4]),
        "version":unescape_cpe_component(parts[5]),
        "update":unescape_cpe_component(parts[6]),
        "edition":unescape_cpe_component(parts[7]),
        "language":unescape_cpe_component(parts[8]),
        "software_edition":unescape_cpe_component(parts[9]),
        "target_software":unescape_cpe_component(parts[10]),
        "target_hardware":unescape_cpe_component(parts[11]),
        "other":unescape_cpe_component(parts[12])
    }

def extract_cpe_name(product_data:dict[str,Any])->str|None:
    if not isinstance(product_data,dict):
        return None
    cpe_data=product_data.get("cpe")
    if not isinstance(cpe_data,dict):
        return None
    cpe_name=normalize_text(cpe_data.get("cpeName"))
    if not cpe_name.startswith("cpe:2.3:"):
        return None
    return cpe_name

def get_expected_identities(product:str)->set[tuple[str,str]]:
    normalized=normalize_product(product)
    identities=CPE_IDENTITIES.get(normalized,set())
    return{
        (normalize_name(vendor),normalize_name(cpe_product))
        for vendor,cpe_product in identities
    }

def product_matches(cpe_name:str,product:str)->bool:
    components=get_cpe_components(cpe_name)
    if not components:
        return False
    if components.get("part")!="a":
        return False
    vendor=normalize_name(components.get("vendor"))
    cpe_product=normalize_name(components.get("product"))
    identities=get_expected_identities(product)
    if identities:
        return(vendor,cpe_product)in identities
    requested=normalize_product(product)
    return cpe_product==requested

def version_tokens(version:str)->tuple[int,...]|None:
    match=re.match(r"^(\d+(?:\.\d+)*)",version)
    if not match:
        return None
    try:
        return tuple(int(part)for part in match.group(1).split("."))
    except ValueError:
        return None

def version_matches(cpe_version:Any,requested_version:Any)->bool:
    requested=normalize_version(requested_version)
    detected=normalize_version(cpe_version)
    if requested is None:
        return True
    if detected is None:
        return False
    if detected==requested:
        return True
    detected_lower=detected.lower()
    requested_lower=requested.lower()
    if detected_lower==requested_lower:
        return True
    detected_numeric=version_tokens(detected_lower)
    requested_numeric=version_tokens(requested_lower)
    if not detected_numeric or not requested_numeric:
        return False
    return detected_numeric==requested_numeric

def get_cpe_score(cpe_name:str,product:str,version:str|None)->int:
    components=get_cpe_components(cpe_name)
    if not components:
        return-1
    score=0
    identities=get_expected_identities(product)
    vendor=normalize_name(components.get("vendor"))
    cpe_product=normalize_name(components.get("product"))
    if(vendor,cpe_product)in identities:
        score+=200
    elif cpe_product==normalize_product(product):
        score+=120
    if components.get("part")=="a":
        score+=20
    if version:
        detected_version=normalize_version(components.get("version"))
        requested_version=normalize_version(version)
        if detected_version==requested_version:
            score+=200
        elif version_matches(detected_version,requested_version):
            score+=100
    if components.get("update")in("*","-"):
        score+=5
    return score

def request_cpes(query:str,limit:int=DEFAULT_RESULT_LIMIT)->list[dict[str,Any]]:
    query=normalize_text(query)
    if not query:
        return[]
    try:
        limit=max(1,int(limit))
    except(TypeError,ValueError):
        limit=DEFAULT_RESULT_LIMIT
    products=[]
    start_index=0
    total_results=None
    while len(products)<limit:
        page_size=min(MAX_RESULTS_PER_PAGE,limit-len(products))
        params={
            "keywordSearch":query,
            "resultsPerPage":page_size,
            "startIndex":start_index
        }
        try:
            data=nvd_get(NVD_CPE_API_URL,params)
        except Exception as error:
            print(f"[!] CPE request failed for '{query}': {error}")
            break
        page_products=data.get("products",[])
        if not isinstance(page_products,list):
            print("[!] Invalid CPE response returned by NVD")
            break
        if total_results is None:
            try:
                total_results=max(0,int(data.get("totalResults",len(page_products))))
            except(TypeError,ValueError):
                total_results=len(page_products)
            print(f"[>] NVD CPE results: {total_results}")
        if not page_products:
            break
        valid_products=[
            item for item in page_products
            if isinstance(item,dict)
        ]
        products.extend(valid_products)
        try:
            response_start=int(data.get("startIndex",start_index))
            response_count=int(data.get("resultsPerPage",len(page_products)))
            next_index=response_start+response_count
        except(TypeError,ValueError):
            next_index=start_index+len(page_products)
        if next_index<=start_index:
            break
        start_index=next_index
        print(f"[>] Retrieved CPEs: {len(products)}/{min(total_results or limit,limit)}")
        if total_results is not None and start_index>=total_results:
            break
        if len(page_products)<page_size:
            break
    return products[:limit]

def search_cpe(product:str,version:str|None=None,limit:int=DEFAULT_RESULT_LIMIT,max_results:int=DEFAULT_MAX_RESULTS)->list[str]:
    product=normalize_product(product)
    version=normalize_version(version)
    if not product:
        print("[!] Product cannot be empty")
        return[]
    try:
        limit=max(1,int(limit))
    except(TypeError,ValueError):
        limit=DEFAULT_RESULT_LIMIT
    try:
        max_results=max(1,int(max_results))
    except(TypeError,ValueError):
        max_results=DEFAULT_MAX_RESULTS
    queries=get_search_queries(product)
    candidates={}
    received_count=0
    product_match_count=0
    print(f"[+] Searching CPE for: {product}")
    if version:
        print(f"[+] Version filter: {version}")
    for query in queries:
        print(f"[>] CPE query: {query}")
        products=request_cpes(query,limit)
        received_count+=len(products)
        for product_data in products:
            cpe_name=extract_cpe_name(product_data)
            if not cpe_name:
                continue
            if not product_matches(cpe_name,product):
                continue
            product_match_count+=1
            components=get_cpe_components(cpe_name)
            if not components:
                continue
            if version and not version_matches(components.get("version"),version):
                continue
            score=get_cpe_score(cpe_name,product,version)
            if score<0:
                continue
            previous_score=candidates.get(cpe_name)
            if previous_score is None or score>previous_score:
                candidates[cpe_name]=score
    ordered=sorted(
        candidates,
        key=lambda cpe:(candidates[cpe],cpe),
        reverse=True
    )
    print(f"[>] CPE records received: {received_count}")
    print(f"[>] Product matches: {product_match_count}")
    print(f"[>] Exact matches: {len(ordered)}")
    if not ordered:
        if version:
            print(f"[!] No exact CPE found for {product} {version}")
        else:
            print(f"[!] No matching CPE found for {product}")
        return[]
    return ordered[:max_results]

if __name__=="__main__":
    tests=[
        ("PHP","7.4"),
        ("Apache httpd","2.4.68"),
        ("OpenSSH","9.8p1"),
        ("nginx","1.24.0")
    ]
    for test_product,test_version in tests:
        print("\n"+"="*70)
        results=search_cpe(test_product,test_version)
        if not results:
            print("[!] No exact CPE found")
            continue
        print(f"[+] Found {len(results)} matching CPE(s)")
        for result in results:
            components=get_cpe_components(result)
            print(
                f"{result} | "
                f"{components.get('vendor')} | "
                f"{components.get('product')} | "
                f"{components.get('version')}"
            )