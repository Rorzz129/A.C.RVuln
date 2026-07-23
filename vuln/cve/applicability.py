import re
from typing import Any

def parse_cpe(cpe:str)->dict[str,str]:
    parts=str(cpe or "").split(":")
    if len(parts)<6 or parts[0]!="cpe" or parts[1]!="2.3":
        return {}
    parts+=["*"]*(13-len(parts))
    return{
        "part":parts[2],
        "vendor":parts[3],
        "product":parts[4],
        "version":parts[5],
        "update":parts[6],
        "edition":parts[7],
        "language":parts[8],
        "software_edition":parts[9],
        "target_software":parts[10],
        "target_hardware":parts[11],
        "other":parts[12]
    }

def normalize_component(value:Any)->str:
    return str(value or "").strip().lower()

def version_parts(version:str)->tuple:
    tokens=re.findall(r"\d+|[a-z]+",normalize_component(version))
    return tuple((0,int(token))if token.isdigit()else(1,token)for token in tokens)

def compare_versions(first:str,second:str)->int:
    first_parts=list(version_parts(first))
    second_parts=list(version_parts(second))
    length=max(len(first_parts),len(second_parts))
    first_parts.extend([(0,0)]*(length-len(first_parts)))
    second_parts.extend([(0,0)]*(length-len(second_parts)))
    return(first_parts>second_parts)-(first_parts<second_parts)

def component_matches(detected:str,expected:str)->bool:
    detected=normalize_component(detected)
    expected=normalize_component(expected)
    if expected in("","*","-"):
        return True
    return detected==expected

def product_matches(detected:dict[str,str],criteria:dict[str,str])->bool:
    for field in("part","vendor","product"):
        if not component_matches(detected.get(field,""),criteria.get(field,"*")):
            return False
    return True

def version_matches(detected_version:str,match:dict[str,Any])->bool:
    criteria=parse_cpe(match.get("criteria",""))
    criteria_version=criteria.get("version","*")
    if criteria_version not in("","*","-")and compare_versions(detected_version,criteria_version)!=0:
        return False
    start_including=match.get("versionStartIncluding")
    if start_including and compare_versions(detected_version,start_including)<0:
        return False
    start_excluding=match.get("versionStartExcluding")
    if start_excluding and compare_versions(detected_version,start_excluding)<=0:
        return False
    end_including=match.get("versionEndIncluding")
    if end_including and compare_versions(detected_version,end_including)>0:
        return False
    end_excluding=match.get("versionEndExcluding")
    if end_excluding and compare_versions(detected_version,end_excluding)>=0:
        return False
    return True

def cpe_match_applies(detected_cpe:str,match:dict[str,Any])->bool:
    if match.get("vulnerable")is not True:
        return False
    detected=parse_cpe(detected_cpe)
    criteria=parse_cpe(match.get("criteria",""))
    if not detected or not criteria:
        return False
    if not product_matches(detected,criteria):
        return False
    return version_matches(detected.get("version",""),match)

def node_contains_applicable_cpe(detected_cpe:str,node:dict[str,Any])->bool:
    for match in node.get("cpeMatch",[]):
        if isinstance(match,dict)and cpe_match_applies(detected_cpe,match):
            return True
    for child in node.get("children",[]):
        if isinstance(child,dict)and node_contains_applicable_cpe(detected_cpe,child):
            return True
    return False

def cve_applies_to_cpe(cve:dict[str,Any],detected_cpe:str)->bool:
    if not parse_cpe(detected_cpe):
        return False
    configurations=cve.get("configurations",[])
    if not isinstance(configurations,list):
        return False
    for configuration in configurations:
        if not isinstance(configuration,dict):
            continue
        nodes=configuration.get("nodes",[])
        if not isinstance(nodes,list):
            continue
        for node in nodes:
            if isinstance(node,dict)and node_contains_applicable_cpe(detected_cpe,node):
                return True
    return False