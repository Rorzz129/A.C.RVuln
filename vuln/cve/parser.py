from typing import Any

METRIC_VERSIONS=(
    ("cvssMetricV40","CVSS 4.0"),
    ("cvssMetricV31","CVSS 3.1"),
    ("cvssMetricV30","CVSS 3.0"),
    ("cvssMetricV2","CVSS 2.0")
)

def normalize_text(value:Any,default:str="")->str:
    if value is None:
        return default
    text=str(value).strip()
    return text if text else default

def get_description(cve:dict[str,Any],language:str="en")->str:
    descriptions=cve.get("descriptions",[])
    if not isinstance(descriptions,list):
        return"No description"
    fallback=None
    for item in descriptions:
        if not isinstance(item,dict):
            continue
        value=normalize_text(item.get("value"))
        if not value:
            continue
        if fallback is None:
            fallback=value
        if normalize_text(item.get("lang")).lower()==language.lower():
            return value
    return fallback or"No description"

def calculate_severity(score:float|int|None)->str:
    try:
        value=float(score)
    except(TypeError,ValueError):
        return"UNKNOWN"
    if value<0 or value>10:
        return"UNKNOWN"
    if value==0:
        return"NONE"
    if value<4:
        return"LOW"
    if value<7:
        return"MEDIUM"
    if value<9:
        return"HIGH"
    return"CRITICAL"

def normalize_score(score:Any)->float|None:
    try:
        value=float(score)
    except(TypeError,ValueError):
        return None
    if value<0 or value>10:
        return None
    return value

def normalize_severity(severity:Any,score:float|None=None)->str:
    value=normalize_text(severity).upper()
    if value in{"NONE","LOW","MEDIUM","HIGH","CRITICAL"}:
        return value
    return calculate_severity(score)

def select_primary_metric(metrics:list[Any])->dict[str,Any]|None:
    valid_metrics=[metric for metric in metrics if isinstance(metric,dict)]
    if not valid_metrics:
        return None
    for metric in valid_metrics:
        if normalize_text(metric.get("type")).lower()=="primary":
            return metric
    return valid_metrics[0]

def get_cvss_data(cve:dict[str,Any])->dict[str,Any]:
    result={
        "score":None,
        "severity":"UNKNOWN",
        "vector":None,
        "version":None,
        "source":None,
        "type":None,
        "exploitability_score":None,
        "impact_score":None
    }
    metrics=cve.get("metrics",{})
    if not isinstance(metrics,dict):
        return result
    for metric_name,version_name in METRIC_VERSIONS:
        metric_list=metrics.get(metric_name,[])
        if not isinstance(metric_list,list)or not metric_list:
            continue
        metric=select_primary_metric(metric_list)
        if not metric:
            continue
        cvss_data=metric.get("cvssData",{})
        if not isinstance(cvss_data,dict):
            continue
        score=normalize_score(cvss_data.get("baseScore"))
        severity=cvss_data.get("baseSeverity")or metric.get("baseSeverity")
        result.update({
            "score":score,
            "severity":normalize_severity(severity,score),
            "vector":normalize_text(cvss_data.get("vectorString"))or None,
            "version":version_name,
            "source":normalize_text(metric.get("source"))or None,
            "type":normalize_text(metric.get("type"))or None,
            "exploitability_score":normalize_score(metric.get("exploitabilityScore")),
            "impact_score":normalize_score(metric.get("impactScore"))
        })
        return result
    return result

def get_references(cve:dict[str,Any])->list[str]:
    references=[]
    seen=set()
    items=cve.get("references",[])
    if not isinstance(items,list):
        return references
    for item in items:
        if not isinstance(item,dict):
            continue
        url=normalize_text(item.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        references.append(url)
    return references

def get_reference_details(cve:dict[str,Any])->list[dict[str,Any]]:
    references=[]
    seen=set()
    items=cve.get("references",[])
    if not isinstance(items,list):
        return references
    for item in items:
        if not isinstance(item,dict):
            continue
        url=normalize_text(item.get("url"))
        if not url or url in seen:
            continue
        seen.add(url)
        tags=item.get("tags",[])
        if not isinstance(tags,list):
            tags=[]
        references.append({
            "url":url,
            "source":normalize_text(item.get("source"))or None,
            "tags":[normalize_text(tag)for tag in tags if normalize_text(tag)]
        })
    return references

def get_cwes(cve:dict[str,Any])->list[str]:
    cwes=[]
    seen=set()
    weaknesses=cve.get("weaknesses",[])
    if not isinstance(weaknesses,list):
        return cwes
    for weakness in weaknesses:
        if not isinstance(weakness,dict):
            continue
        descriptions=weakness.get("description",[])
        if not isinstance(descriptions,list):
            continue
        for description in descriptions:
            if not isinstance(description,dict):
                continue
            value=normalize_text(description.get("value")).upper()
            if not value.startswith("CWE-")or value in seen:
                continue
            seen.add(value)
            cwes.append(value)
    return cwes

def get_source_identifier(cve:dict[str,Any])->str|None:
    source=normalize_text(cve.get("sourceIdentifier"))
    return source or None

def get_configurations(cve:dict[str,Any])->list[dict[str,Any]]:
    configurations=cve.get("configurations",[])
    if not isinstance(configurations,list):
        return[]
    return[configuration for configuration in configurations if isinstance(configuration,dict)]

def parse_cve(cve:dict[str,Any])->dict[str,Any]:
    if not isinstance(cve,dict):
        raise TypeError("CVE data must be a dictionary")
    cve_id=normalize_text(cve.get("id"),"UNKNOWN")
    cvss=get_cvss_data(cve)
    references=get_references(cve)
    return{
        "id":cve_id,
        "description":get_description(cve),
        "cvss":cvss["score"],
        "severity":cvss["severity"],
        "cvss_vector":cvss["vector"],
        "cvss_version":cvss["version"],
        "cvss_source":cvss["source"],
        "cvss_type":cvss["type"],
        "exploitability_score":cvss["exploitability_score"],
        "impact_score":cvss["impact_score"],
        "published":normalize_text(cve.get("published"))or None,
        "last_modified":normalize_text(cve.get("lastModified"))or None,
        "status":normalize_text(cve.get("vulnStatus"),"UNKNOWN"),
        "source_identifier":get_source_identifier(cve),
        "cwes":get_cwes(cve),
        "references":references,
        "reference_details":get_reference_details(cve),
        "reference_count":len(references),
        "has_configurations":bool(get_configurations(cve))
    }