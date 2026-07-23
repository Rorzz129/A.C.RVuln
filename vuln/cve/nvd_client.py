import os
import random
import threading
import time
from email.utils import parsedate_to_datetime
from typing import Any
import requests
NVD_CVE_API_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_URL="https://services.nvd.nist.gov/rest/json/cpes/2.0"
DEFAULT_RETRIES=5
DEFAULT_TIMEOUT=30.0
MAX_BACKOFF=60.0
NVD_API_KEY=os.getenv("NVD_API_KEY","").strip()
MIN_DELAY=0.6 if NVD_API_KEY else 6.0
_last_request_time=0.0
_throttle_lock=threading.Lock()
_session=requests.Session()

def build_headers()->dict[str,str]:
    headers={
        "Accept":"application/json",
        "User-Agent":"VulnScope/1.0"
    }
    if NVD_API_KEY:
        headers["apiKey"]=NVD_API_KEY
    return headers

def _throttle()->None:
    global _last_request_time
    with _throttle_lock:
        elapsed=time.monotonic()-_last_request_time
        wait_time=MIN_DELAY-elapsed
        if wait_time>0:
            time.sleep(wait_time)
        _last_request_time=time.monotonic()

def _normalize_retries(retries:Any)->int:
    try:
        retries=int(retries)
    except(TypeError,ValueError):
        retries=DEFAULT_RETRIES
    return max(1,min(retries,10))

def _normalize_timeout(timeout:Any)->float:
    try:
        timeout=float(timeout)
    except(TypeError,ValueError):
        timeout=DEFAULT_TIMEOUT
    return max(1.0,min(timeout,120.0))

def _backoff_delay(attempt:int)->float:
    base=min(2**(attempt-1),MAX_BACKOFF)
    return base+random.uniform(0.0,min(base*0.25,2.0))

def _retry_after_seconds(response:requests.Response)->float|None:
    value=response.headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0,float(value))
    except ValueError:
        try:
            retry_date=parsedate_to_datetime(value)
            seconds=retry_date.timestamp()-time.time()
            return max(0.0,seconds)
        except(ValueError,TypeError,OverflowError):
            return None

def get_error_message(response:requests.Response)->str:
    header_message=response.headers.get("message")
    if header_message:
        return header_message.strip()
    try:
        data=response.json()
    except(ValueError,requests.exceptions.JSONDecodeError):
        data=None
    if isinstance(data,dict):
        for key in("message","error","detail"):
            value=data.get(key)
            if value:
                return str(value).strip()
    text=(response.text or "").strip()
    if text:
        return text[:500]
    return f"HTTP {response.status_code}"

def _parse_json_response(response:requests.Response)->dict[str,Any]:
    try:
        data=response.json()
    except(ValueError,requests.exceptions.JSONDecodeError) as error:
        raise RuntimeError("NVD returned invalid JSON") from error
    if not isinstance(data,dict):
        raise RuntimeError("NVD returned an unexpected JSON structure")
    return data

def nvd_get(url:str,params:dict[str,Any],retries:int=DEFAULT_RETRIES,timeout:float=DEFAULT_TIMEOUT)->dict[str,Any]:
    url=str(url or "").strip()
    if not url:
        raise ValueError("NVD URL cannot be empty")
    if url not in(NVD_CVE_API_URL,NVD_CPE_API_URL):
        raise ValueError("Unsupported NVD API URL")
    if not isinstance(params,dict):
        raise TypeError("NVD parameters must be a dictionary")
    retries=_normalize_retries(retries)
    timeout=_normalize_timeout(timeout)
    headers=build_headers()
    last_error:Exception|None=None
    for attempt in range(1,retries+1):
        _throttle()
        try:
            response=_session.get(
                url,
                params=params,
                headers=headers,
                timeout=(10.0,timeout)
            )
        except requests.exceptions.Timeout as error:
            last_error=error
            print(f"  [!] NVD timeout ({attempt}/{retries})")
        except requests.exceptions.ConnectionError as error:
            last_error=error
            print(f"  [!] NVD connection error ({attempt}/{retries})")
        except requests.exceptions.RequestException as error:
            last_error=error
            print(f"  [!] NVD request error ({attempt}/{retries}): {error}")
        else:
            status=response.status_code
            if status==200:
                return _parse_json_response(response)
            message=get_error_message(response)
            if status in(408,425,429)or 500<=status<600:
                last_error=RuntimeError(f"HTTP {status}: {message}")
                retry_after=_retry_after_seconds(response)
                if status==429:
                    print(f"  [!] NVD rate limit reached: {message}")
                else:
                    print(f"  [!] NVD temporary error {status}: {message}")
                if attempt<retries:
                    wait_time=retry_after if retry_after is not None else _backoff_delay(attempt)
                    wait_time=min(wait_time,MAX_BACKOFF)
                    print(f"  [>] Retrying in {wait_time:.1f}s...")
                    time.sleep(wait_time)
                continue
            raise RuntimeError(f"NVD HTTP error {status}: {message}")
        if attempt<retries:
            wait_time=_backoff_delay(attempt)
            print(f"  [>] Retrying in {wait_time:.1f}s...")
            time.sleep(wait_time)
    error_message=str(last_error)if last_error else"unknown error"
    raise RuntimeError(f"NVD request failed after {retries} attempts: {error_message}")