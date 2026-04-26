import urllib.request
import json
import socket
from dataclasses import dataclass

@dataclass
class IPLookupResult:
    ip: str
    status: str
    country: str = ""
    region_name: str = ""
    city: str = ""
    zip: str = ""
    isp: str = ""
    org: str = ""
    as_name: str = ""
    hostname: str = "Unknown"
    message: str = ""

def lookup_ip(ip: str) -> IPLookupResult:
    """
    Performs an IP lookup using ip-api.com.
    Note: This uses the free tier which is limited to 45 requests per minute.
    """
    if not ip or ip in ("localhost", "127.0.0.1", "::1"):
        return IPLookupResult(ip=ip, status="fail", message="Local address")

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,zip,isp,org,as"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            
            if data.get("status") == "fail":
                return IPLookupResult(ip=ip, status="fail", message=data.get("message", "Unknown error"))
            
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown"

            return IPLookupResult(
                ip=ip,
                status="success",
                country=data.get("country", "N/A"),
                region_name=data.get("regionName", "N/A"),
                city=data.get("city", "N/A"),
                zip=data.get("zip", "N/A"),
                isp=data.get("isp", "N/A"),
                org=data.get("org", "N/A"),
                as_name=data.get("as", "N/A"),
                hostname=hostname
            )
    except Exception as e:
        return IPLookupResult(ip=ip, status="fail", message=str(e))
