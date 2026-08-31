import ipaddress
from urllib.parse import urlparse


def host_of(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def is_loopback(url: str) -> bool:
    host = host_of(url)
    if host in ("localhost", "ip6-localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_url(raw: str) -> str:
    cleaned = (raw or "").strip()
    if cleaned and not cleaned.lower().startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    return cleaned
