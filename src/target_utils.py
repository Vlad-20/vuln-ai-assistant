from urllib.parse import urlparse


def normalize_target(raw: str):
    """
    Normalize user input into (hostname, url).

    hostname: bare host for tools that take a host (nmap, subfinder)
    url:      full URL with scheme for URL-based tools (httpx, feroxbuster, katana, nuclei, wpscan)

    Examples:
      'http://dvwa'         -> ('dvwa', 'http://dvwa')
      'dvwa'                -> ('dvwa', 'http://dvwa')
      'example.com'         -> ('example.com', 'http://example.com')
      'https://example.com' -> ('example.com', 'https://example.com')
      '127.0.0.1:4280'      -> ('127.0.0.1', 'http://127.0.0.1:4280')
    """
    raw = raw.strip()
    if not raw.startswith(('http://', 'https://')):
        url = 'http://' + raw
    else:
        url = raw
    hostname = urlparse(url).hostname
    return hostname, url


def is_public_domain(hostname: str) -> bool:
    """
    Return True if the hostname looks like a public domain worth querying
    passive subdomain sources for (has a TLD, is not an IP, is not a bare
    internal hostname like 'dvwa' or 'localhost').
    """
    if not hostname:
        return False
    if hostname in ('localhost',):
        return False
    # Reject IPs (all-numeric when dots removed)
    if hostname.replace('.', '').isdigit():
        return False
    # Must have at least one dot (TLD separator)
    return '.' in hostname
