"""HTTP request helpers compatible with current httpx cookie handling."""


def cookie_headers(cookies: dict[str, str], headers: dict[str, str] | None = None) -> dict[str, str]:
    result = dict(headers or {})
    result["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())
    return result
