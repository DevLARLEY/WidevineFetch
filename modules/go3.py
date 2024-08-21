# WidevineFetch Module for 'Go3'
# Author: github.com/DevLARLEY

REGEX = r"https://go3\.lt/api/products/.*/drm/widevine.*"
IMPERSONATE = True


def modify(
        url: str,
        headers: dict,
        body: str
) -> tuple[str, dict, str]:
    headers.update({"content-type": "application/octet-stream"})
    return url, headers, body


MODIFY = modify
