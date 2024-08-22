# WidevineFetch Module for 'YOUKU'
# Author: github.com/DevLARLEY

import base64
from urllib.parse import parse_qsl, urlencode

REGEX = r"https://drm-license\.youku\.tv/ups/drm\.json.*"


def get_challenge(body: str) -> bytes | str:
    return dict(parse_qsl(body))["licenseRequest"]


GET_CHALLENGE = get_challenge


def set_challenge(
        body: str,
        challenge: bytes
) -> str:
    query = dict(parse_qsl(body))
    query["licenseRequest"] = base64.b64encode(challenge).decode()
    return urlencode(query)


SET_CHALLENGE = set_challenge
