# WidevineFetch Module for 'Amazon Prime/freevee'
# Author: github.com/DevLARLEY

import base64
from urllib.parse import parse_qsl, urlencode, urlparse

import requests
import xmltodict

REGEX = r"https://.*\.(amazon|primevideo)\..*/cdp/catalog/GetPlaybackResources\?.*desiredResources=.*Widevine2License.*"
INFO = None
ERROR = None

default_headers = {
    "deviceID": "x",
    "deviceTypeID": "AOAGZA014O5RE",  # static
    "firmware": "1",
    "consumptionType": "Streaming",
    "desiredResources": "Widevine2License",
    "resourceUsage": "ImmediateConsumption",
    "videoMaterialType": "Feature",
    "userWatchSessionId": "x"
}


def modify(
        url: str,
        headers: dict,
        body: str
) -> tuple[str, dict, str]:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query = {
        **default_headers,
        "asin": query.get('asin')
    }
    return parsed._replace(query=urlencode(query)).geturl(), headers, body


MODIFY = modify


def get_challenge(body: str) -> bytes | str:
    return dict(parse_qsl(body))["widevine2Challenge"]


GET_CHALLENGE = get_challenge


def set_challenge(
        body: str,
        challenge: bytes
) -> str:
    query = dict(parse_qsl(body))
    query["widevine2Challenge"] = base64.b64encode(challenge).decode()
    return urlencode(query)


SET_CHALLENGE = set_challenge


def _ensure_list(element: dict | list) -> list:
    if isinstance(element, dict):
        return [element]
    return element


def _extract_pssh(manifest: str) -> str:
    dict_manifest = xmltodict.parse(manifest)
    for period in _ensure_list(dict_manifest["MPD"]["Period"]):
        for ad_set in _ensure_list(period["AdaptationSet"]):
            for content_protection in _ensure_list(ad_set.get("ContentProtection", [])):
                if content_protection.get("@schemeIdUri", "").lower() == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed":
                    return content_protection.get("cenc:pssh")
            for representation in ad_set.get("Representation", []):
                for content_protection in _ensure_list(representation.get("ContentProtection")):
                    if content_protection.get("@schemeIdUri", "").lower() == "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed":
                        return content_protection["cenc:pssh"]["#text"]


def extract_pssh(
        challenge: bytes,
        url: str,
        headers: dict
) -> str | None:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query.update({
        'desiredResources': 'PlaybackUrls',
        'deviceStreamingTechnologyOverride': 'DASH',
        'deviceBitrateAdaptationsOverride': 'CVBR',
        'supportedDRMKeyScheme': 'DUAL_KEY',
        'audioTrackId': 'all',  # useful but not required
    })

    INFO("Requesting playback resources...")
    playlist_request = requests.post(
        url=parsed._replace(query=urlencode(query)).geturl(),
        headers=headers
    )

    request_json = playlist_request.json()
    if playlist_request.status_code != 200 or "errorsByResource" in request_json or "error" in request_json:
        ERROR(f"Unable to request PlaybackResources ({playlist_request.status_code}): {playlist_request.text}\n"
              f"Make sure to 'Copy as fetch (Node.js)' on a chromium-based browser")
        return

    url_sets = request_json["playbackUrls"]["urlSets"]
    urls = list(url_sets.values())[0]["urls"]
    manifest_url = urls["manifest"]["url"]
    INFO(f'Manifest: {manifest_url}')

    INFO("Requesting manifest...")
    manifest_request = requests.get(
        url=manifest_url
    )

    return _extract_pssh(manifest_request.text)


EXTRACT_PSSH = extract_pssh
