import base64
import glob
import json
import logging
import re
import time
from os.path import join
from typing import Any

import requests
from google.protobuf.json_format import MessageToDict

from pywidevine import PSSH, Device, Cdm
from pywidevine.license_protocol_pb2 import SignedMessage, LicenseRequest, WidevinePsshData


class WVFetch:
    CDM_DIR = '../cdm'

    def __init__(self):
        """
        Parse 'Copy as fetch' of a license request and parse its data accordingly.
        No PSSH, Manifest, Cookies or License wrapping integration required.
        Author: github.com/DevLARLEY
        """
        self._post()
        self.read = self._read_lines()

    def _post(self):
        print(
            """
                                    _                          __         ,__          .           _     
        ,  _  / `   ___/   ___  _   __ ` , __     ___        /  `   ___  _/_     ___  /     
        |  |  | |  /   | .'   ` |   /  | |'  `. .'   ` .---' |__  .'   `  |    .'   ` |,---.
        `  ^  ' | ,'   | |----' `  /   | |    | |----'       |    |----'  |    |      |'   `
         \\/ \\/  / `___,' `.___,  \\/    / /    | `.___,       |    `.___,  \\__/  `._.' /    |
                       `     github.com/DevLARLEY            /                              
            """
        )
        time.sleep(0.1)

    @staticmethod
    def _read_lines() -> str:
        logging.info(
            "Paste 'Copy as fetch' of the second license URL. The one that has the actual license request; "
            "Press RETURN twice to end"
        )
        read = ''
        for line in iter(input, ''):
            read += line.strip()
        logging.info("Input received")
        return read

    def _parse(self) -> tuple[str, dict] | None:
        search = re.search(
            r'.*fetch\(\"(.*)\",\s*{(.*)}\).*',
            self.read
        )
        if not search or len(search.groups()) < 2:
            return
        return search.group(1), json.loads('{' + search.group(2) + '}')

    @staticmethod
    def _is_json(response: str) -> Any | None:
        try:
            return json.loads(response)
        except Exception:
            pass

    @staticmethod
    def _valid_base64_challenge(
            b64: str
    ) -> bool:
        return (
                b64 and b64[0] == 'C' and
                re.fullmatch(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", b64)
        )

    def _replace_in_dict(
            self,
            d: dict,
            new: str
    ) -> dict:
        x = {}
        for k, v in d.items():
            if isinstance(v, dict):
                v = self._replace_in_dict(v, new)
            elif isinstance(v, list):
                v = self._replace_in_list(v, new)
            elif isinstance(v, str):
                if self._valid_base64_challenge(v):
                    v = new
            x[k] = v
        return x

    def _replace_in_list(
            self,
            l: list,
            new: str
    ) -> list:
        if (len(l) >= 50 or l == [8, 4]) and l[0] == 8 and all(isinstance(item, int) for item in l):
            return list(base64.b64decode(new))
        x = []
        for e in l:
            if isinstance(e, list):
                e = self._replace_in_list(e, new)
            elif isinstance(e, dict):
                e = self._replace_in_dict(e, new)
            elif isinstance(e, str):
                if self._valid_base64_challenge(e):
                    e = new
            x.append(e)
        return x

    def _find_in_dict(
            self,
            d: dict
    ) -> bytes:
        for k, v in d.items():
            if isinstance(v, dict):
                if r := self._find_in_dict(v):
                    return r
            elif isinstance(v, list):
                if r := self._find_in_list(v):
                    return r
            elif isinstance(v, str):
                if self._valid_base64_challenge(v):
                    return base64.b64decode(v)

    def _find_in_list(
            self,
            l: list
    ) -> bytes:
        if (len(l) >= 50 or l == [8, 4]) and l[0] == 8 and all(isinstance(item, int) for item in l):
            return bytes(l)

        for e in l:
            if isinstance(e, list):
                if r := self._find_in_list(e):
                    return r
            elif isinstance(e, dict):
                if r := self._find_in_dict(e):
                    return r
            elif isinstance(e, str):
                if self._valid_base64_challenge(e):
                    return base64.b64decode(e)

    @staticmethod
    def _substring_indices(
            content: bytes | str,
            sub: bytes | str
    ) -> list[int]:
        start, indices = 0, []
        while (start := content.find(sub, start)) != -1:
            indices.append(start)
            start += 1
        return indices

    @staticmethod
    def _get_pssh(
            content: bytes
    ) -> str | None:
        indices = WVFetch._substring_indices(content, b'pssh')
        for i in indices:
            size = int.from_bytes(content[i - 8:i], "big") * 2
            pssh = PSSH(content[i - 8:i - 8 + size])
            if pssh.system_id == PSSH.SystemId.Widevine:
                return pssh.dumps()

    @staticmethod
    def _extract_pssh(
            message: str | bytes
    ) -> str | None:
        if not message:
            return

        if isinstance(message, str):
            message = base64.b64decode(message)

        signed_message = SignedMessage()
        signed_message.ParseFromString(message)

        if signed_message.type != SignedMessage.MessageType.Value("LICENSE_REQUEST"):
            return

        license_request = LicenseRequest()
        license_request.ParseFromString(signed_message.msg)

        request_json = MessageToDict(license_request)
        if not (content_id := request_json.get('contentId')):
            return

        if pssh_data := content_id.get('widevinePsshData'):
            return pssh_data.get('psshData')[0]

        if init_data := content_id.get('initData'):
            init_bytes = base64.b64decode(init_data.get('initData'))
            if pssh := WVFetch._get_pssh(init_bytes):
                return pssh

        if webm_keyid := content_id.get('webmKeyId'):
            return base64.b64encode(
                WidevinePsshData(
                    key_ids=[base64.b64decode(webm_keyid.get('header'))],
                ).SerializeToString()
            ).decode()

    def _get_keys(
            self,
            url: str,
            headers: dict,
            body: Any
    ) -> list[str] | None:
        if not (devices := glob.glob(join(self.CDM_DIR, '*.wvd'))):
            raise Exception(f"No widevine devices detected inside the {self.CDM_DIR!r} directory")

        device = Device.load(devices[0])

        cdm = Cdm.from_device(device)
        session_id = cdm.open()

        if j := self._is_json(body):
            if isinstance(j, dict):
                challenge = self._find_in_dict(j)
            elif isinstance(j, list):
                challenge = self._find_in_list(j)
            else:
                raise Exception("Unsupported original json data")
        else:
            # assume bytes
            challenge = body
            if body:
                challenge = body.encode('ISO-8859-1')

        if challenge == b'\x08\x04':
            logging.error(
                "Certificate Request detected. "
                "Paste 'Copy as fetch' of the second license URL. The one that has the actual license request"
            )
            exit(-1)

        if not (pssh := WVFetch._extract_pssh(challenge)):
            pssh = input("[WARNING] Unable to extract PSSH from challenge, specify manually: ")

        license_challenge = cdm.get_license_challenge(session_id, PSSH(pssh))

        if body is not None and (j := self._is_json(body)):
            if isinstance(j, dict):
                response = requests.post(
                    url=url,
                    headers=headers,
                    json=self._replace_in_dict(j, base64.b64encode(license_challenge).decode('utf-8')),
                )
            elif isinstance(j, list):
                response = requests.post(
                    url=url,
                    headers=headers,
                    json=self._replace_in_list(j, base64.b64encode(license_challenge).decode('utf-8')),
                )
            else:
                raise Exception("Unsupported original json data")
        else:
            response = requests.post(
                url=url,
                headers=headers,
                data=license_challenge,
            )

        if response.status_code != 200:
            raise Exception(f"Unable to obtain decryption keys, got error code {response.status_code}: {response.text}")

        if j := self._is_json(response.text):
            if isinstance(j, dict):
                licence = self._find_in_dict(j)
            elif isinstance(j, list):
                licence = self._find_in_list(j)
            else:
                raise Exception("Unsupported returned json data")
        else:
            # assume bytes
            licence = response.content

        if not licence:
            raise Exception(f"Unable to locate license in response: {response.text}")

        try:
            cdm.parse_license(session_id, licence)
        except Exception as ex:
            raise Exception(f"Could not parse license {challenge!r}: {ex}")

        return list(
            map(
                lambda key: f"{key.kid.hex}:{key.key.hex()}",
                filter(
                    lambda key: key.type == 'CONTENT',
                    cdm.get_keys(session_id)
                )
            )
        )

    def process(self) -> str | None:
        if not (parsed := self._parse()):
            raise Exception("Unable to parse fetch string")
        url, data = parsed

        if (method := data.get('method')) != 'POST':
            raise Exception(f"Expected a POST request, not {method!r}")

        if not (body := data.get('body')):
            logging.warning("Empty request body, continuing anyways")

        if keys := self._get_keys(
                url=url,
                headers=data.get('headers'),
                body=body
        ):
            return ' '.join(sum([['--key', i] for i in keys], []))


if __name__ == '__main__':
    logging.basicConfig(format='[%(levelname)s]: %(message)s', level=logging.INFO)

    fetch = WVFetch()
    logging.info(fetch.process())
