import requests

from shared.error_code import ErrorCode


class TapoException(Exception):
    def __init__(self, error_code: int, msg: str):
        self.error_code = error_code
        self.msg = msg

        super().__init__(f"{error_code}: {msg}")

class TapoClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.session()
        self.token = None

    @staticmethod
    def get_result(data):
        if "error_code" in data and data["error_code"] != 0:
            error_code = data["error_code"]
            msg = data["msg"] if "msg" in data else ErrorCode.get_message_error(error_code)

            raise TapoException(error_code, msg)

        return data["result"] if "result" in data else None

    def _post_json(self, path: str, json: dict, timeout: int = None):
        params = {}
        if self.token:
            params["token"] = self.token

        response = self.session.post(f"{self.base_url}{path}", json=json, params=params, timeout=timeout)
        response.raise_for_status()

        content_type = response.headers.get("Content-Type")
        if not content_type or not "application/json" in content_type:
            raise ValueError(f"Not JSON ({content_type})")

        return TapoClient.get_result(response.json())

    def _post_html(self, path: str, data: bytes, params: dict = None, timeout: int = None):
        response = self.session.post(f"{self.base_url}{path}",
            data = data,
            params = params, headers = {
                "Content-Type": "text/plain"
            },
            timeout = timeout)
        response.raise_for_status()

        content_type = response.headers.get("Content-Type")
        if not content_type or not "text/html" in content_type:
            raise ValueError(f"Not HTML ({content_type})")

        return response.content

    def post_request(self, method, params = None, timeout = None):
        request = {
            "method": method
        }

        if params:
            request["params"] = params

        return self._post_json("", request, timeout)