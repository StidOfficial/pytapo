from enum import IntEnum


class ErrorCode(IntEnum):
    CLOUD_TOKEN_EXPIRED_OR_INVALID = -20675
    INCORRECT_EMAIL_OR_PASSWORD = -20601
    MISSING_CREDENTIALS = -20104
    INVALID_CREDENTIALS = -1501
    RATE_LIMIT_EXCEEDED = -1301
    SESSION_PARAMS_ERROR = -1101
    INVALID_TERMINAL_UUID = -1012
    INVALID_PUBLIC_KEY_LENGTH = -1010
    INVALID_REQUEST_PARAMS = -1008
    REQUEST_LENGTH_ERROR = -1006
    AES_DECODE_FAIL = -1005
    MALFORMED_JSON_REQUEST = -1003
    TRANSPORT_NO_AVAILABLE_ERROR = -1002
    OK = 0
    NULL_TRANSPORT_ERROR = 1000
    COMMAND_CANCEL_ERROR = 1001
    TRANSPORT_NOT_AVAILABLE_ERROR = 1002
    DEVICE_SUPPORT_KLAP_PROTOCOL = 1003
    HANDSHAKE_FAILED = 1100
    LOGIN_FAILED = 1111
    HTTP_TRANSPORT_ERROR = 1112
    MULTIREQUEST_FAILED = 1200
    SESSION_TIMEOUT = 9999

    @staticmethod
    def get_message_error(error_code: int) -> str:
        error = ErrorCode(error_code)

        if error == ErrorCode.CLOUD_TOKEN_EXPIRED_OR_INVALID:
            return "Cloud token expired or invalid"
        elif error == ErrorCode.INCORRECT_EMAIL_OR_PASSWORD:
            return "Incorrect email or password"
        elif error == ErrorCode.MISSING_CREDENTIALS:
            return "Missing credentials"
        elif error == ErrorCode.INVALID_CREDENTIALS:
            return "Invalid credentials"
        elif error == ErrorCode.RATE_LIMIT_EXCEEDED:
            return "Rate limit exceeded"
        elif error == ErrorCode.SESSION_PARAMS_ERROR:
            return "Session params error"
        elif error == ErrorCode.INVALID_TERMINAL_UUID:
            return "Invalid terminal UUID"
        elif error == ErrorCode.INVALID_PUBLIC_KEY_LENGTH:
            return "Invalid public key length"
        elif error == ErrorCode.INVALID_REQUEST_PARAMS:
            return "Invalid request params"
        elif error == ErrorCode.REQUEST_LENGTH_ERROR:
            return "Request length error"
        elif error == ErrorCode.AES_DECODE_FAIL:
            return "AES Decode Fail"
        elif error == ErrorCode. MALFORMED_JSON_REQUEST:
            return "Malformed json request"
        elif error == ErrorCode.TRANSPORT_NO_AVAILABLE_ERROR:
            return "Transport not available error"
        elif error == ErrorCode.NULL_TRANSPORT_ERROR:
            return "Null transport error"
        elif error == ErrorCode.COMMAND_CANCEL_ERROR:
            return "Command cancel error"
        elif error == ErrorCode.TRANSPORT_NOT_AVAILABLE_ERROR:
            return "Transport not available error"
        elif error == ErrorCode.DEVICE_SUPPORT_KLAP_PROTOCOL:
            return "Device supports KLAP protocol - Legacy login not supported"
        elif error == ErrorCode.HANDSHAKE_FAILED:
            return "Handshake failed"
        elif error == ErrorCode.LOGIN_FAILED:
            return "Login failed"
        elif error == ErrorCode.HTTP_TRANSPORT_ERROR:
            return "Http transport error"
        elif error == ErrorCode.MULTIREQUEST_FAILED:
            return "Multirequest failed"
        elif error == ErrorCode.SESSION_TIMEOUT:
            return "Session Timeout"
        else:
            return None