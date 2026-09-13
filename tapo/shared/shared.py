from enum import IntEnum, StrEnum


class RuleTimeType(StrEnum):
    NONE = "none"
    NORMAL = "normal"
    SUNRISE = "sunrise"
    SUNSET = "sunset"

class RuleMode(StrEnum):
    ONCE = "once"
    REPEAT = "repeat"

class CloudState(IntEnum):
    CONNECTED = 0
    DISCONNECTED = 1
    CONNECTING = 2
    DISCONNECTING = 3