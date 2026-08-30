from enum import Enum, unique


@unique
class Device(Enum):
    GAUDI = "GAUDI"
    GAUDI2 = "GAUDI2"
    GAUDI3 = "GAUDI3"
