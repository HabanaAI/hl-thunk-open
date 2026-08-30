from dataclasses import dataclass
from typing import List, Tuple

import feature
from feature import Feature


@dataclass(frozen=True)
class TestParametrization:
    group: str
    param: str
    values: List[Tuple[str, List[Feature] | None]]


TEST_PARAMETERIZATION_DATA_LOC = TestParametrization(
    "common",
    "data_loc",
    [
        ("host"),
        ("dram", Feature.DRAM),
    ],
)

TEST_PARAMETERIZATION_WQ_LOC = TestParametrization(
    "common",
    "wq_loc",
    [
        ("host"),
        ("device", Feature.DRAM & Feature.WQ_DRAM),
    ],
)

TEST_PARAMETERIZATION_CQ_TYPE = TestParametrization(
    "common",
    "cq_type",
    [
        ("port"),
        ("device", Feature.DEVICE_CQ & ~Feature.PLDM),
    ],
)

TEST_PARAMETERIZATION_CMPL = TestParametrization(
    "common",
    "cmpl",
    [
        ("cq"),
        ("sob"),
    ],
)

TEST_PARAMETERIZATION_SINGLE_ALLOC = TestParametrization(
    "common",
    "single_alloc",
    [
        # Use single alloc on simulator or pldm
        ("yes", Feature.SIM | Feature.PLDM),
        # Don't use single alloc on ASIC
        ("no", Feature.ASIC),
    ],
)

TEST_PARAMETERIZATION_SACK = TestParametrization(
    "common",
    "sack_en",
    [
        # Use selective ack on ASIC or PLDM that support sack
        ("yes", (Feature.ASIC | Feature.PLDM) & Feature.SACK),
        # Don't use selective ack:
        (
            "no",
            # SIM, or ASIC or PLDM that doesn't support SACK
            Feature.SIM | ((Feature.ASIC | Feature.PLDM) & ~Feature.SACK),
        ),
    ],
)
