from device import Device
from feature import Feature
from src.nic_root_test import NicRootTest

TESTS_FNA = [
    NicRootTest(
        name_prefix="FNA REG",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "cmpl": "sob",
                "data_size_shift": "16",
                "wqe_size_shift": "12",
                "single_alloc": "no",
                "test_opcode": "fna",
            },
        },
    ),
    NicRootTest(
        name_prefix="FNA CQ",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "cmpl": "sob",
                "data_size_shift": "16",
                "wqe_size_shift": "12",
                "test_opcode": "fna",
            },
            "fna": {
                "fna_cmpl": "cq_usr",
            },
        },
    ),
]
