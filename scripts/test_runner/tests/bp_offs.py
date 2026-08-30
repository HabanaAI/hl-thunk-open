from device import Device
from feature import Feature
from src.nic_root_test import NicRootTest

TESTS_BP_OFFS = [
    NicRootTest(
        supported_devices={Device.GAUDI2},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "data_size_shift": "24",
                "wqe_size_shift": "17",
            },
        },
    ),
    NicRootTest(
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC & Feature.NIC_200G,
        config_overrides={
            "common": {
                "qps_per_port": "12",
                "data_size_shift": "26",
                "wqe_size_shift": "19",
                "mtu": "4096",
            },
        },
    ),
    NicRootTest(
        name_prefix="400G",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC & Feature.NIC_400G,
        config_overrides={
            "common": {
                "data_size_shift": "28",
                "wqe_size_shift": "21",
                "mtu": "4096",
            },
        },
    ),
]
