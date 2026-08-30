import os

from device import Device
from feature import Feature
from src.binary_test import BinaryTest, BinaryTestGroup


def ethernet_test(
    name,
    arguments,
    supported_devices={Device.GAUDI, Device.GAUDI2, Device.GAUDI3},
):
    return BinaryTest(
        test_name=name + " (SIM)",
        supported_devices=supported_devices,
        required_features=~Feature.MAC_LOOPBACK
        & ~Feature.ETH_LOOPBACK
        & Feature.SIM,
        arguments=arguments,
    ), BinaryTest(
        test_name=name + " (ASIC)",
        supported_devices=supported_devices,
        required_features=Feature.MAC_LOOPBACK
        & Feature.ETH_LOOPBACK
        & (Feature.ASIC | Feature.PLDM),
        arguments=arguments + ["--single_port"],
    )


TESTS_ETHERNET = BinaryTestGroup(
    name="ethernet",
    binary_path=os.path.join(
        os.environ["HLTHUNK_ROOT"], "tests/common/run_eth_test.sh"
    ),
    tests=[
        *ethernet_test("ping", ["--tool", "PING"]),
        *ethernet_test("iperf", ["--tool", "IPERF"]),
        *ethernet_test("iperf mtu", ["--tool", "IPERF", "--mtu", "1000"]),
        *ethernet_test("iperf down up 5 times", ["--tool", "IPERF", "--down_up", "5"]),
        *ethernet_test(
            "iperf soft reset",
            ["--tool", "IPERF", "--reset", "soft"],
            supported_devices={Device.GAUDI2, Device.GAUDI3},
        ),
        *ethernet_test(
            "iperf hard reset",
            ["--tool", "IPERF", "--reset", "hard"],
            supported_devices={Device.GAUDI, Device.GAUDI2, Device.GAUDI3},
        ),
    ],
)
