import itertools
import os

from device import Device
from feature import Feature
from src.binary_test import BinaryTest, BinaryTestGroup


def __rdma_crash_test(
    device: Device,
):
    name = device.name.lower()

    # Due to some bug with gaudi1 coral sim, the hard reset test doesn't work on simulator, so we'll
    # only run the hard reset test on ASIC.
    if device == Device.GAUDI:
        hard_reset_env = Feature.ASIC
    else:
        hard_reset_env = Feature.ASIC | Feature.SIM

    return [
        BinaryTest(
            test_name=f"RDMA Crash - Hard ({name})",
            supported_devices={device},
            required_features=Feature.MAC_LOOPBACK & hard_reset_env,
            arguments=["-r", "-C", name],
        ),
        BinaryTest(
            test_name=f"RDMA Crash - Sim ({name})",
            supported_devices={device},
            required_features=Feature.MAC_LOOPBACK & Feature.SIM,
            arguments=["-r", "-C", name, "-s"],
        ),
    ]

TESTS_RDMA_CRASH = BinaryTestGroup(
    name="RDMA crash",
    binary_path=os.path.join(
        os.environ["HLTHUNK_ROOT"], "tests/common/run_rdma_crash_test.sh"
    ),
    tests=list(
        itertools.chain.from_iterable(
            [__rdma_crash_test(d) for d in [Device.GAUDI, Device.GAUDI2, Device.GAUDI3]]
        )
    ),
)
