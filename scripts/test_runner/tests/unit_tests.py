import os
import subprocess
from typing import Set

from device import Device
from feature import Feature
from src.binary_test import BinaryTest, BinaryTestGroup


def unit_tests(
    name: str,
    binary_path: os.PathLike,
    supported_devices: Set[Device],
    required_features: BooleanFunction,
) -> BinaryTestGroup:
    """
    Creates a BinaryTestGroup by automatically discovering tests from a binary executable.

    This function calls the provided binary with the '--list' flag to retrieve all available
    test cases from the binary. It then creates a BinaryTest object for each test and groups
    them into a BinaryTestGroup. If the binary is not found, it returns an empty test group.

    Parameters:
        name (str): The name of the test group
        binary_path (os.PathLike): Path to the test binary executable
        supported_devices (Set[Device]): Set of devices that can run these tests
        required_features (Set[Feature], optional): Set of features required to run these tests

    Returns:
        BinaryTestGroup: A group containing all tests discovered in the binary

    Example:
        >>> TESTS_EXAMPLE = unit_tests(
        ...     name="example tests",
        ...     binary_path=os.path.join(os.environ["TEST_BIN_DIR"], "example_binary"),
        ...     supported_devices={Device.GAUDI3, Device.GAUDI2},
        ...     required_features=Feature.DRAM | Feature.RUN_ONCE,
        ... )
    """
    try:
        result = subprocess.run(args=[binary_path, "--list"], capture_output=True)
    except FileNotFoundError:
        return BinaryTestGroup(name=name, binary_path=binary_path, tests=[], sudo=True)

    result.check_returncode()

    # The output of `--list` looks like this:
    # ↓↓↓ line number
    # 0  │
    # 1  │List of tests:
    # 2  │-----------------
    # 3  │
    # 4  │test1
    # 5  │test2
    # 6  │...
    # n-1│last_test
    # n  │
    #
    # So we're taking all the elements from line 4 until n-1
    test_names = result.stdout.decode().splitlines()[4:-1]

    tests = [
        BinaryTest(
            test_name=test_name,
            supported_devices=supported_devices,
            required_features=required_features,
            arguments=[f"--test={test_name}"],
        )
        for test_name in test_names
    ]

    return BinaryTestGroup(name=name, binary_path=binary_path, tests=tests, sudo=True)
