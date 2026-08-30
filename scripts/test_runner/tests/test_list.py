from typing import List

from src.nic_root_test import NicRootTestGroup
from src.test import TestGroup
from tests.basic import TESTS_BASIC
from tests.bp_offs import TESTS_BP_OFFS
from tests.collective import TESTS_COLLECTIVE
from tests.ethernet import TESTS_ETHERNET
from tests.fna import TESTS_FNA
from tests.rdma_crash import TESTS_RDMA_CRASH

TEST_LIST: List[TestGroup] = [
    NicRootTestGroup(
        name="basic",
        group_parameter="test_nic_lpbk_basic",
        tests=TESTS_BASIC,
    ),
    NicRootTestGroup(
        name="fna",
        group_parameter="test_nic_lpbk_atomic_fna",
        tests=TESTS_FNA,
    ),
    NicRootTestGroup(
        name="collective",
        group_parameter="test_nic_lpbk_collective",
        config_overrides={
            "common": {
                "cmpl": "sob",
                "qps_per_port": "0",
                "single_alloc": "no",
                "wq_loc": "device",
            },
        },
        tests=TESTS_COLLECTIVE,
    ),
    NicRootTestGroup(
        name="bp_offs",
        group_parameter="test_nic_lpbk_bp_offs",
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "cmpl": "sob",
                "user_fifo": "yes",
            },
        },
        tests=TESTS_BP_OFFS,
    ),
    TESTS_ETHERNET,
    TESTS_RDMA_CRASH,
    #TESTS_MULTI_CONTEXT,
]

group_names = [group.name for group in TEST_LIST]
if len(set(group_names)) != len(group_names):
    raise AssertionError("Test list has groups with duplicate names!")

for group in TEST_LIST:
    test_names = [test.name for test in group.test_list]

    if len(set(test_names)) != len(test_names):
        raise AssertionError(f"Group {group.name} has tests with duplicate names!")
