import parameterizations
from device import Device
from feature import Feature
from src.nic_root_test import NicRootTest

TESTS_COLLECTIVE = [
    NicRootTest(
        name_prefix="context_legacy",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "scale_out_coll_qps": "1",
                "coll_type": "context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="context_multi_lag",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "scale_out_coll_qps": "1",
                "coll_type": "context",
                "coll_op": "multi_lag",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="context_multi_rank",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "scale_out_coll_qps": "1",
                "coll_type": "context",
                "coll_op": "multi_rank",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="context_multi_context",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="context_wr_rdv",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="context_rd_rdv",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "rd-rdv",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="context_vop",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "rdv_type": "v-op",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
                "coll_patcher_op": "vop",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="context_wr_rdv_hbm_reduct_down_and_up",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "down_and_up",
                "red_op": "add",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
    ),
    NicRootTest(
        name_prefix="context_wr_rdv_hbm_reduct_downscale",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "downscale",
                "red_op": "add",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
    ),
    NicRootTest(
        name_prefix="context_wr_rdv_hbm_reduct",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "bf16",
                "red_op": "add",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
    ),
    NicRootTest(
        name_prefix="context_wr_rdv_hbm_reduct_upscale",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "upscale",
                "red_op": "max",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
    ),
    NicRootTest(
        name_prefix="context_ms_z",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "rdv_type": "ms",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
                "coll_rank_axis": "z",
                "coll_ranks_num": "3",
            },
        },
    ),
    NicRootTest(
        name_prefix="context_compression_multi_context",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "compression_en": "yes",
                "sack_en": "yes",
            },
            "collective": {
                "coll_type": "context",
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="direct_legacy",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "scale_out_coll_qps": "1",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_multi_lag",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "scale_out_coll_qps": "1",
                "coll_op": "multi_lag",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_multi_rank",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "scale_out_coll_qps": "1",
                "coll_op": "multi_rank",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_multi_context",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_scale_up",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
		"scale_up_coll_qps": "128",
		"scale_out_coll_qps": "0",
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_wr_rdv",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
            },
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_rd_rdv",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "rd-rdv",
            },
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_vop",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "rdv_type": "v-op",
            },
            "collective": {
                "coll_op": "multi_context",
                "coll_patcher_op": "vop",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="direct_wr_rdv_hbm_reduct_down_and_up",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "down_and_up",
                "red_op": "add",
            },
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_wr_rdv_hbm_reduct_downscale",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "downscale",
                "red_op": "add",
            },
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_wr_rdv_hbm_reduct",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "bf16",
                "red_op": "add",
            },
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_wr_rdv_hbm_reduct_upscale",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "cmpl": "cq",
                "data_loc": "dram",
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "reduction_en": "yes",
                "red_dt": "upscale",
                "red_op": "max",
            },
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_ms_x",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "rdv_type": "ms",
            },
            "collective": {
                "coll_op": "multi_context",
                "coll_rank_axis": "x",
                "coll_ranks_num": "3",
            },
        },
    ),
    NicRootTest(
        name_prefix="direct_ms_y",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "rdv_type": "ms",
            },
            "collective": {
                "coll_op": "multi_context",
                "coll_rank_axis": "y",
                "coll_ranks_num": "3",
            },
        },
    ),
    NicRootTest(
        name_prefix="direct_ms_z",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
                "rdv_type": "ms",
            },
            "collective": {
                "coll_op": "multi_context",
                "coll_rank_axis": "z",
                "coll_ranks_num": "3",
            },
        },
    ),
    NicRootTest(
        name_prefix="direct_wr_rdv_disregard_rank",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "test_opcode": "wr-rdv",
            },
            "collective": {
                "coll_op": "multi_context",
                "disregard_rank": "yes",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_multi_context_disregard_rank",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "collective": {
                "coll_op": "multi_context",
                "disregard_rank": "yes",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_compression_multi_context",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "compression_en": "yes",
                "sack_en": "yes",
            },
            "collective": {
                "coll_op": "multi_context",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="direct_legacy_migration",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "runtime_iterations": "2",
            },
            "collective": {
                "scale_out_coll_qps": "1",
            },
            "migration": {
                "enable": "yes",
            },
        },
    ),
    NicRootTest(
        name_prefix="direct_wr_rdv_migration",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "runtime_iterations": "2",
                "test_opcode": "wr-rdv",
            },
            "collective": {
                "coll_op": "multi_context",
            },
            "migration": {
                "enable": "yes",
            },
        },
    ),
]
