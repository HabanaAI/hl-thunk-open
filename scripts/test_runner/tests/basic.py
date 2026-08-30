import feature
import parameterizations
from device import Device
from feature import Feature
from src.nic_root_test import NicRootTest

TESTS_BASIC = [
    NicRootTest(
        name_prefix="baseline",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK,
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_CQ_TYPE,
            parameterizations.TEST_PARAMETERIZATION_SINGLE_ALLOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="511 QPs",
        supported_devices={Device.GAUDI2},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "qps_per_port": "511",
                "data_size_shift": "15",
                "wqe_size_shift": "12",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="User-fifo submission",
        supported_devices={Device.GAUDI2},
        required_features=Feature.MAC_LOOPBACK
        & (Feature.ASIC | Feature.SIM)
        & Feature.DRAM,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "user_fifo": "yes",
                "data_loc": "dram",
            },
        },
    ),
    NicRootTest(
        name_prefix="WQ MMU",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.SACK,
        config_overrides={
            "common": {
                "force_wq_with_pmmu": "yes",
                "sack_en": "yes",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="WQ MMU",
        supported_devices={Device.GAUDI2},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "force_wq_with_pmmu": "yes",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="WQ MMU many QPs",
        supported_devices={Device.GAUDI2},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "qps_per_port": "1024",
                "single_cmpl": "yes",
                "data_size_shift": "15",
                "wqe_size_shift": "12",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="SOB",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK,
        config_overrides={
            "common": {
                "cmpl": "sob",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="SOB WTD",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC & Feature.SACK,
        config_overrides={
            "common": {
                "cmpl": "sob",
                "qps_per_port": "8",
                "wtd_en": "yes",
                "single_alloc": "no",
                "sack_en": "yes",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="WTD",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "wtd_en": "yes",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_CQ_TYPE,
            parameterizations.TEST_PARAMETERIZATION_SINGLE_ALLOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="WR-RDV",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "data_size_shift": "19",
                # Enable WTD because we don't support WQ on HBM without WTD
                "wtd_en": "yes",
                "test_opcode": "wr-rdv",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_CQ_TYPE,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="RD-RDV",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "data_size_shift": "19",
                # Enable WTD because we don't support WQ on HBM without WTD
                "wtd_en": "yes",
                "test_opcode": "rd-rdv",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_CQ_TYPE,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="SOB RD-RDV",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "cmpl": "sob",
                "data_size_shift": "19",
                # Enable WTD because we don't support WQ on HBM without WTD
                "wtd_en": "yes",
                "test_opcode": "rd-rdv",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="CC Swift",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC & Feature.SACK,
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "single_alloc": "no",
                "cc_mode": "swift",
                "sack_en": "yes",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="CC bbr",
        supported_devices={Device.GAUDI2},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "ports": "8 22 23",
                "qps_per_port": "8",
                "single_alloc": "no",
                "cc_mode": "bbr",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="Reduction bf16",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "data_loc": "dram",
                "cmpl": "sob",
                "mtu": "4096",
                "single_alloc": "no",
                "reduction_en": "yes",
                "red_op": "add",
                "red_dt": "bf16",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="Reduction upscale",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "data_loc": "dram",
                "mtu": "4096",
                "single_alloc": "no",
                "reduction_en": "yes",
                "red_op": "max",
                "red_dt": "upscale",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="Reduction downscale",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "data_loc": "dram",
                "data_size_shift": "17",
                "wqe_size_shift": "13",
                "mtu": "4096",
                "single_alloc": "no",
                "reduction_en": "yes",
                "red_op": "add",
                "red_dt": "downscale",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="Multi-packet WQE",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC & Feature.SACK,
        config_overrides={
            "common": {
                "qps_per_port": "1",
                "data_size_shift": "24",
                "wqe_size_shift": "20",
                "sack_en": "yes",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_CMPL,
        ],
    ),
    NicRootTest(
        name_prefix="Compression WR",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & Feature.ASIC
        & Feature.DRAM
        & Feature.SACK,
        config_overrides={
            "common": {
                "data_loc": "dram",
                "sack_en": "yes",
                "compression_en": "yes",
            }
        },
    ),
    NicRootTest(
        name_prefix="Compression reduct",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & Feature.ASIC
        & Feature.DRAM
        & Feature.SACK,
        config_overrides={
            "common": {
                "data_loc": "dram",
                "single_alloc": "no",
                "sack_en": "yes",
                "compression_en": "yes",
                "reduction_en": "yes",
                "red_op": "add",
                "red_dt": "bf16",
            }
        },
    ),
    NicRootTest(
        name_prefix="Compression WR-RDV",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & Feature.ASIC
        & Feature.DRAM
        & Feature.SACK,
        config_overrides={
            "common": {
                "data_loc": "dram",
                "data_size_shift": "19",
                "sack_en": "yes",
                "compression_en": "yes",
                "test_opcode": "wr-rdv",
            }
        },
    ),
    NicRootTest(
        name_prefix="Compression WTD",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK
        & Feature.ASIC
        & Feature.DRAM
        & Feature.SACK,
        config_overrides={
            "common": {
                "data_loc": "dram",
                "single_alloc": "no",
                "wtd_en": "yes",
                "sack_en": "yes",
                "compression_en": "yes",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_WQ_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="LPBK QPS",
        supported_devices={Device.GAUDI3},
        required_features=(~Feature.MAC_LOOPBACK) & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "qps_per_port": "16",
                "lpbk_qps_per_port": "16",
                "single_alloc": "no",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_CMPL,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="Many LPBK QPS",
        supported_devices={Device.GAUDI3},
        required_features=(~Feature.MAC_LOOPBACK) & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "lpbk_qps_per_port": "128",
                "single_alloc": "no",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
            parameterizations.TEST_PARAMETERIZATION_SACK,
        ],
    ),
    NicRootTest(
        name_prefix="Encap vxlan",
        supported_devices={Device.GAUDI2},
        required_features=Feature.MAC_LOOPBACK & (Feature.ASIC | Feature.SIM),
        config_overrides={
            "common": {
                "qps_per_port": "1",
                "encap_type": "vxlan",
            }
        },
    ),
    NicRootTest(
        name_prefix="Plain RDMA",
        supported_devices={Device.GAUDI2, Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK,
        config_overrides={
            "common": {
                "qps_per_port": "8",
                "plain_rdma": "yes",
                "user_fifo": "yes",
            }
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_DATA_LOC,
        ],
    ),
    NicRootTest(
        name_prefix="Migration",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "runtime_iterations": "2",
            },
            "migration": {
                "enable": "yes",
            },
        },
        parameterization=[
            parameterizations.TEST_PARAMETERIZATION_CMPL,
        ],
    ),
    NicRootTest(
        name_prefix="Migration RD-RDV",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "qps_per_port": "8",
                "runtime_iterations": "2",
                "test_opcode": "rd-rdv",
            },
            "migration": {
                "enable": "yes",
            },
        },
    ),
    NicRootTest(
        name_prefix="Migration WR-RDV",
        supported_devices={Device.GAUDI3},
        required_features=Feature.MAC_LOOPBACK & Feature.ASIC,
        config_overrides={
            "common": {
                "data_size_shift": "19",
                "qps_per_port": "8",
                "runtime_iterations": "2",
                "test_opcode": "wr-rdv",
            },
            "migration": {
                "enable": "yes",
            },
        },
    ),
]
