from device import Device
from feature import Feature

DEFAULT_CONFIG = {
    "common": {
        "assign_qp_priority": "no",
        "cleanup": "yes",
        "cmpl": "cq",
        "compression_en": "no",
        "cq_type": "port",
        "data_cmp": "yes",
        "data_loc": "host",
        "data_size_shift": "18",
        "eq_poll": "yes",
        "force_wq_with_pmmu": "no",
        "keys_en": "no",
        "lpbk_qps_per_port": "0",
        "mtu": "8192",
        "odp_en": "no",
        "qps_per_port": "128",
        "red_dt": "",
        "red_op": "",
        "reduction_en": "no",
        "runtime_iterations": "1",
        "sack_en": "no",
        "single_alloc": "yes",
        "single_cmpl": "no",
        "test_opcode": "write",
        "user_cq_idx": "0",
        "user_fifo": "yes",
        "verbose": "1",
        "wait_for_cleanup": "no",
        "wq_loc": "host",
        "wqe_size_shift": "14",
        "wtd_en": "no",
    },
    "collective": {
        "scale_up_coll_qps": "0",
        "scale_up_coll_lpbk_qps": "0",
        "scale_out_coll_qps": "8",
        "scale_out_coll_lpbk_qps": "0",
        "coll_type": "direct",
        "coll_op": "legacy",
        "coll_patcher_op": "gen",
        "coll_data_type": "reduction",
    },
    "fna": {
        "fna_thresh": "6",
        "fna_cmpl": "reg",
        "atomic_val_loc": "dram",
    },
    "lag": {
        "first_index": "0",
        "last_index": "n",
        "qps_count": "8",
        "lpbk_qps_count": "0",
        "scale_out": "false",
        "use_keys": "false",
    },
    "migration": {
        "enable": "no",
        "old_port": "first",
        "new_port": "last",
        # Will trigger migration before the second iteration.
        "runtime_iterations_trigger": "1",
        "check_event": "yes",
    },
}

DEVICE_DEFAULT_CONFIG = {
    Device.GAUDI: {},
    Device.GAUDI2: {
        "common": {
            "user_fifo": "no",
        },
    },
    Device.GAUDI3: {},
}

DEVICE_DEFAULT_FEATURES = {
    Device.GAUDI: {Feature.DRAM, Feature.WQ_DRAM},
    Device.GAUDI2: {Feature.DRAM, Feature.WQ_DRAM},
    Device.GAUDI3: {Feature.DRAM, Feature.WQ_DRAM, Feature.SACK},
}
