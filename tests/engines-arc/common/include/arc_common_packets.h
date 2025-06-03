#ifndef ARC_COMMON_PACKETS_H
#define ARC_COMMON_PACKETS_H

/**
 * Upper limit on the number of arc CPUs, actual number of CPUs must
 * be less or equal to it.
 * Limits the size of statically allocated per cpu arrays.
 */
#define MAX_ARC_CPUS			255

/**
 * Total number of engine groups supported by firmware
 */
#define QMAN_ENGINE_GROUP_TYPE_COUNT	16

/**
 * Total number of Dcores
 */
#define MAX_DCORE			4

/**
 * Total number of Streams supported by a scheduler instance
 */
#define MAX_STREAMS			32

/**
 * Max Priorities
 */
#define MAX_ACP_PRIORITY		4

/**
 * Max number of groups that can be created per engine type
 */
#define MAX_ENGINE_TYPE_GROUPS		2

/**
 * Total number of Fence counters per scheduler instance
 */
#define GLOBAL_FENCE_COUNTERS_COUNT	32

/**
 * Size of the DCCM CCB buffer in bytes. All the commands in the CCB
 * must not cross this boundary.
 */
#define CCB_STREAM_BUFF_SIZE		256

/**
 * Message codes of SCAL for firmware usage
 * Updated by SCAL into SCHED_SCAL_STATUS register
 */
#define SCAL_INIT_COMPLETED		0x00010000


/**
 * \enum    qman_engine_type_t
 * \brief   Various engine types
 * \details Engine Types supported by Scheduler ARC
 */
enum qman_engine_type_t {
	QMAN_ENGINE_MME = 0,
	QMAN_ENGINE_TPC = 1,
	QMAN_ENGINE_NIC = 2,
	QMAN_ENGINE_RTR = 3,
	QMAN_ENGINE_EDMA = 4,
	QMAN_ENGINE_PDMA = 5,
	QMAN_ENGINE_TYPE_COUNT = 0x6,
	QMAN_ENGINE_LAST = 0x7,
};

#endif //ARC_COMMON_PACKETS_H
