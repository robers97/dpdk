/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 Cisco Systems, Inc.  All rights reserved.
 */

#ifndef _RTE_ETH_MIIF_H_
#define _RTE_ETH_MIIF_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif				/* GNU_SOURCE */

#include <sys/queue.h>

#include <rte_ethdev_driver.h>
#include <rte_ether.h>
#include <rte_interrupts.h>

#include "miif.h"

#define ETH_MIIF_DEFAULT_SOCKET_FILENAME	"/run/miif.sock"
#define ETH_MIIF_DEFAULT_RING_SIZE		10
#define ETH_MIIF_DEFAULT_PKT_BUFFER_SIZE	2048

#define ETH_MIIF_MAX_NUM_Q_PAIRS		255
#define ETH_MIIF_MAX_LOG2_RING_SIZE		14
#define ETH_MIIF_MAX_REGION_NUM		256

#define ETH_MIIF_SHM_NAME_SIZE			32
#define ETH_MIIF_DISC_STRING_SIZE		96
#define ETH_MIIF_SECRET_SIZE			24

extern int miif_logtype;

#define MIIF_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, miif_logtype, \
		"%s(): " fmt "\n", __func__, ##args)

enum miif_role_t {
	MIIF_ROLE_MASTER,
	MIIF_ROLE_SLAVE,
};

struct miif_region {
	void *addr;				/**< shared memory address */
	miif_region_size_t region_size;	        /**< shared memory size */
	uint32_t pkt_buffer_offset;
	/**< offset from 'addr' to first packet buffer */
};

struct miif_queue {
	struct rte_mempool *mempool;		/**< mempool for RX packets */
	struct pmd_internals *pmd;		/**< device internals */

	miif_ring_type_t type;			/**< ring type */
	miif_region_index_t region;		/**< shared memory region index */

	uint16_t in_port;			/**< port id */

	miif_region_offset_t ring_offset;
	/**< ring offset from start of shm region (ring - miif_region.addr) */

	uint16_t last_head;			/**< last ring head */
	uint16_t last_tail;			/**< last ring tail */

	/* rx/tx info */
	uint64_t n_pkts;			/**< number of rx/tx packets */
	uint64_t n_bytes;			/**< number of rx/tx bytes */

	miif_ring_t *ring;			/**< pointer to ring */

	struct rte_intr_handle intr_handle;	/**< interrupt handle */

	miif_log2_ring_size_t log2_ring_size;	/**< log2 of ring size */
};

struct pmd_internals {
	miif_interface_id_t id;		/**< unique id */
	enum miif_role_t role;			/**< device role */
	uint32_t flags;				/**< device status flags */
#define ETH_MIIF_FLAG_CONNECTING	(1 << 0)
/**< device is connecting */
#define ETH_MIIF_FLAG_CONNECTED	(1 << 1)
/**< device is connected */
#define ETH_MIIF_FLAG_ZERO_COPY	(1 << 2)
/**< device is zero-copy enabled */
#define ETH_MIIF_FLAG_DISABLED		(1 << 3)
/**< device has not been configured and can not accept connection requests */

	char *socket_filename;			/**< pointer to socket filename */
	char secret[ETH_MIIF_SECRET_SIZE]; /**< secret (optional security parameter) */

	struct miif_control_channel *cc;	/**< control channel */

	/* remote info */
	char remote_name[RTE_DEV_NAME_MAX_LEN];		/**< remote app name */
	char remote_if_name[RTE_DEV_NAME_MAX_LEN];	/**< remote peer name */

	struct {
		miif_log2_ring_size_t log2_ring_size; /**< log2 of ring size */
		uint8_t num_s2m_rings;		/**< number of slave to master rings */
		uint8_t num_m2s_rings;		/**< number of master to slave rings */
		uint16_t pkt_buffer_size;	/**< buffer size */
	} cfg;					/**< Configured parameters (max values) */

	struct {
		miif_log2_ring_size_t log2_ring_size; /**< log2 of ring size */
		uint8_t num_s2m_rings;		/**< number of slave to master rings */
		uint8_t num_m2s_rings;		/**< number of master to slave rings */
		uint16_t pkt_buffer_size;	/**< buffer size */
	} run;
	/**< Parameters used in active connection */

	char local_disc_string[ETH_MIIF_DISC_STRING_SIZE];
	/**< local disconnect reason */
	char remote_disc_string[ETH_MIIF_DISC_STRING_SIZE];
	/**< remote disconnect reason */

	struct rte_vdev_device *vdev;		/**< vdev handle */
};

struct pmd_process_private {
	struct miif_region *regions[ETH_MIIF_MAX_REGION_NUM];
	/**< shared memory regions */
	miif_region_index_t regions_num;	/**< number of regions */
	void *shared_ea;
};

/**
 * Unmap shared memory and free regions from memory.
 *
 * @param proc_private
 *   device process private data
 */
void miif_free_regions(struct pmd_process_private *proc_private);

/**
 * Finalize connection establishment process. Map shared memory file
 * (master role), initialize ring queue, set link status up.
 *
 * @param dev
 *   miif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int miif_connect(struct rte_eth_dev *dev);

/**
 * Create shared memory file and initialize ring queue.
 * Only called by slave when establishing connection
 *
 * @param dev
 *   miif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int miif_init_regions_and_queues(struct rte_eth_dev *dev);

/**
 * Get miif version string.
 *
 * @return
 *   - miif version string
 */
const char *miif_version(void);

#ifndef MFD_HUGETLB
// Empty in miif
#endif				/* MFD_HUGETLB */

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING       0x0002U
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)

#define F_SEAL_SEAL     0x0001	/* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002	/* prevent file from shrinking */
#define F_SEAL_GROW     0x0004	/* prevent file from growing */
#define F_SEAL_WRITE    0x0008	/* prevent writes */
#endif

#endif				/* RTE_ETH_MIIF_H */
