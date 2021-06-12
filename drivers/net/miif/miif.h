/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2020 International Business Machines, Inc. All rights resevered.
 */

#ifndef _MIIF_H_
#define _MIIF_H_

#include <mi_shmem_api.h>

#define MIIF_COOKIE		0x3E31F20
#define MIIF_VERSION_MAJOR	2
#define MIIF_VERSION_MINOR	0
#define MIIF_VERSION		((MIIF_VERSION_MAJOR << 8) | MIIF_VERSION_MINOR)
#define MIIF_NAME_SZ		32
#define MIIF_POOL_SIZE	        100ULL*1024*1024*1024


/* POWER9 cacheline size
 * TODO: make this more robust*/
#define CACHELINE_SIZE 0x80
#define CACHELINE_MASK (CACHELINE_SIZE - 1)

/*Hints the PCU on bringing a line into cache*/
#define TOUCH_LINE(addr) \
	asm volatile ( \
		"dcbtst 0x0,%0,0x0\n" \
		: \
		: "b"(addr) \
		: "memory" \
	)

#define FLUSH_LINE(addr) \
	asm volatile ( \
		"dcbf 0x0,%0\n" \
		: \
		: "b"(addr) \
		: "memory" \
	)

#define FLUSH_LINE_SYNC(addr) \
	asm volatile ( \
		"dcbf 0x0,%0\n" \
		"lwsync\n" \
		: \
		: "b"(addr) \
		: "memory" \
	)

#define LWSYNC \
	asm volatile ( \
	       "lwsync\n" \
	       : \
               : \
               : "memory" \
        )

#define COPY_PASTE(src, dst, offset) \
	asm volatile ( \
		"copy %2,%1\n" \
		"paste. %1,%3\n" \
		"mfocrf %0, 0x80\n" \
		: "=r"(cr0) \
		: "b"(offset), "b"(src), "b"(dst) \
		: "memory", "cr0" \
	)

static inline void flush_memory_block (void *addr, uint64_t size, int sync) {
	uint64_t start_addr = (uint64_t) addr;
	uint64_t end_addr = start_addr + size;

	// If the start address is not aligned to the cache line size let's just flush it
	//  right away and then align the address to the beginning of the next cache line.
	//  We can now safely continue flushing in a loop with CACHELINE_SIZE as offset.
	if ((start_addr & CACHELINE_MASK) != 0) {
		if (sync) {
			FLUSH_LINE_SYNC(start_addr);
		}
		else {
			FLUSH_LINE(start_addr);
		}
		start_addr += CACHELINE_SIZE - (start_addr & CACHELINE_MASK);
	}

	for ( ; start_addr < end_addr; start_addr += CACHELINE_SIZE){
		if (sync) {
			FLUSH_LINE_SYNC(start_addr);
		}
		else {
			FLUSH_LINE(start_addr);
		}
	}
}

static inline void touch_memory_block (void *addr, uint64_t size) {
	uint64_t start_addr = (uint64_t) addr;
	uint64_t end_addr = start_addr + size;

	if ((start_addr & CACHELINE_MASK) != 0) {
		TOUCH_LINE(start_addr);
		start_addr += CACHELINE_SIZE - (start_addr & CACHELINE_MASK);
        }

	for ( ; start_addr < end_addr; start_addr += CACHELINE_SIZE){
		TOUCH_LINE(start_addr);
	}
}


/*
 * S2M: direction slave -> master
 * M2S: direction master -> slave
 */

/*
 *  Type definitions
 */

typedef enum miif_msg_type {
	MIIF_MSG_TYPE_NONE,
	MIIF_MSG_TYPE_ACK,
	MIIF_MSG_TYPE_HELLO,
	MIIF_MSG_TYPE_INIT,
	MIIF_MSG_TYPE_ADD_REGION,
	MIIF_MSG_TYPE_ADD_RING,
	MIIF_MSG_TYPE_CONNECT,
	MIIF_MSG_TYPE_CONNECTED,
	MIIF_MSG_TYPE_DISCONNECT,
} miif_msg_type_t;

typedef enum {
	MIIF_RING_S2M, /**< buffer ring in direction slave -> master */
	MIIF_RING_M2S, /**< buffer ring in direction master -> slave */
} miif_ring_type_t;

typedef enum {
	MIIF_INTERFACE_MODE_ETHERNET,
	MIIF_INTERFACE_MODE_IP,
	MIIF_INTERFACE_MODE_PUNT_INJECT,
} miif_interface_mode_t;

typedef uint16_t miif_region_index_t;
typedef uint32_t miif_region_offset_t;
typedef uint64_t miif_region_size_t;
typedef void*    miif_address_t;
typedef uint16_t miif_ring_index_t;
typedef uint32_t miif_interface_id_t;
typedef uint16_t miif_version_t;
typedef uint8_t miif_log2_ring_size_t;

/*
 *  Socket messages
 */

 /**
  * M2S
  * Contains master interfaces configuration.
  */
typedef struct __rte_packed {
	uint8_t name[MIIF_NAME_SZ]; /**< Client app name. In this case DPDK version */
	miif_version_t min_version; /**< lowest supported miif version */
	miif_version_t max_version; /**< highest supported miif version */
	miif_region_index_t max_region; /**< maximum num of regions */
	miif_ring_index_t max_m2s_ring; /**< maximum num of M2S ring */
	miif_ring_index_t max_s2m_ring; /**< maximum num of S2M rings */
	miif_log2_ring_size_t max_log2_ring_size; /**< maximum ring size (as log2) */
} miif_msg_hello_t;

/**
 * S2M
 * Contains information required to identify interface
 * to which the slave wants to connect.
 */
typedef struct __rte_packed {
	miif_version_t version;		/**< miif version */
	miif_interface_id_t id;		/**< interface id */
	miif_interface_mode_t mode:8;		/**< interface mode */
	uint8_t secret[24];			/**< optional security parameter */
	uint8_t name[MIIF_NAME_SZ]; /**< Client app name. In this case DPDK version */
	void*    mi_pool_ea;
	uint64_t mi_pool_size;
} miif_msg_init_t;

/**
 * S2M
 * Request master to add new shared memory region to master interface.
 */
typedef struct __rte_packed {
     miif_address_t base;               /**< mi region base address */
     miif_region_index_t index;		/**< mi region index */
     miif_region_size_t size;		/**< mi region size */
} miif_msg_add_region_t;

/**
 * S2M
 * Request master to add new ring to master interface.
 */
typedef struct __rte_packed {
	uint16_t flags;				/**< flags */
#define MIIF_MSG_ADD_RING_FLAG_S2M 1		/**< ring is in S2M direction */
	miif_ring_index_t index;		/**< ring index */
	miif_region_index_t region; /**< region index on which this ring is located */
	miif_region_offset_t offset;		/**< buffer start offset */
	miif_log2_ring_size_t log2_ring_size;	/**< ring size (log2) */
	uint16_t private_hdr_size;		/**< used for private metadata */
} miif_msg_add_ring_t;

/**
 * S2M
 * Finalize connection establishment.
 */
typedef struct __rte_packed {
	uint8_t if_name[MIIF_NAME_SZ];		/**< slave interface name */
} miif_msg_connect_t;

/**
 * M2S
 * Finalize connection establishment.
 */
typedef struct __rte_packed {
	uint8_t if_name[MIIF_NAME_SZ];		/**< master interface name */
} miif_msg_connected_t;

/**
 * S2M & M2S
 * Disconnect interfaces.
 */
typedef struct __rte_packed {
	uint32_t code;				/**< error code */
	uint8_t string[96];			/**< disconnect reason */
} miif_msg_disconnect_t;

typedef struct __rte_packed __rte_aligned(128)
{
	miif_msg_type_t type:16;
	union {
		miif_msg_hello_t hello;
		miif_msg_init_t init;
		miif_msg_add_region_t add_region;
		miif_msg_add_ring_t add_ring;
		miif_msg_connect_t connect;
		miif_msg_connected_t connected;
		miif_msg_disconnect_t disconnect;
	};
} miif_msg_t;

/*
 *  Ring and Descriptor Layout
 */

/**
 * Buffer descriptor.
 */
typedef struct __rte_packed {
	uint16_t flags;				/**< flags */
#define MIIF_DESC_FLAG_NEXT 1			/**< is chained buffer */
	miif_region_index_t region;             /**< region index on which the buffer is located */
	uint32_t length;			/**< buffer length */
	miif_region_offset_t offset;		/**< buffer offset */
	uint32_t metadata;
} miif_desc_t;

#define MIIF_CACHELINE_ALIGN_MARK(mark) \
	uint8_t mark[0] __rte_aligned(RTE_CACHE_LINE_SIZE)

typedef struct {
	MIIF_CACHELINE_ALIGN_MARK(cacheline0);
	uint32_t cookie;			/**< MIIF_COOKIE */
	uint16_t flags;				/**< flags */
#define MIIF_RING_FLAG_MASK_INT 1		/**< disable interrupt mode */
	uint16_t head;			/**< pointer to ring buffer head */
	MIIF_CACHELINE_ALIGN_MARK(cacheline1);
	uint16_t tail;			/**< pointer to ring buffer tail */
	MIIF_CACHELINE_ALIGN_MARK(cacheline2);
	miif_desc_t desc[0];			/**< buffer descriptors */
} miif_ring_t;

#endif				/* _MIIF_H_ */
