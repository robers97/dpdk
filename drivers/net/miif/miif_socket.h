/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2020 International Business Machines, Inc. All rights reserved.
 */

#ifndef _MIIF_SOCKET_H_
#define _MIIF_SOCKET_H_

#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Remove device from socket device list. If no device is left on the socket,
 * remove the socket as well.
 *
 * @param dev
 *   miif device
 */
void miif_socket_remove_device(struct rte_eth_dev *dev);

/**
 * Enqueue disconnect message to control channel message queue.
 *
 * @param cc
 *   control channel
 * @param reason
 *   const string stating disconnect reason (96 characters)
 * @param err_code
 *   error code
 */
void miif_msg_enq_disconnect(struct miif_control_channel *cc, const char *reason,
			      int err_code);

/**
 * Initialize miif socket for specified device. If socket doesn't exist, create socket.
 *
 * @param dev
 *   miif device
 * @param socket_filename
 *   socket filename
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int miif_socket_init(struct rte_eth_dev *dev, const char *socket_filename);

/**
 * Disconnect miif device. Close control channel and shared memory.
 *
 * @param dev
 *   miif device
 */
void miif_disconnect(struct rte_eth_dev *dev);

/**
 * If device is properly configured, enable connection establishment.
 *
 * @param dev
 *   miif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int miif_connect_master(struct rte_eth_dev *dev);

/**
 * If device is properly configured, send connection request.
 *
 * @param dev
 *   miif device
 * @return
 *   - On success, zero.
 *   - On failure, a negative value.
 */
int miif_connect_slave(struct rte_eth_dev *dev);

struct miif_socket_dev_list_elt {
	TAILQ_ENTRY(miif_socket_dev_list_elt) next;
	struct rte_eth_dev *dev;		/**< pointer to device internals */
	char dev_name[RTE_ETH_NAME_MAX_LEN];
};

#define MIIF_SOCKET_HASH_NAME			"miif-sh"
#define MIIF_SOCKET_IN_SIZE	\
	(sizeof(struct sockaddr_in))

struct miif_socket {
	struct rte_intr_handle intr_handle;	/**< interrupt handle */
	char ipaddress[16];	                /**< ipaddress */

	TAILQ_HEAD(, miif_socket_dev_list_elt) dev_queue;
	/**< Queue of devices using this socket */
	uint8_t listener;			/**< if not zero socket is listener */
};

/* Control message queue. */
struct miif_msg_queue_elt {
	miif_msg_t msg;			/**< control message */
	TAILQ_ENTRY(miif_msg_queue_elt) next;
};

struct miif_control_channel {
	struct rte_intr_handle intr_handle;	/**< interrupt handle */
	TAILQ_HEAD(, miif_msg_queue_elt) msg_queue; /**< control message queue */
	struct miif_socket *socket;		/**< pointer to socket */
	struct rte_eth_dev *dev;		/**< pointer to device */
};

#endif				/* MIIF_SOCKET_H */
