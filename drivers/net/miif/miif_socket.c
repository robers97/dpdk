/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 Cisco Systems, Inc.  All rights reserved.
 * Copyright 2020 International Business Machines, Inc. All rights reserved.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <rte_version.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_kvargs.h>
#include <rte_bus_vdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_string_fns.h>

#include "rte_eth_miif.h"
#include "miif_socket.h"

static void miif_intr_handler(void *arg);

static ssize_t
miif_msg_send(int fd, miif_msg_t *msg)
{
  MIIF_LOG(DEBUG, "Sending message type %u of size %lu to socket fd: %d", msg->type, sizeof(miif_msg_t), fd);
	return write(fd, msg, sizeof(miif_msg_t));
}

static int
miif_msg_send_from_queue(struct miif_control_channel *cc)
{
	ssize_t size;
	int ret = 0;
	struct miif_msg_queue_elt *e;

	e = TAILQ_FIRST(&cc->msg_queue);
	if (e == NULL)
		return 0;

	size = miif_msg_send(cc->intr_handle.fd, &e->msg);
	if (size != sizeof(miif_msg_t)) {
		MIIF_LOG(ERR, "sendmsg fail: %s.", strerror(errno));
		ret = -1;
	} else {
	}
	TAILQ_REMOVE(&cc->msg_queue, e, next);
	rte_free(e);

	return ret;
}

static struct miif_msg_queue_elt *
miif_msg_enq(struct miif_control_channel *cc)
{
	struct miif_msg_queue_elt *e;

	e = rte_zmalloc("miif_msg", sizeof(struct miif_msg_queue_elt), 0);
	if (e == NULL) {
		MIIF_LOG(ERR, "Failed to allocate control message.");
		return NULL;
	}

	TAILQ_INSERT_TAIL(&cc->msg_queue, e, next);

	return e;
}

void
miif_msg_enq_disconnect(struct miif_control_channel *cc, const char *reason,
			 int err_code)
{
	struct miif_msg_queue_elt *e;
	struct pmd_internals *pmd;
	miif_msg_disconnect_t *d;

	if (cc == NULL) {
		MIIF_LOG(DEBUG, "Missing control channel.");
		return;
	}

	e = miif_msg_enq(cc);
	if (e == NULL) {
		MIIF_LOG(WARNING, "Failed to enqueue disconnect message.");
		return;
	}

	d = &e->msg.disconnect;

	e->msg.type = MIIF_MSG_TYPE_DISCONNECT;
	d->code = err_code;

	if (reason != NULL) {
		strlcpy((char *)d->string, reason, sizeof(d->string));
		if (cc->dev != NULL) {
			pmd = cc->dev->data->dev_private;
			strlcpy(pmd->local_disc_string, reason,
				sizeof(pmd->local_disc_string));
		}
	}
}

static int
miif_msg_enq_hello(struct miif_control_channel *cc)
{
	struct miif_msg_queue_elt *e = miif_msg_enq(cc);
	miif_msg_hello_t *h;

	if (e == NULL)
		return -1;

	h = &e->msg.hello;

	e->msg.type = MIIF_MSG_TYPE_HELLO;
	h->min_version = MIIF_VERSION;
	h->max_version = MIIF_VERSION;
	h->max_s2m_ring = ETH_MIIF_MAX_NUM_Q_PAIRS;
	h->max_m2s_ring = ETH_MIIF_MAX_NUM_Q_PAIRS;
	h->max_region = ETH_MIIF_MAX_REGION_NUM - 1;
	h->max_log2_ring_size = ETH_MIIF_MAX_LOG2_RING_SIZE;

	strlcpy((char *)h->name, rte_version(), sizeof(h->name));

	return 0;
}

static int
miif_msg_receive_hello(struct rte_eth_dev *dev, miif_msg_t *msg)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	miif_msg_hello_t *h = &msg->hello;

	if (h->min_version > MIIF_VERSION || h->max_version < MIIF_VERSION) {
		miif_msg_enq_disconnect(pmd->cc, "Incompatible miif version", 0);
		return -1;
	}

	/* Set parameters for active connection */
	pmd->run.num_s2m_rings = RTE_MIN(h->max_s2m_ring + 1,
					   pmd->cfg.num_s2m_rings);
	pmd->run.num_m2s_rings = RTE_MIN(h->max_m2s_ring + 1,
					   pmd->cfg.num_m2s_rings);
	pmd->run.log2_ring_size = RTE_MIN(h->max_log2_ring_size,
					    pmd->cfg.log2_ring_size);
	pmd->run.pkt_buffer_size = pmd->cfg.pkt_buffer_size;

	strlcpy(pmd->remote_name, (char *)h->name, sizeof(pmd->remote_name));

	MIIF_LOG(DEBUG, "%s: Connecting to %s.",
		rte_vdev_device_name(pmd->vdev), pmd->remote_name);

	return 0;
}

static int
miif_msg_receive_init(struct miif_control_channel *cc, miif_msg_t *msg)
{
	miif_msg_init_t *i = &msg->init;
	struct miif_socket_dev_list_elt *elt;
	struct pmd_internals *pmd;
	struct rte_eth_dev *dev;

	if (i->version != MIIF_VERSION) {
		miif_msg_enq_disconnect(cc, "Incompatible miif version", 0);
		return -1;
	}

	if (cc->socket == NULL) {
		miif_msg_enq_disconnect(cc, "Device error", 0);
		return -1;
	}

	/* Find device with requested ID */
	TAILQ_FOREACH(elt, &cc->socket->dev_queue, next) {
		dev = elt->dev;
		pmd = dev->data->dev_private;
		if (((pmd->flags & ETH_MIIF_FLAG_DISABLED) == 0) &&
		    pmd->id == i->id) {
			/* assign control channel to device */
			cc->dev = dev;
			pmd->cc = cc;

			if (i->mode != MIIF_INTERFACE_MODE_ETHERNET) {
				miif_msg_enq_disconnect(pmd->cc,
							 "Only ethernet mode supported",
							 0);
				return -1;
			}

			if (pmd->flags & (ETH_MIIF_FLAG_CONNECTING |
					   ETH_MIIF_FLAG_CONNECTED)) {
				miif_msg_enq_disconnect(pmd->cc,
							 "Already connected", 0);
				return -1;
			}
			strlcpy(pmd->remote_name, (char *)i->name,
				sizeof(pmd->remote_name));

			if (*pmd->secret != '\0') {
				if (*i->secret == '\0') {
					miif_msg_enq_disconnect(pmd->cc,
								 "Secret required", 0);
					return -1;
				}
				if (strncmp(pmd->secret, (char *)i->secret,
						ETH_MIIF_SECRET_SIZE) != 0) {
					miif_msg_enq_disconnect(pmd->cc,
								 "Incorrect secret", 0);
					return -1;
				}
			}

			MIIF_LOG(DEBUG, "MI_COMPUTE_INIT with ea %p and size %lu", i->mi_pool_ea, i->mi_pool_size);
			mi_compute_init(i->mi_pool_ea, i->mi_pool_size);

			pmd->flags |= ETH_MIIF_FLAG_CONNECTING;
			return 0;
		}
	}

	/* ID not found on this socket */
	MIIF_LOG(DEBUG, "ID %u not found.", i->id);
	miif_msg_enq_disconnect(cc, "ID not found", 0);
	return -1;
}

static int
miif_msg_receive_add_region(struct rte_eth_dev *dev, miif_msg_t *msg)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;
	miif_msg_add_region_t *ar = &msg->add_region;
	struct miif_region *r;

	if (ar->index >= ETH_MIIF_MAX_REGION_NUM ||
			ar->index != proc_private->regions_num ||
			proc_private->regions[ar->index] != NULL) {
		miif_msg_enq_disconnect(pmd->cc, "Invalid region index", 0);
		return -1;
	}

	r = rte_zmalloc("region", sizeof(struct miif_region), 0);
	if (r == NULL) {
		miif_msg_enq_disconnect(pmd->cc, "Failed to alloc miif region.", 0);
		return -ENOMEM;
	}

	r->region_size = ar->size;
	r->addr = ar->base; 

	MIIF_LOG(DEBUG,"Adding remote region %d as region %d with address %p and size %lu", ar->index, proc_private->regions_num, r->addr, r->region_size);
	/* TODO: this doesn't make since to index off the remote node! */
	proc_private->regions[ar->index] = r;
	proc_private->regions_num++;

	return 0;
}

static int
miif_msg_receive_add_ring(struct rte_eth_dev *dev, miif_msg_t *msg)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	miif_msg_add_ring_t *ar = &msg->add_ring;
	struct miif_queue *mq;

	/* check if we have enough queues */
	if (ar->flags & MIIF_MSG_ADD_RING_FLAG_S2M) {
		if (ar->index >= pmd->cfg.num_s2m_rings) {
			miif_msg_enq_disconnect(pmd->cc, "Invalid ring index", 0);
			return -1;
		}
		pmd->run.num_s2m_rings++;
	} else {
		if (ar->index >= pmd->cfg.num_m2s_rings) {
			miif_msg_enq_disconnect(pmd->cc, "Invalid ring index", 0);
			return -1;
		}
		pmd->run.num_m2s_rings++;
	}

	mq = (ar->flags & MIIF_MSG_ADD_RING_FLAG_S2M) ?
	    dev->data->rx_queues[ar->index] : dev->data->tx_queues[ar->index];

	/* TODO: I don't think mq needs an interrupt with miif, so commenting out */
	mq->intr_handle.fd = -1;
	if (mq->intr_handle.fd < 0) MIIF_LOG(DEBUG, "FD not found for message queue add.");
	mq->log2_ring_size = ar->log2_ring_size;
	mq->region = ar->region;
	mq->ring_offset = ar->offset;

	MIIF_LOG(DEBUG,"Added mq per request region index %d offset %u.  Ring ptr = %p", mq->region, mq->ring_offset, mq->ring);

	return 0;
}

static int
miif_msg_receive_connect(struct rte_eth_dev *dev, miif_msg_t *msg)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	miif_msg_connect_t *c = &msg->connect;
	int ret;

	ret = miif_connect(dev);
	if (ret < 0)
		return ret;

	strlcpy(pmd->remote_if_name, (char *)c->if_name,
		sizeof(pmd->remote_if_name));
	MIIF_LOG(INFO, "%s: Remote interface %s connected.",
		rte_vdev_device_name(pmd->vdev), pmd->remote_if_name);

	return 0;
}

static int
miif_msg_receive_connected(struct rte_eth_dev *dev, miif_msg_t *msg)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	miif_msg_connected_t *c = &msg->connected;
	int ret;

	ret = miif_connect(dev);
	if (ret < 0)
		return ret;

	strlcpy(pmd->remote_if_name, (char *)c->if_name,
		sizeof(pmd->remote_if_name));
	MIIF_LOG(INFO, "%s: Remote interface %s connected.",
		rte_vdev_device_name(pmd->vdev), pmd->remote_if_name);

	return 0;
}

static int
miif_msg_receive_disconnect(struct rte_eth_dev *dev, miif_msg_t *msg)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	miif_msg_disconnect_t *d = &msg->disconnect;

	memset(pmd->remote_disc_string, 0, ETH_MIIF_DISC_STRING_SIZE);
	strlcpy(pmd->remote_disc_string, (char *)d->string,
		sizeof(pmd->remote_disc_string));

	MIIF_LOG(INFO, "%s: Disconnect received: %s",
		rte_vdev_device_name(pmd->vdev), pmd->remote_disc_string);

	memset(pmd->local_disc_string, 0, ETH_MIIF_DISC_STRING_SIZE);
	miif_disconnect(dev);
	return 0;
}

static int
miif_msg_enq_ack(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_msg_queue_elt *e = miif_msg_enq(pmd->cc);
	if (e == NULL)
		return -1;

	e->msg.type = MIIF_MSG_TYPE_ACK;

	return 0;
}

static int
miif_msg_enq_init(struct rte_eth_dev *dev)
{
	/* need to sent master a message */

	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;

	struct miif_msg_queue_elt *e = miif_msg_enq(pmd->cc);
	miif_msg_init_t *i = &e->msg.init;

	if (e == NULL)
		return -1;

	i = &e->msg.init;
	e->msg.type = MIIF_MSG_TYPE_INIT;
	i->version = MIIF_VERSION;
	i->id = pmd->id;
	i->mode = MIIF_INTERFACE_MODE_ETHERNET;
	i->mi_pool_ea = proc_private->shared_ea;
	i->mi_pool_size = MIIF_POOL_SIZE;

	strlcpy((char *)i->name, rte_version(), sizeof(i->name));

	if (*pmd->secret != '\0')
		strlcpy((char *)i->secret, pmd->secret, sizeof(i->secret));

	return 0;
}

static int
miif_msg_enq_add_region(struct rte_eth_dev *dev, uint8_t idx)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;
	struct miif_msg_queue_elt *e = miif_msg_enq(pmd->cc);
	miif_msg_add_region_t *ar;
	struct miif_region *mr = proc_private->regions[idx];

	if (e == NULL)
		return -1;

	ar = &e->msg.add_region;
	e->msg.type = MIIF_MSG_TYPE_ADD_REGION;

        ar->base = mr->addr;
	ar->index = idx;
	ar->size = mr->region_size;

	return 0;
}

static int
miif_msg_enq_add_ring(struct rte_eth_dev *dev, uint8_t idx,
		       miif_ring_type_t type)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_msg_queue_elt *e = miif_msg_enq(pmd->cc);
	struct miif_queue *mq;
	miif_msg_add_ring_t *ar;

	if (e == NULL)
		return -1;

	ar = &e->msg.add_ring;
	mq = (type == MIIF_RING_S2M) ? dev->data->tx_queues[idx] :
	    dev->data->rx_queues[idx];

	e->msg.type = MIIF_MSG_TYPE_ADD_RING;
	ar->index = idx;
	ar->offset = mq->ring_offset;
	ar->region = mq->region;
	ar->log2_ring_size = mq->log2_ring_size;
	ar->flags = (type == MIIF_RING_S2M) ? MIIF_MSG_ADD_RING_FLAG_S2M : 0;
	ar->private_hdr_size = 0;

	MIIF_LOG(DEBUG,"Asking remote node to add ring type %d queue index %d ring offset %u region index %d.", type, ar->index, ar->offset, ar->region);
        MIIF_LOG(DEBUG,"mq ring pointer = %p", mq->ring);

	return 0;
}

static int
miif_msg_enq_connect(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_msg_queue_elt *e = miif_msg_enq(pmd->cc);
	const char *name = rte_vdev_device_name(pmd->vdev);
	miif_msg_connect_t *c;

	if (e == NULL)
		return -1;

	c = &e->msg.connect;
	e->msg.type = MIIF_MSG_TYPE_CONNECT;
	strlcpy((char *)c->if_name, name, sizeof(c->if_name));

	return 0;
}

static int
miif_msg_enq_connected(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_msg_queue_elt *e = miif_msg_enq(pmd->cc);
	const char *name = rte_vdev_device_name(pmd->vdev);
	miif_msg_connected_t *c;

	if (e == NULL)
		return -1;

	c = &e->msg.connected;
	e->msg.type = MIIF_MSG_TYPE_CONNECTED;
	strlcpy((char *)c->if_name, name, sizeof(c->if_name));

	return 0;
}

static void
miif_intr_unregister_handler(struct rte_intr_handle *intr_handle, void *arg)
{
	struct miif_msg_queue_elt *elt;
	struct miif_control_channel *cc = arg;

	/* close control channel fd */
	close(intr_handle->fd);
	/* clear message queue */
	while ((elt = TAILQ_FIRST(&cc->msg_queue)) != NULL) {
		TAILQ_REMOVE(&cc->msg_queue, elt, next);
		rte_free(elt);
	}
	/* free control channel */
	rte_free(cc);
}

void
miif_disconnect(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;
	struct miif_msg_queue_elt *elt, *next;
	struct miif_queue *mq;
	struct rte_intr_handle *ih;
	int i;
	int ret;

	dev->data->dev_link.link_status = ETH_LINK_DOWN;
	pmd->flags &= ~ETH_MIIF_FLAG_CONNECTING;
	pmd->flags &= ~ETH_MIIF_FLAG_CONNECTED;

	if (pmd->cc != NULL) {
		/* Clear control message queue (except disconnect message if any). */
		for (elt = TAILQ_FIRST(&pmd->cc->msg_queue); elt != NULL; elt = next) {
			next = TAILQ_NEXT(elt, next);
			if (elt->msg.type != MIIF_MSG_TYPE_DISCONNECT) {
				TAILQ_REMOVE(&pmd->cc->msg_queue, elt, next);
				rte_free(elt);
			}
		}
		/* send disconnect message (if there is any in queue) */
		miif_msg_send_from_queue(pmd->cc);

		/* at this point, there should be no more messages in queue */
		if (TAILQ_FIRST(&pmd->cc->msg_queue) != NULL) {
			MIIF_LOG(WARNING,
				"Unexpected message(s) in message queue.");
		}

		ih = &pmd->cc->intr_handle;
		if (ih->fd > 0) {
			ret = rte_intr_callback_unregister(ih,
							miif_intr_handler,
							pmd->cc);
			/*
			 * If callback is active (disconnecting based on
			 * received control message).
			 */
			if (ret == -EAGAIN) {
				ret = rte_intr_callback_unregister_pending(ih,
							miif_intr_handler,
							pmd->cc,
							miif_intr_unregister_handler);
			} else if (ret > 0) {
				close(ih->fd);
				rte_free(pmd->cc);
			}
			pmd->cc = NULL;
			if (ret <= 0)
			        MIIF_LOG(WARNING,
					 "Failed to unregister control channel callback.");
		} 
	}

	/* unconfig interrupts */
	for (i = 0; i < pmd->cfg.num_s2m_rings; i++) {
		if (pmd->role == MIIF_ROLE_SLAVE) {
			if (dev->data->tx_queues != NULL)
				mq = dev->data->tx_queues[i];
			else
				continue;
		} else {
			if (dev->data->rx_queues != NULL)
				mq = dev->data->rx_queues[i];
			else
				continue;
		}
		if (mq->intr_handle.fd > 0) {
			close(mq->intr_handle.fd);
			mq->intr_handle.fd = -1;
		}
	}
	for (i = 0; i < pmd->cfg.num_m2s_rings; i++) {
		if (pmd->role == MIIF_ROLE_MASTER) {
			if (dev->data->tx_queues != NULL)
				mq = dev->data->tx_queues[i];
			else
				continue;
		} else {
			if (dev->data->rx_queues != NULL)
				mq = dev->data->rx_queues[i];
			else
				continue;
		}
		if (mq->intr_handle.fd > 0) {
			close(mq->intr_handle.fd);
			mq->intr_handle.fd = -1;
		}
	}

	if(pmd->role == MIIF_ROLE_MASTER) miif_free_regions(proc_private);

	/* reset connection configuration */
	memset(&pmd->run, 0, sizeof(pmd->run));

	MIIF_LOG(DEBUG, "Disconnected.");
}

static int
miif_msg_receive(struct miif_control_channel *cc)
{
	miif_msg_t msg = { 0 };
	ssize_t size;
	int ret = 0;
	int i;
	struct pmd_internals *pmd;
	struct pmd_process_private *proc_private;

	size = read(cc->intr_handle.fd, &msg, sizeof(miif_msg_t));

	if (size != sizeof(miif_msg_t)) {
	  MIIF_LOG(DEBUG, "Invalid message size got %lu expected %lu.", size, sizeof(miif_msg_t));
	  MIIF_LOG(DEBUG, "Received msg type: %u from fd %d", msg.type, cc->intr_handle.fd);
	  miif_msg_enq_disconnect(cc, "Invalid message size", 0);
	  return -1;
	}

	MIIF_LOG(DEBUG, "Socket fd=%d Received msg type: %u.", cc->intr_handle.fd, msg.type);

	if (cc->dev == NULL && msg.type != MIIF_MSG_TYPE_INIT) {
		MIIF_LOG(DEBUG, "Unexpected message.");
		miif_msg_enq_disconnect(cc, "Unexpected message", 0);
		return -1;
	}

	/* get device from hash data */
	switch (msg.type) {
	case MIIF_MSG_TYPE_ACK:
		break;
	case MIIF_MSG_TYPE_HELLO:
		ret = miif_msg_receive_hello(cc->dev, &msg);
		if (ret < 0)
			goto exit;
		  
		ret = miif_init_regions_and_queues(cc->dev);
	  	if (ret < 0)
			goto exit;
		ret = miif_msg_enq_init(cc->dev);
		if (ret < 0)
			goto exit;
		pmd = cc->dev->data->dev_private;
		proc_private = cc->dev->process_private;
		for (i = 0; i < proc_private->regions_num; i++) {
			ret = miif_msg_enq_add_region(cc->dev, i);
			if (ret < 0)
				goto exit;
		}
		for (i = 0; i < pmd->run.num_s2m_rings; i++) {
			ret = miif_msg_enq_add_ring(cc->dev, i,
						     MIIF_RING_S2M);
			if (ret < 0)
				goto exit;
		}
		for (i = 0; i < pmd->run.num_m2s_rings; i++) {
			ret = miif_msg_enq_add_ring(cc->dev, i,
						     MIIF_RING_M2S);
			if (ret < 0)
				goto exit;
		}
		ret = miif_msg_enq_connect(cc->dev);
		if (ret < 0)
			goto exit;
		break;
	case MIIF_MSG_TYPE_INIT:
		/*
		 * This cc does not have an interface asociated with it.
		 * If suitable interface is found it will be assigned here.
		 */
		ret = miif_msg_receive_init(cc, &msg);
		if (ret < 0)
			goto exit;
		ret = miif_msg_enq_ack(cc->dev);
		if (ret < 0)
			goto exit;
		break;
	case MIIF_MSG_TYPE_ADD_REGION:
		ret = miif_msg_receive_add_region(cc->dev, &msg);
		if (ret < 0)
			goto exit;
		ret = miif_msg_enq_ack(cc->dev);
		if (ret < 0)
			goto exit;
		break;
	case MIIF_MSG_TYPE_ADD_RING:
		ret = miif_msg_receive_add_ring(cc->dev, &msg);
		if (ret < 0)
			goto exit;
		ret = miif_msg_enq_ack(cc->dev);
		if (ret < 0)
			goto exit;
		break;
	case MIIF_MSG_TYPE_CONNECT:
		ret = miif_msg_receive_connect(cc->dev, &msg);
		if (ret < 0)
			goto exit;
		ret = miif_msg_enq_connected(cc->dev);
		if (ret < 0)
			goto exit;
		break;
	case MIIF_MSG_TYPE_CONNECTED:
		ret = miif_msg_receive_connected(cc->dev, &msg);
		break;
	case MIIF_MSG_TYPE_DISCONNECT:
		ret = miif_msg_receive_disconnect(cc->dev, &msg);
		if (ret < 0)
			goto exit;
		break;
	default:
		miif_msg_enq_disconnect(cc, "Unknown message type", 0);
		ret = -1;
		goto exit;
	}

 exit:
	return ret;
}

static void
miif_intr_handler(void *arg)
{
	struct miif_control_channel *cc = arg;
	int ret;

	ret = miif_msg_receive(cc);
	/* if driver failed to assign device */
	if (cc->dev == NULL) {
		ret = rte_intr_callback_unregister_pending(&cc->intr_handle,
							   miif_intr_handler,
							   cc,
							   miif_intr_unregister_handler);
		if (ret < 0)
			MIIF_LOG(WARNING,
				"Failed to unregister control channel callback.");
		return;
	}
	/* if miif_msg_receive failed */
	if (ret < 0)
		goto disconnect;

	ret = miif_msg_send_from_queue(cc);
	if (ret < 0)
		goto disconnect;

	return;

 disconnect:
	if (cc->dev == NULL) {
		MIIF_LOG(WARNING, "eth dev not allocated");
		return;
	}
	miif_disconnect(cc->dev);
}

static void
miif_listener_handler(void *arg)
{
	struct miif_socket *socket = arg;
	int sockfd;
	int addr_len;
	struct sockaddr_in client;
	struct miif_control_channel *cc;
	int ret;

	addr_len = sizeof(client);
	sockfd = accept(socket->intr_handle.fd, (struct sockaddr *)&client,
			(socklen_t *)&addr_len);
	if (sockfd < 0) {
		MIIF_LOG(ERR,
			"Failed to accept connection request on socket fd %d",
			socket->intr_handle.fd);
		return;
	}

	MIIF_LOG(INFO, "%s(%d): Connection request accepted %d.",
                 socket->ipaddress,  socket->intr_handle.fd, sockfd);

	cc = rte_zmalloc("miif-cc", sizeof(struct miif_control_channel), 0);
	if (cc == NULL) {
		MIIF_LOG(ERR, "Failed to allocate control channel.");
		goto error;
	}

	cc->intr_handle.fd = sockfd;
	cc->intr_handle.type = RTE_INTR_HANDLE_EXT;
	cc->socket = socket;
	cc->dev = NULL;
	TAILQ_INIT(&cc->msg_queue);

	ret = rte_intr_callback_register(&cc->intr_handle, miif_intr_handler, cc);
	if (ret < 0) {
		MIIF_LOG(ERR, "Failed to register control channel callback.");
		goto error;
	}

	ret = miif_msg_enq_hello(cc);
	if (ret < 0) {
		MIIF_LOG(ERR, "Failed to enqueue hello message.");
		goto error;
	}
	ret = miif_msg_send_from_queue(cc);
	if (ret < 0)
		goto error;

	return;

 error:
	if (sockfd >= 0) {
		close(sockfd);
		sockfd = -1;
	}
	if (cc != NULL)
		rte_free(cc);
}

static struct miif_socket *
miif_socket_create(struct pmd_internals *pmd,
		    const char *key, uint8_t listener)
{
	struct miif_socket *sock;
	struct sockaddr_in in;
	int sockfd;
	int ret;

	sock = rte_zmalloc("miif-socket", sizeof(struct miif_socket), 0);
	if (sock == NULL) {
		MIIF_LOG(ERR, "Failed to allocate memory for miif socket");
		return NULL;
	}

	sock->listener = listener;
	strlcpy(sock->ipaddress, key, 16);
	sock->ipaddress[15] = '\0';

	MIIF_LOG(INFO, "miif_socket_create setting input key %s to sock->ipaddress %s", key, sock->ipaddress );

	TAILQ_INIT(&sock->dev_queue);

	if (listener != 0) {
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
		  MIIF_LOG(INFO, "Failed at socket call.");
		  goto error;
		}; 

		in.sin_family = AF_INET;
		in.sin_addr.s_addr = htonl(INADDR_ANY);
		in.sin_port = htons(44566);
	      
		ret = bind(sockfd, (struct sockaddr *)&in, sizeof(in));
		if (ret < 0) {
		  MIIF_LOG(INFO, "Failed at socket bind.");		  
		  goto error;
		}

		ret = listen(sockfd, 1);
		if (ret < 0) {
		  MIIF_LOG(INFO, "Failed at listen.");
		  goto error;
		}

		MIIF_LOG(DEBUG, "%s: Miif listener socket connected with sockfd=%d.",
			 rte_vdev_device_name(pmd->vdev), sockfd);

		sock->intr_handle.fd = sockfd;
		sock->intr_handle.type = RTE_INTR_HANDLE_EXT;
		ret = rte_intr_callback_register(&sock->intr_handle,
						 miif_listener_handler, sock);
		if (ret < 0) {
			MIIF_LOG(ERR, "%s: Failed to register interrupt "
				"callback for listener socket",
				rte_vdev_device_name(pmd->vdev));
			return NULL;
		}
	}

	return sock;

 error:
	MIIF_LOG(ERR, "%s: Failed to setup socket %s: %s",
		rte_vdev_device_name(pmd->vdev) ?
		rte_vdev_device_name(pmd->vdev) : "NULL", key, strerror(errno));
	if (sock != NULL)
		rte_free(sock);
	if (sockfd >= 0)
		close(sockfd);
	return NULL;
}

static struct rte_hash *
miif_create_socket_hash(void)
{
	struct rte_hash_parameters params = { 0 };

	params.name = MIIF_SOCKET_HASH_NAME;
	params.entries = 256;
	params.key_len = MIIF_SOCKET_IN_SIZE;
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	return rte_hash_create(&params);
}

int
miif_socket_init(struct rte_eth_dev *dev, const char *socket_filename)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_socket *socket = NULL;
	struct miif_socket_dev_list_elt *elt;
	struct pmd_internals *tmp_pmd;
	struct rte_hash *hash;
	int ret;
	char key[16];

	hash = rte_hash_find_existing(MIIF_SOCKET_HASH_NAME);
	if (hash == NULL) {
		hash = miif_create_socket_hash();
		if (hash == NULL) {
			MIIF_LOG(ERR, "Failed to create miif socket hash.");
			return -1;
		}
	}

	memset(key, 0, 16);
	strlcpy(key, socket_filename, 16);
	ret = rte_hash_lookup_data(hash, key, (void **)&socket);

	MIIF_LOG(INFO, "Using this key for hash lookup: %s", key);

	if (ret < 0) {
		socket = miif_socket_create(pmd, key,
					     (pmd->role ==
					      MIIF_ROLE_SLAVE) ? 0 : 1);
		if (socket == NULL)
			return -1;
		ret = rte_hash_add_key_data(hash, key, socket);
		if (ret < 0) {
			MIIF_LOG(ERR, "Failed to add socket to socket hash.");
			return ret;
		}
	}

	pmd->socket_filename = socket->ipaddress;
	MIIF_LOG(INFO, "Oddity pmd=%s socketip=%s key=%s", pmd->socket_filename, socket->ipaddress, key);

	if (socket->listener != 0 && pmd->role == MIIF_ROLE_SLAVE) {
		MIIF_LOG(ERR, "Socket is a listener.");
		return -1;
	} else if ((socket->listener == 0) && (pmd->role == MIIF_ROLE_MASTER)) {
		MIIF_LOG(ERR, "Socket is not a listener.");
		return -1;
	}

	TAILQ_FOREACH(elt, &socket->dev_queue, next) {
		tmp_pmd = elt->dev->data->dev_private;
		if (tmp_pmd->id == pmd->id) {
			MIIF_LOG(ERR, "Miif device with id %d already "
				"exists on socket %s",
				pmd->id, socket->ipaddress);
			return -1;
		}
	}

	elt = rte_malloc("pmd-queue", sizeof(struct miif_socket_dev_list_elt), 0);
	if (elt == NULL) {
		MIIF_LOG(ERR, "%s: Failed to add device to socket device list.",
			rte_vdev_device_name(pmd->vdev));
		return -1;
	}
	elt->dev = dev;
	TAILQ_INSERT_TAIL(&socket->dev_queue, elt, next);

	return 0;
}

void
miif_socket_remove_device(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_socket *socket = NULL;
	struct miif_socket_dev_list_elt *elt, *next;
	struct rte_hash *hash;
	int ret;

	hash = rte_hash_find_existing(MIIF_SOCKET_HASH_NAME);
	if (hash == NULL)
		return;

	if (pmd->socket_filename == NULL)
		return;

	if (rte_hash_lookup_data(hash, pmd->socket_filename, (void **)&socket) < 0)
		return;

	for (elt = TAILQ_FIRST(&socket->dev_queue); elt != NULL; elt = next) {
		next = TAILQ_NEXT(elt, next);
		if (elt->dev == dev) {
			TAILQ_REMOVE(&socket->dev_queue, elt, next);
			rte_free(elt);
			pmd->socket_filename = NULL;
		}
	}

	/* remove socket, if this was the last device using it */
        /* TODO: the connections are all hashed, but the listener only accepts one per server ?? */
	if (TAILQ_EMPTY(&socket->dev_queue)) {
		rte_hash_del_key(hash, socket->ipaddress);
		if (socket->listener) {
			/* remove listener socket file,
			 * so we can create new one later.
			 */
			ret = remove(socket->ipaddress);
			if (ret < 0)
				MIIF_LOG(ERR, "Failed to remove socket file: %s",
					socket->ipaddress);
		}
		rte_free(socket);
	}
}

int
miif_connect_master(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	memset(pmd->local_disc_string, 0, ETH_MIIF_DISC_STRING_SIZE);
	memset(pmd->remote_disc_string, 0, ETH_MIIF_DISC_STRING_SIZE);
	pmd->flags &= ~ETH_MIIF_FLAG_DISABLED;
	return 0;
}

int
miif_connect_slave(struct rte_eth_dev *dev)
{
	int sockfd;
	int ret;
	struct sockaddr_in in;
	struct pmd_internals *pmd = dev->data->dev_private;

	memset(pmd->local_disc_string, 0, ETH_MIIF_DISC_STRING_SIZE);
	memset(pmd->remote_disc_string, 0, ETH_MIIF_DISC_STRING_SIZE);
	pmd->flags &= ~ETH_MIIF_FLAG_DISABLED;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		MIIF_LOG(ERR, "%s: Failed to open socket. name: %s",
			 rte_vdev_device_name(pmd->vdev), pmd->socket_filename);
		return -1;
	}

	MIIF_LOG(INFO, "PMD socket_filename = %s", pmd->socket_filename);

	in.sin_family = AF_INET;
	in.sin_addr.s_addr = inet_addr(pmd->socket_filename);
	in.sin_port = htons(44566);

	ret = connect(sockfd, (struct sockaddr *)&in,
		      sizeof(struct sockaddr_in));
	if (ret < 0) {
		MIIF_LOG(ERR, "%s: Failed to connect socket: %s.",
			rte_vdev_device_name(pmd->vdev), pmd->socket_filename);
		goto error;
	}

	MIIF_LOG(DEBUG, "%s: Miif socket: %s(%u) connected.",
		 rte_vdev_device_name(pmd->vdev), pmd->socket_filename, sockfd);

	pmd->cc = rte_zmalloc("miif-cc",
			      sizeof(struct miif_control_channel), 0);
	if (pmd->cc == NULL) {
		MIIF_LOG(ERR, "%s: Failed to allocate control channel.",
			rte_vdev_device_name(pmd->vdev));
		goto error;
	}

	pmd->cc->intr_handle.fd = sockfd;
	pmd->cc->intr_handle.type = RTE_INTR_HANDLE_EXT;
	pmd->cc->socket = NULL;
	pmd->cc->dev = dev;
	TAILQ_INIT(&pmd->cc->msg_queue);

	ret = rte_intr_callback_register(&pmd->cc->intr_handle,
					 miif_intr_handler, pmd->cc);
	if (ret < 0) {
		MIIF_LOG(ERR, "%s: Failed to register interrupt callback ",
			 rte_vdev_device_name(pmd->vdev));
		goto error;
	}

	return 0;

 error:
	if (sockfd >= 0) {
		close(sockfd);
		sockfd = -1;
	}
	if (pmd->cc != NULL) {
		rte_free(pmd->cc);
		pmd->cc = NULL;
	}
	return -1;
}
