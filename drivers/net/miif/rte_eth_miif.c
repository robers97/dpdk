/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2019 Cisco Systems, Inc.  All rights reserved.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/eventfd.h>

#include <rte_version.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_vdev.h>
#include <rte_malloc.h>
#include <rte_kvargs.h>
#include <rte_bus_vdev.h>
#include <rte_string_fns.h>

#include "rte_eth_miif.h"
#include "miif_socket.h"

#define ETH_MIIF_ID_ARG		        "id"
#define ETH_MIIF_ROLE_ARG		"role"
#define ETH_MIIF_PKT_BUFFER_SIZE_ARG	"bsize"
#define ETH_MIIF_RING_SIZE_ARG		"rsize"
#define ETH_MIIF_SOCKET_ARG		"socket"
#define ETH_MIIF_MAC_ARG		"mac"
#define ETH_MIIF_ZC_ARG		        "zero-copy"
#define ETH_MIIF_SECRET_ARG		"secret"

static const char * const valid_arguments[] = {
	ETH_MIIF_ID_ARG,
	ETH_MIIF_ROLE_ARG,
	ETH_MIIF_PKT_BUFFER_SIZE_ARG,
	ETH_MIIF_RING_SIZE_ARG,
	ETH_MIIF_SOCKET_ARG,
	ETH_MIIF_MAC_ARG,
	ETH_MIIF_ZC_ARG,
	ETH_MIIF_SECRET_ARG,
	NULL
};

#define MIIF_MP_SEND_REGION		"miif_mp_send_region"

const char *
miif_version(void)
{
	return ("miif-" RTE_STR(MIIF_VERSION_MAJOR) "." RTE_STR(MIIF_VERSION_MINOR));
}

/* Message header to synchronize regions */
struct mp_region_msg {
	char port_name[RTE_DEV_NAME_MAX_LEN];
	miif_region_index_t idx;
	void* addr;
	miif_region_size_t size;
};

static int
miif_mp_send_region(const struct rte_mp_msg *msg, const void *peer)
{
	struct rte_eth_dev *dev;
	struct pmd_process_private *proc_private;
	const struct mp_region_msg *msg_param = (const struct mp_region_msg *)msg->param;
	struct rte_mp_msg reply;
	struct mp_region_msg *reply_param = (struct mp_region_msg *)reply.param;
	uint16_t port_id;
	int ret;

	/* Get requested port */
	ret = rte_eth_dev_get_port_by_name(msg_param->port_name, &port_id);
	if (ret) {
		MIIF_LOG(ERR, "Failed to get port id for %s",
			msg_param->port_name);
		return -1;
	}
	dev = &rte_eth_devices[port_id];
	proc_private = dev->process_private;

	memset(&reply, 0, sizeof(reply));
	strlcpy(reply.name, msg->name, sizeof(reply.name));
	reply_param->idx = msg_param->idx;
	if (proc_private->regions[msg_param->idx] != NULL) {
		reply_param->size = proc_private->regions[msg_param->idx]->region_size;
		reply_param->addr = proc_private->regions[msg_param->idx]->addr;
		reply.fds[0] = 0; /* not used in miif */
		reply.num_fds = 0; /* not used in miif */
	}
	MIIF_LOG(DEBUG, "Sending region index %d with address %p", reply_param->idx, proc_private->regions[msg_param->idx]->addr);
	reply.len_param = sizeof(*reply_param);
	if (rte_mp_reply(&reply, peer) < 0) {
		MIIF_LOG(ERR, "Failed to reply to an add region request");
		return -1;
	}

	return 0;
}

/*
 * Request regions
 * Called by secondary process, when ports link status goes up.
 */
static int
miif_mp_request_regions(struct rte_eth_dev *dev)
{
	int ret, i;
	struct timespec timeout = {.tv_sec = 5, .tv_nsec = 0};
	struct rte_mp_msg msg, *reply;
	struct rte_mp_reply replies;
	struct mp_region_msg *msg_param = (struct mp_region_msg *)msg.param;
	struct mp_region_msg *reply_param;
	struct miif_region *r;
	struct pmd_process_private *proc_private = dev->process_private;

	MIIF_LOG(DEBUG, "Requesting memory regions");

	for (i = 0; i < ETH_MIIF_MAX_REGION_NUM; i++) {
		/* Prepare the message */
		memset(&msg, 0, sizeof(msg));
		strlcpy(msg.name, MIIF_MP_SEND_REGION, sizeof(msg.name));
		strlcpy(msg_param->port_name, dev->data->name,
			sizeof(msg_param->port_name));
		msg_param->idx = i;
		msg.len_param = sizeof(*msg_param);

		/* Send message */
		ret = rte_mp_request_sync(&msg, &replies, &timeout);
		if (ret < 0 || replies.nb_received != 1) {
			MIIF_LOG(ERR, "Failed to send mp msg: %d",
				rte_errno);
			return -1;
		}

		reply = &replies.msgs[0];
		reply_param = (struct mp_region_msg *)reply->param;

		if (reply_param->size > 0) {
			r = rte_zmalloc("region", sizeof(struct miif_region), 0);
			if (r == NULL) {
				MIIF_LOG(ERR, "Failed to alloc miif region.");
				free(reply);
				return -ENOMEM;
			}
			r->region_size = reply_param->size;
			if (reply->num_fds < 1) {
				MIIF_LOG(ERR, "Missing file descriptor.");
				free(reply);
				return -1;
			}
			r->addr = reply_param->addr;

			proc_private->regions[reply_param->idx] = r;
			proc_private->regions_num++;
		}
		free(reply);
	}

	return miif_connect(dev);
}

static int
miif_dev_info(struct rte_eth_dev *dev __rte_unused, struct rte_eth_dev_info *dev_info)
{
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)ETH_FRAME_LEN;
	dev_info->max_rx_queues = ETH_MIIF_MAX_NUM_Q_PAIRS;
	dev_info->max_tx_queues = ETH_MIIF_MAX_NUM_Q_PAIRS;
	dev_info->min_rx_bufsize = 0;

	return 0;
}

static miif_ring_t *
miif_get_ring(struct pmd_internals *pmd, struct pmd_process_private *proc_private,
	       miif_ring_type_t type, uint16_t ring_num)
{
	/* rings only in region 0 */
	void *p = proc_private->regions[0]->addr;
	int ring_size = sizeof(miif_ring_t) + sizeof(miif_desc_t) *
	    (1 << pmd->run.log2_ring_size);

	p = (uint8_t *)p + (ring_num + type * pmd->run.num_s2m_rings) * ring_size;

	return (miif_ring_t *)p;
}

static miif_region_offset_t
miif_get_ring_offset(struct rte_eth_dev *dev, struct miif_queue *mq,
		      miif_ring_type_t type, uint16_t num)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;

	return ((uint8_t *)miif_get_ring(pmd, proc_private, type, num) -
		(uint8_t *)proc_private->regions[mq->region]->addr);
}

static miif_ring_t *
miif_get_ring_from_queue(struct pmd_process_private *proc_private,
			  struct miif_queue *mq)
{
	struct miif_region *r;

	r = proc_private->regions[mq->region];
	if (r == NULL)
		return NULL;

	//MIIF_LOG(DEBUG,"using ring address: %p", ((uint8_t *)r->addr + mq->ring_offset));

	return (miif_ring_t *)((uint8_t *)r->addr + mq->ring_offset);
}

static void *
miif_get_buffer(struct pmd_process_private *proc_private, miif_desc_t *d)
{
	return ((uint8_t *)proc_private->regions[d->region]->addr + d->offset);
}

static int
miif_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *cur_tail,
		    struct rte_mbuf *tail)
{
	/* Check for number-of-segments-overflow */
	if (unlikely(head->nb_segs + tail->nb_segs > RTE_MBUF_MAX_NB_SEGS))
		return -EOVERFLOW;

	/* Chain 'tail' onto the old tail */
	cur_tail->next = tail;

	/* accumulate number of segments and total length. */
	head->nb_segs = (uint16_t)(head->nb_segs + tail->nb_segs);

	tail->pkt_len = tail->data_len;
	head->pkt_len += tail->pkt_len;

	return 0;
}


//#define PRINT_RING
#ifdef PRINT_RING
static void print_ring(miif_ring_t * ring) {
	printf("@@@@@@@@@\n");
	printf("head: %u\n", ring->head);
	printf("tail: %u\n", ring->tail);
	printf("@@@@@@@@@\n");
}
#endif

static uint16_t
eth_miif_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct miif_queue *mq = queue;
	struct pmd_internals *pmd = rte_eth_devices[mq->in_port].data->dev_private;
	struct pmd_process_private *proc_private =
		rte_eth_devices[mq->in_port].process_private;
	miif_ring_t *ring = miif_get_ring_from_queue(proc_private, mq);
	uint16_t cur_slot, last_slot, n_slots, ring_size, mask, s0;
	uint16_t n_rx_pkts = 0;
	uint16_t mbuf_size = rte_pktmbuf_data_room_size(mq->mempool) -
		RTE_PKTMBUF_HEADROOM;
	uint16_t src_len, src_off, dst_len, dst_off, cp_len;
	miif_ring_type_t type = mq->type;
	miif_desc_t *d0;
	struct rte_mbuf *mbuf, *mbuf_head, *mbuf_tail;
	uint64_t b;
	ssize_t size __rte_unused;
	uint16_t head;
	int ret;
	struct rte_eth_link link;

	if (unlikely((pmd->flags & ETH_MIIF_FLAG_CONNECTED) == 0))
		return 0;
	if (unlikely(ring == NULL)) {
		/* Secondary process will attempt to request regions. */
		ret = rte_eth_link_get(mq->in_port, &link);
		if (ret < 0)
			MIIF_LOG(ERR, "Failed to get port %u link info: %s",
				mq->in_port, rte_strerror(-ret));
		return 0;
	}

	/* consume interrupt -- we shouldn't be consumming interrupts on the queues and I don't have them setup... */
        /* not sure why commenting out the 'read' is makes catania 'start' command fall through.. it should 'start and then run until traffic */

	if ((ring->flags & MIIF_RING_FLAG_MASK_INT) == 0) {
		//MIIF_LOG(ERR, "Consuming interrupt fd = %d from message queue type %s", mq->intr_handle.fd, (type == MIIF_RING_S2M) ? "S2M" : "M2S");
		size = read(mq->intr_handle.fd, &b, sizeof(b));

	}

	ring_size = 1 << mq->log2_ring_size;
	mask = ring_size - 1;

	/**
	 * Christian: I am using the "raw" flush line because I want the dcbf to be executed on the exact same address
	 * where the load is done. This I think would prevent the processor from further reordering because it would create
	 * a dependency between the dcbf and the load.
	 * I flush both head and tail because we could use them both after receiving is done.
	 *
	 * NOTE: We could avoid the first flush and first check if the value has changed, and then retry if it didn't. However this complicates the code
	 * and in any case we would endup always flushing when head/tail did not change becuse there's nothing to do.
	 */

	if (type == MIIF_RING_S2M) {
		FLUSH_LINE(&ring->head);
		cur_slot = mq->last_head;
		last_slot = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
	} else {
		FLUSH_LINE(&ring->tail);
		cur_slot = mq->last_tail;
		last_slot = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
	}

#ifdef PRINT_RING
	printf("ring before rx\n");
	print_ring(ring);
#endif

	if (cur_slot == last_slot)
		goto refill;
	n_slots = last_slot - cur_slot;

	while (n_slots && n_rx_pkts < nb_pkts) {
		mbuf_head = rte_pktmbuf_alloc(mq->mempool);
		if (unlikely(mbuf_head == NULL))
			goto no_free_bufs;
		mbuf = mbuf_head;
		mbuf->port = mq->in_port;

next_slot:
		s0 = cur_slot & mask;
		d0 = &ring->desc[s0];

		/*
		 * Flush the descriptor before we access it as we might have a stale version of it.
		 */
		flush_memory_block (d0, sizeof(miif_desc_t),1);
		/*
		 * Once the descriptor fields are fresh we need to refresh the buffer associated with it.
		 */
		flush_memory_block((uint8_t *)miif_get_buffer(proc_private, d0),
				d0->length, 1);

		src_len = d0->length;
		dst_off = 0;
		src_off = 0;

		do {
			dst_len = mbuf_size - dst_off;
			if (dst_len == 0) {
				dst_off = 0;
				dst_len = mbuf_size;

				/* store pointer to tail */
				mbuf_tail = mbuf;
				mbuf = rte_pktmbuf_alloc(mq->mempool);
				if (unlikely(mbuf == NULL))
					goto no_free_bufs;
				mbuf->port = mq->in_port;
				ret = miif_pktmbuf_chain(mbuf_head, mbuf_tail, mbuf);
				if (unlikely(ret < 0)) {
					MIIF_LOG(ERR, "number-of-segments-overflow");
					rte_pktmbuf_free(mbuf);
					goto no_free_bufs;
				}
			}
			cp_len = RTE_MIN(dst_len, src_len);

			rte_pktmbuf_data_len(mbuf) += cp_len;
			rte_pktmbuf_pkt_len(mbuf) = rte_pktmbuf_data_len(mbuf);
			if (mbuf != mbuf_head)
				rte_pktmbuf_pkt_len(mbuf_head) += cp_len;

			rte_memcpy(rte_pktmbuf_mtod_offset(mbuf, void *, dst_off),
			       (uint8_t *)miif_get_buffer(proc_private, d0) +
			       src_off, cp_len);

			//MIIF_LOG(DEBUG,"last,curr,nslots (%u,%u,%u)... rx buffer copied chuck len %d", last_slot,cur_slot,n_slots,cp_len);

			src_off += cp_len;
			dst_off += cp_len;
			src_len -= cp_len;
		} while (src_len);

		cur_slot++;
		n_slots--;

		if (d0->flags & MIIF_DESC_FLAG_NEXT)
			goto next_slot;

		mq->n_bytes += rte_pktmbuf_pkt_len(mbuf_head);
		*bufs++ = mbuf_head;
		//MIIF_LOG(DEBUG, "Advancing n_rx_pkts");
		n_rx_pkts++;
	}

	/*
	 * Here we make sure we update head/tail only after all the above changes have hit memory
	 * Perhaps this can be removed
	 */
	LWSYNC;

no_free_bufs:
	if (type == MIIF_RING_S2M) {
		__atomic_store_n(&ring->tail, cur_slot, __ATOMIC_RELEASE);
		FLUSH_LINE(&ring->tail);
		mq->last_head = cur_slot;
	} else {
		mq->last_tail = cur_slot;
	}

refill:
	if (type == MIIF_RING_M2S) {

		FLUSH_LINE(&ring->head);
		head = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
		n_slots = ring_size - head + mq->last_tail;

		while (n_slots--) {
			s0 = head++ & mask;
			d0 = &ring->desc[s0];
			d0->length = pmd->run.pkt_buffer_size;
			/*
			 * Flush the blocks that get modified. We do not care about the buffer ew only care about the descriptor data.
			 */
			flush_memory_block (d0, sizeof(miif_desc_t), 1);
		}
		__atomic_store_n(&ring->head, head, __ATOMIC_RELEASE);
		FLUSH_LINE(&ring->head);
		//MIIF_LOG(DEBUG,"Refill function advanced head from %d to %d", start_head, ring->head);
	}

	//flush_memory_block (&ring->desc, sizeof(miif_desc_t),0);
	//flush_memory_block (ring, RTE_CACHE_LINE_SIZE*2, 1);
	//what about flushing the whole region here??
	
#ifdef PRINT_RING
	printf("ring after rx\n");
	print_ring(ring);
	printf("packets received: %u\n", n_rx_pkts);
#endif

	mq->n_pkts += n_rx_pkts;
	//MIIF_LOG(DEBUG, "Refill function activated with %lu packets", mq->n_pkts);

	return n_rx_pkts;
}

static uint16_t
eth_miif_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct miif_queue *mq = queue;
	struct pmd_internals *pmd = rte_eth_devices[mq->in_port].data->dev_private;
	struct pmd_process_private *proc_private =
		rte_eth_devices[mq->in_port].process_private;
	miif_ring_t *ring = miif_get_ring_from_queue(proc_private, mq);
	uint16_t slot, saved_slot, n_free, ring_size, mask, n_tx_pkts = 0;
	uint16_t src_len, src_off, dst_len, dst_off, cp_len;
	miif_ring_type_t type = mq->type;
	miif_desc_t *d0;
	struct rte_mbuf *mbuf;
	struct rte_mbuf *mbuf_head;
	uint64_t a;
	ssize_t size;
	struct rte_eth_link link;

	if (unlikely((pmd->flags & ETH_MIIF_FLAG_CONNECTED) == 0))
		return 0;
	if (unlikely(ring == NULL)) {
		int ret;

		/* Secondary process will attempt to request regions. */
		ret = rte_eth_link_get(mq->in_port, &link);
		if (ret < 0)
			MIIF_LOG(ERR, "Failed to get port %u link info: %s",
				mq->in_port, rte_strerror(-ret));
		return 0;
	}

	ring_size = 1 << mq->log2_ring_size;
	mask = ring_size - 1;

	/**
	 * Christian: I am using the "raw" flush line because I want the dcbf to be executed on the exact same address
	 * where the load is done. This I think would prevent the processor from further reordering because it would create
	 * a dependency between the dcbf and the load.
	 * I flush both head and tail because we could use them both after receiving is done.
	 *
	 * NOTE: We could avoid the first flush and first check if the value has changed, and then retry if it didn't. However this complicates the code
	 * and in any case we would endup always flushing when head/tail did not change becuse there's nothing to do.
	 */
	FLUSH_LINE(&ring->tail);
	n_free = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE) - mq->last_tail;
	mq->last_tail += n_free;

#ifdef PRINT_RING
	printf("ring before tx\n");
	print_ring(ring);
#endif

	if (type == MIIF_RING_S2M) {
		FLUSH_LINE(&ring->head);
		slot = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE);
		n_free = ring_size - slot + mq->last_tail;
	} else {
		/*
		 * Here the fact that every time we do a load instead of reusing the variable read previously for the
		 * thail makes me think that these values can change while we read them. This is why I am flushing the tail once more
		 */
		FLUSH_LINE(&ring->head);
		FLUSH_LINE(&ring->tail);
		slot = __atomic_load_n(&ring->tail, __ATOMIC_ACQUIRE);
		n_free = __atomic_load_n(&ring->head, __ATOMIC_ACQUIRE) - slot;
	}

	while (n_tx_pkts < nb_pkts && n_free) {
		mbuf_head = *bufs++;
		mbuf = mbuf_head;

		saved_slot = slot;
		d0 = &ring->desc[slot & mask];

		/*
		 * Flush the descriptor before we access it as we might have a stale version of it.
		 */
		flush_memory_block (d0, sizeof(miif_desc_t),1);

		dst_off = 0;
		dst_len = (type == MIIF_RING_S2M) ?
			pmd->run.pkt_buffer_size : d0->length;

next_in_chain:
		src_off = 0;
		src_len = rte_pktmbuf_data_len(mbuf);

		while (src_len) {
			if (dst_len == 0) {
				if (n_free) {
					slot++;
					n_free--;
					d0->flags |= MIIF_DESC_FLAG_NEXT;
					d0 = &ring->desc[slot & mask];
					dst_off = 0;
					dst_len = (type == MIIF_RING_S2M) ?
					    pmd->run.pkt_buffer_size : d0->length;
					d0->flags = 0;
				} else {
					slot = saved_slot;
					goto no_free_slots;
				}
			}
			cp_len = RTE_MIN(dst_len, src_len);

			rte_memcpy((uint8_t *)miif_get_buffer(proc_private, d0) + dst_off,
			       rte_pktmbuf_mtod_offset(mbuf, void *, src_off),
			       cp_len);

			/* TODO: consideration larger flush of src_len or flush whole buffer area after while loop */
			flush_memory_block ((uint8_t *)miif_get_buffer(proc_private, d0) + dst_off, cp_len, 0);

			mq->n_bytes += cp_len;
			src_off += cp_len;
			dst_off += cp_len;
			src_len -= cp_len;
			dst_len -= cp_len;

			d0->length = dst_off;
		}

		flush_memory_block (d0, sizeof(miif_desc_t),1);

		if (rte_pktmbuf_is_contiguous(mbuf) == 0) {
			mbuf = mbuf->next;
			goto next_in_chain;
		}

		n_tx_pkts++;
		slot++;
		n_free--;
		rte_pktmbuf_free(mbuf_head);
	}

	/*
	 * Here we make sure we update head/tail only after all the above changes have hit memory
	 * Perhaps this can be removed
	 */
	LWSYNC;

no_free_slots:
	if (type == MIIF_RING_S2M)
		__atomic_store_n(&ring->head, slot, __ATOMIC_RELEASE);
	else
		__atomic_store_n(&ring->tail, slot, __ATOMIC_RELEASE);

    flush_memory_block(ring, RTE_CACHE_LINE_SIZE*2, 1);

	/*  guessing not needed for MIIF */
	if ((ring->flags & MIIF_RING_FLAG_MASK_INT) == 0) {
		a = 1;

		MIIF_LOG(DEBUG,"producing interrupt with mq %d type %s ring flags %u", mq->intr_handle.fd, (type == MIIF_RING_S2M) ? "S2M" : "M2S", ring->flags);

		size = write(mq->intr_handle.fd, &a, sizeof(a));
		if (unlikely(size < 0)) {
			MIIF_LOG(WARNING,
				"Failed to send interrupt. %s", strerror(errno));
		}
	}

#ifdef PRINT_RING
	printf("ring after tx\n");
	print_ring(ring);
	printf("packets transmitted: %u\n", n_tx_pkts);
#endif

	mq->n_pkts += n_tx_pkts;
	return n_tx_pkts;
}

void
miif_free_regions(struct pmd_process_private *proc_private)
{
	int i;
	struct miif_region *r;

	MIIF_LOG(DEBUG, "Free memory regions");
	/* regions are allocated contiguously, so it's
	 * enough to loop until 'proc_private->regions_num'
	 */
	for (i = 0; i < proc_private->regions_num; i++) {
		r = proc_private->regions[i];
		if (r != NULL) {
			if (r->addr != NULL) {
				mi_buffer_unmap(r->addr, r->region_size);
			}
			rte_free(r);
			proc_private->regions[i] = NULL;
		}
	 }
	 proc_private->regions_num = 0;
}


static int
miif_region_init(struct rte_eth_dev *dev, uint8_t has_buffers)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;
	int ret = 0;
	struct miif_region *r;
	void *buf;

	if (proc_private->regions_num >= ETH_MIIF_MAX_REGION_NUM) {
		MIIF_LOG(ERR, "Too many regions.");
		return -1;
	}

	r = rte_zmalloc("region", sizeof(struct miif_region), 0);
	if (r == NULL) {
		MIIF_LOG(ERR, "Failed to alloc miif region.");
		return -ENOMEM;
	}

	/* calculate buffer offset */
	r->pkt_buffer_offset = (pmd->run.num_s2m_rings + pmd->run.num_m2s_rings) *
	    (sizeof(miif_ring_t) + sizeof(miif_desc_t) *
	    (1 << pmd->run.log2_ring_size));

	r->region_size = r->pkt_buffer_offset;
	/* if region has buffers, add buffers size to region_size */
	if (has_buffers == 1)
		r->region_size += (uint32_t)(pmd->run.pkt_buffer_size *
			(1 << pmd->run.log2_ring_size) *
			(pmd->run.num_s2m_rings +
			 pmd->run.num_m2s_rings));

	buf = mi_buffer_alloc(r->region_size);
	if (buf == NULL){
		MIIF_LOG(ERR, "Failed to alloc region buffer %d.", proc_private->regions_num);
		ret = -1;
		goto error;
	}
	r->addr = buf;

	MIIF_LOG(DEBUG, "Successfully alloc'ed region buffer %d at address %p", proc_private->regions_num, r->addr);
	proc_private->regions[proc_private->regions_num] = r;
	proc_private->regions_num++;

	return ret;

error:
	r->addr = NULL;
	return ret;
}

static int
miif_regions_init(struct rte_eth_dev *dev)
{
        int ret;

        /* create one buffer region */
        ret = miif_region_init(dev, /* has buffer */ 1);
        if (ret < 0)
                return ret;

        return 0;
}

static void
miif_init_rings(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;
	miif_ring_t *ring;
	int i, j;
	uint16_t slot;

	for (i = 0; i < pmd->run.num_s2m_rings; i++) {
		ring = miif_get_ring(pmd, proc_private, MIIF_RING_S2M, i);
		__atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
		__atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
		ring->cookie = MIIF_COOKIE;
		ring->flags = 0;
		for (j = 0; j < (1 << pmd->run.log2_ring_size); j++) {
			slot = i * (1 << pmd->run.log2_ring_size) + j;
			ring->desc[j].region = 0;
			ring->desc[j].offset =
				proc_private->regions[0]->pkt_buffer_offset +
				(uint32_t)(slot * pmd->run.pkt_buffer_size);
			ring->desc[j].length = pmd->run.pkt_buffer_size;
		}
		// Needed to push back to shared memory
		flush_memory_block (ring, RTE_CACHE_LINE_SIZE*2, 0);
	}

	for (i = 0; i < pmd->run.num_m2s_rings; i++) {
		ring = miif_get_ring(pmd, proc_private, MIIF_RING_M2S, i);
		__atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
		__atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
		ring->cookie = MIIF_COOKIE;
		ring->flags = 0;
		for (j = 0; j < (1 << pmd->run.log2_ring_size); j++) {
			slot = (i + pmd->run.num_s2m_rings) *
			    (1 << pmd->run.log2_ring_size) + j;
			ring->desc[j].region = 0;
			ring->desc[j].offset =
				proc_private->regions[0]->pkt_buffer_offset +
				(uint32_t)(slot * pmd->run.pkt_buffer_size);
			ring->desc[j].length = pmd->run.pkt_buffer_size;
		}
		//Needed to push back to shared memory
                flush_memory_block (ring, RTE_CACHE_LINE_SIZE*2, 0);
	}
}

/* called only by slave */
static void
miif_init_queues(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_queue *mq;
	int i;

	for (i = 0; i < pmd->run.num_s2m_rings; i++) {
		mq = dev->data->tx_queues[i];
		mq->log2_ring_size = pmd->run.log2_ring_size;
		/* queues located only in region 0 */
		mq->region = 0;
		mq->ring_offset = miif_get_ring_offset(dev, mq, MIIF_RING_S2M, i);
		mq->last_head = 0;
		mq->last_tail = 0;
		mq->intr_handle.fd = eventfd(0, EFD_NONBLOCK);
		if (mq->intr_handle.fd < 0) {
			MIIF_LOG(WARNING,
				"Failed to create eventfd for tx queue %d: %s.", i,
				strerror(errno));
		}
		//Needed to push back to shared memory
		//TODO: verify the mq's are shared... I don't think so, I think only the rings are shared
		flush_memory_block (mq, sizeof(struct miif_queue), 0);
	}

	for (i = 0; i < pmd->run.num_m2s_rings; i++) {
		mq = dev->data->rx_queues[i];
		mq->log2_ring_size = pmd->run.log2_ring_size;
		/* queues located only in region 0 */
		mq->region = 0;
		mq->ring_offset = miif_get_ring_offset(dev, mq, MIIF_RING_M2S, i);
		mq->last_head = 0;
		mq->last_tail = 0;
		mq->intr_handle.fd = eventfd(0, EFD_NONBLOCK);
		if (mq->intr_handle.fd < 0) {
			MIIF_LOG(WARNING,
				"Failed to create eventfd for rx queue %d: %s.", i,
				strerror(errno));
		}
		//Needed to push back to shared memory
		//TODO: verify the mq's are shared... I don't think so, I think only the rings are shared
		flush_memory_block (mq, sizeof(struct miif_queue), 0);
	}
}

int
miif_init_regions_and_queues(struct rte_eth_dev *dev)
{
	int ret;
        struct pmd_process_private *proc_private = dev->process_private;
        /*
	 * Initialize the memory pool used to allocate buffers from user applications.
	 * TBD: check if there is a memory pool aready in use!  Could just check if there is a non-NULL ea...
	 */
        ret = mi_memory_init(MIIF_POOL_SIZE);
	if (ret < 0) {
		MIIF_LOG(ERR, "Failed to initialize CAPI memory pool.");
		return ret;
	}

        /*
	 * Retrieve the base ea of the pool. This value must be shared with the counterpart
	 * on the master (borrower) node 
	 */
	proc_private->shared_ea = mi_get_pool_ea();

	//MIIF_LOG(DEBUG,"Starting to initialize regionds.");
	ret = miif_regions_init(dev);
	if (ret < 0)
		return ret;

	//MIIF_LOG(DEBUG,"Starting to intialize rings.");
	miif_init_rings(dev);
	//MIIF_LOG(DEBUG,"Starting to initialize queues.");
	miif_init_queues(dev);

	return 0;
}

int
miif_connect(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct pmd_process_private *proc_private = dev->process_private;
	struct miif_region *mr;
	struct miif_queue *mq;
	miif_ring_t *ring;
	int i;

	if (pmd->role == MIIF_ROLE_MASTER) {
	   for (i = 0; i < proc_private->regions_num; i++) {
		mr = proc_private->regions[i];
		MIIF_LOG(DEBUG,"Investigating device region index %d of %d", i, proc_private->regions_num); 
		if (mr != NULL) {
			if (mr->addr != NULL) {
				MIIF_LOG(DEBUG,"Attempting to nmap region of size %lu with addr=%p", mr->region_size, mr->addr);
				mr->addr = mi_buffer_map(mr->addr, mr->region_size);
				MIIF_LOG(DEBUG,"buffer map returns %p.", mr->addr);
				if (mr->addr == NULL) {
					MIIF_LOG(ERR,"Failed to map address for region %d!", i);
					return -1;
				}
			} else {
				MIIF_LOG(DEBUG,"why does this index have a valid MR with a null address?");
			}
		}
	   }
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		for (i = 0; i < pmd->run.num_s2m_rings; i++) {
			mq = (pmd->role == MIIF_ROLE_SLAVE) ?
			    dev->data->tx_queues[i] : dev->data->rx_queues[i];
			ring = miif_get_ring_from_queue(proc_private, mq);
			if (ring == NULL || ring->cookie != MIIF_COOKIE) {
				MIIF_LOG(ERR, "Wrong ring");
				return -1;
			}
			__atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
			__atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
			mq->last_head = 0;
			mq->last_tail = 0;
			/* enable polling mode */
			if (pmd->role == MIIF_ROLE_MASTER)
				ring->flags = MIIF_RING_FLAG_MASK_INT;

			flush_memory_block(ring, sizeof(miif_ring_t), 0);
		}
		for (i = 0; i < pmd->run.num_m2s_rings; i++) {
			mq = (pmd->role == MIIF_ROLE_SLAVE) ?
			    dev->data->rx_queues[i] : dev->data->tx_queues[i];
			ring = miif_get_ring_from_queue(proc_private, mq);
			if (ring == NULL || ring->cookie != MIIF_COOKIE) {
				MIIF_LOG(ERR, "Wrong ring");
				return -1;
			}
			__atomic_store_n(&ring->head, 0, __ATOMIC_RELAXED);
			__atomic_store_n(&ring->tail, 0, __ATOMIC_RELAXED);
			mq->last_head = 0;
			mq->last_tail = 0;
			/* enable polling mode */
			if (pmd->role == MIIF_ROLE_SLAVE)
				ring->flags = MIIF_RING_FLAG_MASK_INT;

			flush_memory_block(ring, sizeof(miif_ring_t), 0);
		}

		pmd->flags &= ~ETH_MIIF_FLAG_CONNECTING;
		pmd->flags |= ETH_MIIF_FLAG_CONNECTED;
		dev->data->dev_link.link_status = ETH_LINK_UP;
	}
	MIIF_LOG(INFO, "Connected.");
	return 0;
}

static int
miif_dev_start(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	int ret = 0;

	switch (pmd->role) {
	case MIIF_ROLE_SLAVE:
		ret = miif_connect_slave(dev);
		break;
	case MIIF_ROLE_MASTER:
		ret = miif_connect_master(dev);
		break;
	default:
		MIIF_LOG(ERR, "%s: Unknown role: %d.",
			rte_vdev_device_name(pmd->vdev), pmd->role);
		ret = -1;
		break;
	}

	return ret;
}

static void
miif_dev_close(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	int i;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		miif_msg_enq_disconnect(pmd->cc, "Device closed", 0);
		miif_disconnect(dev);

		for (i = 0; i < dev->data->nb_rx_queues; i++)
			(*dev->dev_ops->rx_queue_release)(dev->data->rx_queues[i]);
		for (i = 0; i < dev->data->nb_tx_queues; i++)
			(*dev->dev_ops->tx_queue_release)(dev->data->tx_queues[i]);

		miif_socket_remove_device(dev);
	} else {
		miif_disconnect(dev);
	}

	rte_free(dev->process_private);
	mi_shmem_teardown();
}

static int
miif_dev_configure(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;

	/*
	 * SLAVE - TXQ
	 * MASTER - RXQ
	 */
	pmd->cfg.num_s2m_rings = (pmd->role == MIIF_ROLE_SLAVE) ?
				  dev->data->nb_tx_queues : dev->data->nb_rx_queues;

	/*
	 * SLAVE - RXQ
	 * MASTER - TXQ
	 */
	pmd->cfg.num_m2s_rings = (pmd->role == MIIF_ROLE_SLAVE) ?
				  dev->data->nb_rx_queues : dev->data->nb_tx_queues;

	return 0;
}

static int
miif_tx_queue_setup(struct rte_eth_dev *dev,
		     uint16_t qid,
		     uint16_t nb_tx_desc __rte_unused,
		     unsigned int socket_id __rte_unused,
		     const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_queue *mq;

	mq = rte_zmalloc("tx-queue", sizeof(struct miif_queue), 0);
	if (mq == NULL) {
		MIIF_LOG(ERR, "%s: Failed to allocate tx queue id: %u",
			rte_vdev_device_name(pmd->vdev), qid);
		return -ENOMEM;
	}

	mq->type =
	    (pmd->role == MIIF_ROLE_SLAVE) ? MIIF_RING_S2M : MIIF_RING_M2S;
	mq->n_pkts = 0;
	mq->n_bytes = 0;
	mq->intr_handle.fd = -1;
	mq->intr_handle.type = RTE_INTR_HANDLE_EXT;
	mq->in_port = dev->data->port_id;
	dev->data->tx_queues[qid] = mq;

	return 0;
}

static int
miif_rx_queue_setup(struct rte_eth_dev *dev,
		     uint16_t qid,
		     uint16_t nb_rx_desc __rte_unused,
		     unsigned int socket_id __rte_unused,
		     const struct rte_eth_rxconf *rx_conf __rte_unused,
		     struct rte_mempool *mb_pool)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_queue *mq;

	mq = rte_zmalloc("rx-queue", sizeof(struct miif_queue), 0);
	if (mq == NULL) {
		MIIF_LOG(ERR, "%s: Failed to allocate rx queue id: %u",
			rte_vdev_device_name(pmd->vdev), qid);
		return -ENOMEM;
	}

	mq->type = (pmd->role == MIIF_ROLE_SLAVE) ? MIIF_RING_M2S : MIIF_RING_S2M;
	mq->n_pkts = 0;
	mq->n_bytes = 0;
	mq->intr_handle.fd = -1;
	mq->intr_handle.type = RTE_INTR_HANDLE_EXT;
	mq->mempool = mb_pool;
	mq->in_port = dev->data->port_id;
	dev->data->rx_queues[qid] = mq;

	return 0;
}

static void
miif_queue_release(void *queue)
{
	struct miif_queue *mq = (struct miif_queue *)queue;

	if (!mq)
		return;

	rte_free(mq);
}

static int
miif_link_update(struct rte_eth_dev *dev,
		  int wait_to_complete __rte_unused)
{
	struct pmd_process_private *proc_private;
        struct pmd_internals *pmd;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		proc_private = dev->process_private;
		pmd = dev->data->dev_private;
		if (dev->data->dev_link.link_status == ETH_LINK_UP &&
				proc_private->regions_num == 0) {
			miif_mp_request_regions(dev);
		} else if (dev->data->dev_link.link_status == ETH_LINK_DOWN &&
				proc_private->regions_num > 0 &&
				pmd->role == MIIF_ROLE_MASTER) {
			miif_free_regions(proc_private);
		}
	}
	return 0;
}

static int
miif_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	struct miif_queue *mq;
	int i;
	uint8_t tmp, nq;

	stats->ipackets = 0;
	stats->ibytes = 0;
	stats->opackets = 0;
	stats->obytes = 0;

	tmp = (pmd->role == MIIF_ROLE_SLAVE) ? pmd->run.num_s2m_rings :
	    pmd->run.num_m2s_rings;
	nq = (tmp < RTE_ETHDEV_QUEUE_STAT_CNTRS) ? tmp :
	    RTE_ETHDEV_QUEUE_STAT_CNTRS;

	/* RX stats */
	for (i = 0; i < nq; i++) {
		mq = dev->data->rx_queues[i];
		stats->q_ipackets[i] = mq->n_pkts;
		stats->q_ibytes[i] = mq->n_bytes;
		stats->ipackets += mq->n_pkts;
		stats->ibytes += mq->n_bytes;
	}

	tmp = (pmd->role == MIIF_ROLE_SLAVE) ? pmd->run.num_m2s_rings :
	    pmd->run.num_s2m_rings;
	nq = (tmp < RTE_ETHDEV_QUEUE_STAT_CNTRS) ? tmp :
	    RTE_ETHDEV_QUEUE_STAT_CNTRS;

	/* TX stats */
	for (i = 0; i < nq; i++) {
		mq = dev->data->tx_queues[i];
		stats->q_opackets[i] = mq->n_pkts;
		stats->q_obytes[i] = mq->n_bytes;
		stats->opackets += mq->n_pkts;
		stats->obytes += mq->n_bytes;
	}
	return 0;
}

static int
miif_stats_reset(struct rte_eth_dev *dev)
{
	struct pmd_internals *pmd = dev->data->dev_private;
	int i;
	struct miif_queue *mq;

	for (i = 0; i < pmd->run.num_s2m_rings; i++) {
		mq = (pmd->role == MIIF_ROLE_SLAVE) ? dev->data->tx_queues[i] :
		    dev->data->rx_queues[i];
		mq->n_pkts = 0;
		mq->n_bytes = 0;
	}
	for (i = 0; i < pmd->run.num_m2s_rings; i++) {
		mq = (pmd->role == MIIF_ROLE_SLAVE) ? dev->data->rx_queues[i] :
		    dev->data->tx_queues[i];
		mq->n_pkts = 0;
		mq->n_bytes = 0;
	}

	return 0;
}

static int
miif_rx_queue_intr_enable(struct rte_eth_dev *dev __rte_unused,
			   uint16_t qid __rte_unused)
{
	MIIF_LOG(WARNING, "Interrupt mode not supported.");

	return -1;
}

static int
miif_rx_queue_intr_disable(struct rte_eth_dev *dev, uint16_t qid __rte_unused)
{
	struct pmd_internals *pmd __rte_unused = dev->data->dev_private;

	return 0;
}

static const struct eth_dev_ops ops = {
	.dev_start = miif_dev_start,
	.dev_close = miif_dev_close,
	.dev_infos_get = miif_dev_info,
	.dev_configure = miif_dev_configure,
	.tx_queue_setup = miif_tx_queue_setup,
	.rx_queue_setup = miif_rx_queue_setup,
	.rx_queue_release = miif_queue_release,
	.tx_queue_release = miif_queue_release,
	.rx_queue_intr_enable = miif_rx_queue_intr_enable,
	.rx_queue_intr_disable = miif_rx_queue_intr_disable,
	.link_update = miif_link_update,
	.stats_get = miif_stats_get,
	.stats_reset = miif_stats_reset,
};

static int
miif_create(struct rte_vdev_device *vdev, enum miif_role_t role,
	     miif_interface_id_t id, uint32_t flags,
	     const char *socket_filename,
	     miif_log2_ring_size_t log2_ring_size,
	     uint16_t pkt_buffer_size, const char *secret,
	     struct rte_ether_addr *ether_addr)
{
	int ret = 0;
	struct rte_eth_dev *eth_dev;
	struct rte_eth_dev_data *data;
	struct pmd_internals *pmd;
	struct pmd_process_private *process_private;
	const unsigned int numa_node = vdev->device.numa_node;
	const char *name = rte_vdev_device_name(vdev);

	if (flags & ETH_MIIF_FLAG_ZERO_COPY) {
		MIIF_LOG(ERR, "Zero-copy slave not supported.");
		return -1;
	}

	eth_dev = rte_eth_vdev_allocate(vdev, sizeof(*pmd));
	if (eth_dev == NULL) {
		MIIF_LOG(ERR, "%s: Unable to allocate device struct.", name);
		return -1;
	}

	process_private = (struct pmd_process_private *)
		rte_zmalloc(name, sizeof(struct pmd_process_private),
			    RTE_CACHE_LINE_SIZE);

	if (process_private == NULL) {
		MIIF_LOG(ERR, "Failed to alloc memory for process private");
		return -1;
	}
	eth_dev->process_private = process_private;

	pmd = eth_dev->data->dev_private;
	memset(pmd, 0, sizeof(*pmd));

	pmd->id = id;
	pmd->flags = flags;
	pmd->flags |= ETH_MIIF_FLAG_DISABLED;
	pmd->role = role;

	MIIF_LOG(INFO, "Socket Init with filename %s", socket_filename);

	ret = miif_socket_init(eth_dev, socket_filename);
	if (ret < 0)
		return ret;

	memset(pmd->secret, 0, sizeof(char) * ETH_MIIF_SECRET_SIZE);
	if (secret != NULL)
		strlcpy(pmd->secret, secret, sizeof(pmd->secret));

	pmd->cfg.log2_ring_size = log2_ring_size;
	/* set in .dev_configure() */
	pmd->cfg.num_s2m_rings = 0;
	pmd->cfg.num_m2s_rings = 0;

	pmd->cfg.pkt_buffer_size = pkt_buffer_size;

	data = eth_dev->data;
	data->dev_private = pmd;
	data->numa_node = numa_node;
	data->mac_addrs = ether_addr;

	eth_dev->dev_ops = &ops;
	eth_dev->device = &vdev->device;
	eth_dev->rx_pkt_burst = eth_miif_rx;
	eth_dev->tx_pkt_burst = eth_miif_tx;

	eth_dev->data->dev_flags &= RTE_ETH_DEV_CLOSE_REMOVE;

	rte_eth_dev_probing_finish(eth_dev);

	return 0;
}

static int
miif_set_role(const char *key __rte_unused, const char *value,
	       void *extra_args)
{
	enum miif_role_t *role = (enum miif_role_t *)extra_args;

	if (strstr(value, "master") != NULL) {
		*role = MIIF_ROLE_MASTER;
	} else if (strstr(value, "slave") != NULL) {
		*role = MIIF_ROLE_SLAVE;
	} else {
		MIIF_LOG(ERR, "Unknown role: %s.", value);
		return -EINVAL;
	}
	return 0;
}

static int
miif_set_zc(const char *key __rte_unused, const char *value, void *extra_args)
{
	uint32_t *flags = (uint32_t *)extra_args;

	if (strstr(value, "yes") != NULL) {
		*flags |= ETH_MIIF_FLAG_ZERO_COPY;
	} else if (strstr(value, "no") != NULL) {
		*flags &= ~ETH_MIIF_FLAG_ZERO_COPY;
	} else {
		MIIF_LOG(ERR, "Failed to parse zero-copy param: %s.", value);
		return -EINVAL;
	}
	return 0;
}

static int
miif_set_id(const char *key __rte_unused, const char *value, void *extra_args)
{
	miif_interface_id_t *id = (miif_interface_id_t *)extra_args;

	/* even if parsing fails, 0 is a valid id */
	*id = strtoul(value, NULL, 10);
	return 0;
}

static int
miif_set_bs(const char *key __rte_unused, const char *value, void *extra_args)
{
	unsigned long tmp;
	uint16_t *pkt_buffer_size = (uint16_t *)extra_args;

	tmp = strtoul(value, NULL, 10);
	if (tmp == 0 || tmp > 0xFFFF) {
		MIIF_LOG(ERR, "Invalid buffer size: %s.", value);
		return -EINVAL;
	}
	*pkt_buffer_size = tmp;
	return 0;
}

static int
miif_set_rs(const char *key __rte_unused, const char *value, void *extra_args)
{
	unsigned long tmp;
	miif_log2_ring_size_t *log2_ring_size =
	    (miif_log2_ring_size_t *)extra_args;

	tmp = strtoul(value, NULL, 10);
	if (tmp == 0 || tmp > ETH_MIIF_MAX_LOG2_RING_SIZE) {
		MIIF_LOG(ERR, "Invalid ring size: %s (max %u).",
			value, ETH_MIIF_MAX_LOG2_RING_SIZE);
		return -EINVAL;
	}
	*log2_ring_size = tmp;
	return 0;
}

/* check if directory exists and if we have permission to read/write */
static int
miif_check_socket_filename(const char *filename)
{
	int ret = 0;
	
	MIIF_LOG(INFO,"check_socket_filename: %s", filename);

	if (strlen(filename) >= MIIF_SOCKET_IN_SIZE) {
		MIIF_LOG(ERR, "Unix socket address too long (max 108).");
		return -1;
	}

	return ret;
}

static int
miif_set_socket_filename(const char *key __rte_unused, const char *value,
			  void *extra_args)
{
	const char **socket_filename = (const char **)extra_args;

	*socket_filename = value;
        MIIF_LOG(INFO, "setting socket filename to: %s", *socket_filename);

	return miif_check_socket_filename(*socket_filename);
}

static int
miif_set_mac(const char *key __rte_unused, const char *value, void *extra_args)
{
	struct rte_ether_addr *ether_addr = (struct rte_ether_addr *)extra_args;

	if (rte_ether_unformat_addr(value, ether_addr) < 0)
		MIIF_LOG(WARNING, "Failed to parse mac '%s'.", value);
	return 0;
}

static int
miif_set_secret(const char *key __rte_unused, const char *value, void *extra_args)
{
	const char **secret = (const char **)extra_args;

	*secret = value;
	return 0;
}

static int
rte_pmd_miif_probe(struct rte_vdev_device *vdev)
{
	RTE_BUILD_BUG_ON(sizeof(miif_msg_t) != 128);
	RTE_BUILD_BUG_ON(sizeof(miif_desc_t) != 16);
	int ret = 0;
	struct rte_kvargs *kvlist;
	const char *name = rte_vdev_device_name(vdev);
	enum miif_role_t role = MIIF_ROLE_SLAVE;
	miif_interface_id_t id = 0;
	uint16_t pkt_buffer_size = ETH_MIIF_DEFAULT_PKT_BUFFER_SIZE;
	miif_log2_ring_size_t log2_ring_size = ETH_MIIF_DEFAULT_RING_SIZE;
	const char *socket_filename = ETH_MIIF_DEFAULT_SOCKET_FILENAME;
	uint32_t flags = 0;
	const char *secret = NULL;
	struct rte_ether_addr *ether_addr = rte_zmalloc("",
		sizeof(struct rte_ether_addr), 0);
	struct rte_eth_dev *eth_dev;

	rte_eth_random_addr(ether_addr->addr_bytes);

	MIIF_LOG(INFO, "Initialize MIIF: %s.", name);

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		eth_dev = rte_eth_dev_attach_secondary(name);
		if (!eth_dev) {
			MIIF_LOG(ERR, "Failed to probe %s", name);
			return -1;
		}

		eth_dev->dev_ops = &ops;
		eth_dev->device = &vdev->device;
		eth_dev->rx_pkt_burst = eth_miif_rx;
		eth_dev->tx_pkt_burst = eth_miif_tx;

		if (!rte_eal_primary_proc_alive(NULL)) {
			MIIF_LOG(ERR, "Primary process is missing");
			return -1;
		}

		eth_dev->process_private = (struct pmd_process_private *)
			rte_zmalloc(name,
				sizeof(struct pmd_process_private),
				RTE_CACHE_LINE_SIZE);
		if (eth_dev->process_private == NULL) {
			MIIF_LOG(ERR,
				"Failed to alloc memory for process private");
			return -1;
		}

		rte_eth_dev_probing_finish(eth_dev);

		return 0;
	}

	ret = rte_mp_action_register(MIIF_MP_SEND_REGION, miif_mp_send_region);
	/*
	 * Primary process can continue probing, but secondary process won't
	 * be able to get memory regions information
	 */
	if (ret < 0 && rte_errno != EEXIST)
		MIIF_LOG(WARNING, "Failed to register mp action callback: %s",
			strerror(rte_errno));

	kvlist = rte_kvargs_parse(rte_vdev_device_args(vdev), valid_arguments);

	/* parse parameters */
	if (kvlist != NULL) {
		ret = rte_kvargs_process(kvlist, ETH_MIIF_ROLE_ARG,
					 &miif_set_role, &role);
		if (ret < 0)
			goto exit;
		ret = rte_kvargs_process(kvlist, ETH_MIIF_ID_ARG,
					 &miif_set_id, &id);
		if (ret < 0)
			goto exit;
		ret = rte_kvargs_process(kvlist, ETH_MIIF_PKT_BUFFER_SIZE_ARG,
					 &miif_set_bs, &pkt_buffer_size);
		if (ret < 0)
			goto exit;
		ret = rte_kvargs_process(kvlist, ETH_MIIF_RING_SIZE_ARG,
					 &miif_set_rs, &log2_ring_size);
		if (ret < 0)
			goto exit;
		ret = rte_kvargs_process(kvlist, ETH_MIIF_SOCKET_ARG,
					 &miif_set_socket_filename,
					 (void *)(&socket_filename));
		if (ret < 0)
			goto exit;
		ret = rte_kvargs_process(kvlist, ETH_MIIF_MAC_ARG,
					 &miif_set_mac, ether_addr);
		if (ret < 0)
			goto exit;
		ret = rte_kvargs_process(kvlist, ETH_MIIF_ZC_ARG,
					 &miif_set_zc, &flags);
		if (ret < 0)
			goto exit;
		ret = rte_kvargs_process(kvlist, ETH_MIIF_SECRET_ARG,
					 &miif_set_secret, (void *)(&secret));
		if (ret < 0)
			goto exit;
	}

        MIIF_LOG(INFO, "Creating miif_create called with filename: %s", socket_filename);

	/* create interface */
	ret = miif_create(vdev, role, id, flags, socket_filename,
			   log2_ring_size, pkt_buffer_size, secret, ether_addr);

exit:
	if (kvlist != NULL)
		rte_kvargs_free(kvlist);
	return ret;
}

static int
rte_pmd_miif_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev;

	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (eth_dev == NULL)
		return 0;

	rte_eth_dev_close(eth_dev->data->port_id);

	return 0;
}

static struct rte_vdev_driver pmd_miif_drv = {
	.probe = rte_pmd_miif_probe,
	.remove = rte_pmd_miif_remove,
};

RTE_PMD_REGISTER_VDEV(net_miif, pmd_miif_drv);

RTE_PMD_REGISTER_PARAM_STRING(net_miif,
			      ETH_MIIF_ID_ARG "=<int>"
			      ETH_MIIF_ROLE_ARG "=master|slave"
			      ETH_MIIF_PKT_BUFFER_SIZE_ARG "=<int>"
			      ETH_MIIF_RING_SIZE_ARG "=<int>"
			      ETH_MIIF_SOCKET_ARG "=<string>"
			      ETH_MIIF_MAC_ARG "=xx:xx:xx:xx:xx:xx"
			      ETH_MIIF_ZC_ARG "=yes|no"
			      ETH_MIIF_SECRET_ARG "=<string>");

int miif_logtype;

RTE_INIT(miif_init_log)
{
	miif_logtype = rte_log_register("pmd.net.miif");
	if (miif_logtype >= 0)
		rte_log_set_level(miif_logtype, RTE_LOG_NOTICE);
}
