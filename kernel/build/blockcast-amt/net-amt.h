/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 */
#ifndef _NET_AMT_H_
#define _NET_AMT_H_

#include <linux/siphash.h>
#include <linux/jhash.h>
#include <linux/netdevice.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <net/gro_cells.h>
#include <net/rtnetlink.h>

enum amt_msg_type {
	AMT_MSG_DISCOVERY = 1,
	AMT_MSG_ADVERTISEMENT,
	AMT_MSG_REQUEST,
	AMT_MSG_MEMBERSHIP_QUERY,
	AMT_MSG_MEMBERSHIP_UPDATE,
	AMT_MSG_MULTICAST_DATA,
	AMT_MSG_TEARDOWN,
	__AMT_MSG_MAX,
};

#define AMT_MSG_MAX (__AMT_MSG_MAX - 1)

enum amt_ops {
	/* A*B */
	AMT_OPS_INT,
	/* A+B */
	AMT_OPS_UNI,
	/* A-B */
	AMT_OPS_SUB,
	/* B-A */
	AMT_OPS_SUB_REV,
	__AMT_OPS_MAX,
};

#define AMT_OPS_MAX (__AMT_OPS_MAX - 1)

enum amt_filter {
	AMT_FILTER_FWD,
	AMT_FILTER_D_FWD,
	AMT_FILTER_FWD_NEW,
	AMT_FILTER_D_FWD_NEW,
	AMT_FILTER_ALL,
	AMT_FILTER_NONE_NEW,
	AMT_FILTER_BOTH,
	AMT_FILTER_BOTH_NEW,
	__AMT_FILTER_MAX,
};

#define AMT_FILTER_MAX (__AMT_FILTER_MAX - 1)

enum amt_act {
	AMT_ACT_GMI,
	AMT_ACT_GMI_ZERO,
	AMT_ACT_GT,
	AMT_ACT_STATUS_FWD_NEW,
	AMT_ACT_STATUS_D_FWD_NEW,
	AMT_ACT_STATUS_NONE_NEW,
	/* Emit only the upstream host-stack LEAVE for this (S, G).
	 * Does NOT touch snode->status / snode->flags / source_timer --
	 * used by the INCLUDE->EXCLUDE transition path to drain
	 * upstream refcounts BEFORE filter_mode flips, since
	 * amt_upstream_track no-ops once filter_mode != MCAST_INCLUDE
	 * and amt_cleanup_srcs would otherwise delete the snode
	 * silently with the refcount still held.
	 */
	AMT_ACT_UPSTREAM_LEAVE,
	__AMT_ACT_MAX,
};

#define AMT_ACT_MAX (__AMT_ACT_MAX - 1)

enum amt_status {
	AMT_STATUS_INIT,
	AMT_STATUS_SENT_DISCOVERY,
	AMT_STATUS_RECEIVED_DISCOVERY,
	AMT_STATUS_SENT_ADVERTISEMENT,
	AMT_STATUS_RECEIVED_ADVERTISEMENT,
	AMT_STATUS_SENT_REQUEST,
	AMT_STATUS_RECEIVED_REQUEST,
	AMT_STATUS_SENT_QUERY,
	AMT_STATUS_RECEIVED_QUERY,
	AMT_STATUS_SENT_UPDATE,
	AMT_STATUS_RECEIVED_UPDATE,
	__AMT_STATUS_MAX,
};

#define AMT_STATUS_MAX (__AMT_STATUS_MAX - 1)

/* Gateway events only */
enum amt_event {
	AMT_EVENT_NONE,
	AMT_EVENT_RECEIVE,
	AMT_EVENT_SEND_DISCOVERY,
	AMT_EVENT_SEND_REQUEST,
	__AMT_EVENT_MAX,
};

struct amt_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 type:4,
	   version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 version:4,
	   type:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __packed;

struct amt_header_discovery {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u32	type:4,
		version:4,
		reserved:24;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u32	version:4,
		type:4,
		reserved:24;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32	nonce;
} __packed;

struct amt_header_advertisement {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u32	type:4,
		version:4,
		reserved:24;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u32	version:4,
		type:4,
		reserved:24;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32	nonce;
	__be32	ip4;
} __packed;

#if IS_ENABLED(CONFIG_IPV6)
/* RFC 7450 §5.1.2 Relay Advertisement message — IPv6 form.
 *
 * Same fixed 4-byte header and 4-byte Discovery Nonce as the IPv4
 * variant (struct amt_header_advertisement above); the trailing
 * Relay Address field is 16 bytes instead of 4. Total wire size:
 * 4 + 4 + 16 = 24 bytes. Per §5.2 the form is selected from the
 * outer IP version, not from any in-header marker, so this is a
 * separate type rather than a union over amt_header_advertisement.
 */
struct amt_header_advertisement_v6 {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u32	type:4,
		version:4,
		reserved:24;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u32	version:4,
		type:4,
		reserved:24;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32		nonce;
	struct in6_addr	ip6;
} __packed;
#endif /* CONFIG_IPV6 */

struct amt_header_request {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u32	type:4,
		version:4,
		reserved1:7,
		p:1,
		reserved2:16;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u32	version:4,
		type:4,
		p:1,
		reserved1:7,
		reserved2:16;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32	nonce;
} __packed;

struct amt_header_membership_query {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u64	type:4,
		version:4,
		reserved:6,
		l:1,
		g:1,
		response_mac:48;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u64	version:4,
		type:4,
		g:1,
		l:1,
		reserved:6,
		response_mac:48;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32	nonce;
} __packed;

struct amt_header_membership_update {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u64	type:4,
		version:4,
		reserved:8,
		response_mac:48;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u64	version:4,
		type:4,
		reserved:8,
		response_mac:48;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
	__be32	nonce;
} __packed;

struct amt_header_mcast_data {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u16	type:4,
		version:4,
		reserved:8;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u16	version:4,
		type:4,
		reserved:8;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __packed;

struct amt_headers {
	union {
		struct amt_header_discovery discovery;
		struct amt_header_advertisement advertisement;
		struct amt_header_request request;
		struct amt_header_membership_query query;
		struct amt_header_membership_update update;
		struct amt_header_mcast_data data;
	};
} __packed;

struct amt_gw_headers {
	union {
		struct amt_header_discovery discovery;
		struct amt_header_request request;
		struct amt_header_membership_update update;
	};
} __packed;

struct amt_relay_headers {
	union {
		struct amt_header_advertisement advertisement;
		struct amt_header_membership_query query;
		struct amt_header_mcast_data data;
	};
} __packed;

struct amt_skb_cb {
	struct amt_tunnel_list *tunnel;
};

union amt_addr {
	__be32			ip4;
#if IS_ENABLED(CONFIG_IPV6)
	struct in6_addr		ip6;
#endif
};

/* Upstream IGMPv3 / MLDv2 host-stack membership state. Sized for production
 * relay scale (thousands of active (S, G) tuples possible).
 */
#define AMT_UPSTREAM_HASH_BITS	10
#define AMT_UPSTREAM_HASH_SIZE	(1u << AMT_UPSTREAM_HASH_BITS)

struct amt_upstream_entry {
	struct hlist_node	node;
	__be32			group;
	__be32			source;
	int			refcount;
};

#if IS_ENABLED(CONFIG_IPV6)
struct amt_upstream_entry_v6 {
	struct hlist_node	node;
	struct in6_addr		group;
	struct in6_addr		source;
	int			refcount;
};
#endif

enum amt_upstream_op { AMT_UPSTREAM_JOIN, AMT_UPSTREAM_LEAVE };

struct amt_upstream_pending {
	struct list_head	link;
	int			family;	/* AF_INET or AF_INET6 */
	union {
		struct {
			__be32		group_v4;
			__be32		source_v4;
		};
#if IS_ENABLED(CONFIG_IPV6)
		struct {
			struct in6_addr	group_v6;
			struct in6_addr	source_v6;
		};
#endif
	};
	enum amt_upstream_op	op;
};

/* Per-tunnel rhltable initialisation lifecycle.
 *
 * amt_alloc_tunnel runs in softirq context (encap_rcv UDP path) with
 * GFP_ATOMIC, but rhltable_init internally allocates the bucket table
 * with GFP_KERNEL. We split the work: the softirq path allocates the
 * tunnel skeleton and queues amt_tunnel_init_work onto amt_wq; the
 * process-context worker calls rhltable_init and flips the state to
 * READY. Membership Updates arriving before READY are dropped (the
 * gateway re-transmits — the init window is ~milliseconds while the
 * AMT retransmit interval is 1 second).
 */
enum amt_tunnel_init_state {
	AMT_TUNNEL_INIT_PENDING,
	AMT_TUNNEL_INIT_READY,
	AMT_TUNNEL_INIT_FAILED,
};

struct amt_tunnel_list {
	struct list_head	list;
	/* Protect All resources under an amt_tunne_list */
	spinlock_t		lock;
	struct amt_dev		*amt;
	u32			nr_groups;
	u32			nr_sources;
	enum amt_status		status;
	struct delayed_work	gc_wq;
	__be16			source_port;
	/* Outer source address of the gateway endpoint. addr.ip4 is
	 * populated when v6 == false; addr.ip6 when v6 == true. The family
	 * is fixed at the relay netdev level by the encap socket
	 * (amt_create_sock branches on !ipv6_addr_any(local_ipv6)).
	 */
	union amt_addr		addr;
	bool			v6;
	__be32			nonce;
	siphash_key_t		key;
	u64			mac:48,
				reserved:16;
	struct rcu_head		rcu;
	/* rhltable backing the per-tunnel (group, host) lookup. rhltable
	 * (not rhashtable) because the data-plane fan-out at
	 * amt_dev_xmit must walk every gnode matching a multicast group
	 * regardless of inner host -- rhltable returns a list per key
	 * via rhltable_lookup, while rhashtable_lookup_fast returns only
	 * one entry.
	 *
	 * State machine via init_state + init_wq because rhltable_init
	 * allocates with GFP_KERNEL (see comment on
	 * enum amt_tunnel_init_state). All hash-touching callers must
	 * check atomic_read_acquire(&init_state) == AMT_TUNNEL_INIT_READY
	 * before reaching into groups_rhl.
	 *
	 * Teardown: cancel_work_sync(&init_wq) BEFORE rhltable_destroy
	 * so a deferred init worker can't race the destroy. cancel + a
	 * subsequent state==READY check is safe regardless of whether
	 * the worker had a chance to run.
	 */
	atomic_t		init_state;
	struct work_struct	init_wq;
	struct rhltable		groups_rhl;
};

/* RFC 3810
 *
 * When the router is in EXCLUDE mode, the router state is represented
 * by the notation EXCLUDE (X,Y), where X is called the "Requested List"
 * and Y is called the "Exclude List".  All sources, except those from
 * the Exclude List, will be forwarded by the router
 */
enum amt_source_status {
	AMT_SOURCE_STATUS_NONE,
	/* Node of Requested List */
	AMT_SOURCE_STATUS_FWD,
	/* Node of Exclude List */
	AMT_SOURCE_STATUS_D_FWD,
};

/* protected by gnode->lock */
struct amt_source_node {
	struct hlist_node	node;
	struct amt_group_node	*gnode;
	struct delayed_work     source_timer;
	union amt_addr		source_addr;
	enum amt_source_status	status;
#define AMT_SOURCE_OLD	0
#define AMT_SOURCE_NEW	1
	u8			flags;
	struct rcu_head		rcu;
};

/* Protected by amt_tunnel_list->lock */
struct amt_group_node {
	struct amt_dev		*amt;
	union amt_addr		group_addr;
	union amt_addr		host_addr;
	bool			v6;
	u8			filter_mode;
	u32			nr_sources;
	struct amt_tunnel_list	*tunnel_list;
	/* rhltable list-membership node. Keyed by (group_addr, v6) only
	 * (see amt_gnode_rht_params); the host_addr filter is applied
	 * by amt_lookup_group after iterating the per-key rhlist. This
	 * matches the legacy hlist behavior where multiple gnodes with
	 * the same group but different inner hosts shared a bucket.
	 */
	struct rhlist_head	rhlnode;
	struct delayed_work     group_timer;
	struct rcu_head		rcu;
	struct hlist_head	sources[];
};

#define AMT_MAX_EVENTS	16
struct amt_events {
	enum amt_event event;
	struct sk_buff *skb;
};

struct amt_dev {
	struct net_device       *dev;
	struct net_device       *stream_dev;
	struct net		*net;
	/* Global lock for amt device */
	spinlock_t		lock;
	/* Used only in relay mode */
	struct list_head        tunnel_list;
	struct gro_cells	gro_cells;

	/* Protected by RTNL */
	struct delayed_work     discovery_wq;
	/* Protected by RTNL */
	struct delayed_work     req_wq;
	/* Protected by RTNL */
	struct delayed_work     secret_wq;
	struct work_struct	event_wq;
	/* AMT status */
	enum amt_status		status;
	/* Generated key */
	siphash_key_t		key;
	struct socket	  __rcu *sock;
	u32			max_groups;
	u32			max_sources;
	u32			hash_buckets;
	u32			hash_seed;
	/* Default 128 */
	u32                     max_tunnels;
	/* Default 128 */
	u32                     nr_tunnels;
	/* Gateway or Relay mode */
	u32                     mode;
	/* Default 2268 */
	__be16			relay_port;
	/* Default 2268 */
	__be16			gw_port;
	/* Outer local ip */
	__be32			local_ip;
	/* Outer local ipv6 (in6addr_any when v4 mode; mutually exclusive with local_ip) */
	struct in6_addr		local_ipv6;
	/* Outer remote ip */
	__be32			remote_ip;
	/* Outer discovery ip */
	__be32			discovery_ip;
	/* Only used in gateway mode */
	__be32			nonce;
	/* Gateway sent request and received query */
	bool			ready4;
	bool			ready6;
	u8			req_cnt;
	u8			qi;
	u64			qrv;
	u64			qri;
	/* Used only in gateway mode */
	u64			mac:48,
				reserved:16;
	/* AMT gateway side message handler queue */
	struct amt_events	events[AMT_MAX_EVENTS];
	u8			event_idx;
	u8			nr_events;

	/* Upstream IGMPv3/MLDv2 host-stack membership state.
	 *
	 * Relay mode joins (S, G) on the underlying stream_dev via setsockopt
	 * on stream_sock_v{4,6}. The refcount tables coalesce many gateway
	 * Membership Updates referring to the same (S, G) into a single
	 * host-stack join/leave (0->1 emit, 1->0 emit; intermediate ops are
	 * pure refcount bumps). All setsockopt calls run from upstream_work
	 * (process context) so the rtnl_lock taken internally by the IGMP/MLD
	 * filter path is always taken AFTER any caller-held locks, avoiding the
	 * AB-BA deadlock that motivated this rewrite. upstream_lock is bh and
	 * may be taken from softirq (gateway decap path) and process context.
	 * upstream_pending_lock guards the FIFO of deferred emits drained by
	 * the worker; upstream_active gates whether the worker should run at
	 * all (cleared in amt_dev_stop to fence late ops during teardown).
	 */
	spinlock_t		upstream_lock;
	struct hlist_head	upstream[AMT_UPSTREAM_HASH_SIZE];
#if IS_ENABLED(CONFIG_IPV6)
	struct hlist_head	upstream_v6[AMT_UPSTREAM_HASH_SIZE];
#endif
	bool			upstream_active;
	struct work_struct	upstream_work;
	spinlock_t		upstream_pending_lock;
	struct list_head	upstream_pending;
	struct socket __rcu	*stream_sock_v4;
#if IS_ENABLED(CONFIG_IPV6)
	struct socket __rcu	*stream_sock_v6;
#endif
	atomic_t		upstream_setsockopt_slow_count;
};

#define AMT_TOS			0xc0
#define AMT_IPHDR_OPTS		4
#define AMT_IP6HDR_OPTS		8
#define AMT_GC_INTERVAL		(30 * 1000)
#define AMT_MAX_GROUP		32
#define AMT_MAX_SOURCE		128
#define AMT_HSIZE_SHIFT		8
#define AMT_HSIZE		(1 << AMT_HSIZE_SHIFT)

#define AMT_DISCOVERY_TIMEOUT	5000
#define AMT_INIT_REQ_TIMEOUT	1
#define AMT_INIT_QUERY_INTERVAL	125
#define AMT_MAX_REQ_TIMEOUT	120
#define AMT_MAX_REQ_COUNT	3
#define AMT_SECRET_TIMEOUT	60000
#define IANA_AMT_UDP_PORT	2268
#define AMT_MAX_TUNNELS         128
#define AMT_MAX_REQS		128
/* Upper bound on TX/RX queues an amt netdev can be allocated with.
 * The actual live queue count is set per-link via IFLA_AMT_NUM_QUEUES
 * with a default of 1 (backwards-compatible). Picked to match a
 * reasonable upper bound on per-relay parallelism; bigger numbers
 * just waste alloc memory (a few hundred bytes per reserved slot).
 */
#define AMT_MAX_QUEUES		32
#define AMT_GW_HLEN (sizeof(struct iphdr) + \
		     sizeof(struct udphdr) + \
		     sizeof(struct amt_gw_headers))
#define AMT_RELAY_HLEN (sizeof(struct iphdr) + \
		     sizeof(struct udphdr) + \
		     sizeof(struct amt_relay_headers))

static inline bool netif_is_amt(const struct net_device *dev)
{
	return dev->rtnl_link_ops && !strcmp(dev->rtnl_link_ops->kind, "amt");
}

static inline u64 amt_gmi(const struct amt_dev *amt)
{
	return ((amt->qrv * amt->qi) + amt->qri) * 1000;
}

#endif /* _NET_AMT_H_ */
