/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com>
 */
#ifndef _UAPI_AMT_H_
#define _UAPI_AMT_H_

enum ifla_amt_mode {
	/* AMT interface works as Gateway mode.
	 * The Gateway mode encapsulates IGMP/MLD traffic and decapsulates
	 * multicast traffic.
	 */
	AMT_MODE_GATEWAY = 0,
	/* AMT interface works as Relay mode.
	 * The Relay mode encapsulates multicast traffic and decapsulates
	 * IGMP/MLD traffic.
	 */
	AMT_MODE_RELAY,
	__AMT_MODE_MAX,
};

#define AMT_MODE_MAX (__AMT_MODE_MAX - 1)

enum {
	IFLA_AMT_UNSPEC,
	/* This attribute specify mode etier Gateway or Relay. */
	IFLA_AMT_MODE,
	/* This attribute specify Relay port.
	 * AMT interface is created as Gateway mode, this attribute is used
	 * to specify relay(remote) port.
	 * AMT interface is created as Relay mode, this attribute is used
	 * as local port.
	 */
	IFLA_AMT_RELAY_PORT,
	/* This attribute specify Gateway port.
	 * AMT interface is created as Gateway mode, this attribute is used
	 * as local port.
	 * AMT interface is created as Relay mode, this attribute is not used.
	 */
	IFLA_AMT_GATEWAY_PORT,
	/* This attribute specify physical device */
	IFLA_AMT_LINK,
	/* This attribute specify local ip address */
	IFLA_AMT_LOCAL_IP,
	/* This attribute specify Relay ip address.
	 * So, this is not used by Relay.
	 */
	IFLA_AMT_REMOTE_IP,
	/* This attribute specify Discovery ip address.
	 * When Gateway get started, it send discovery message to find the
	 * Relay's ip address.
	 * So, this is not used by Relay.
	 */
	IFLA_AMT_DISCOVERY_IP,
	/* This attribute specify number of maximum tunnel. */
	IFLA_AMT_MAX_TUNNELS,
	/* This attribute specify the local IPv6 address used by the relay
	 * for AMT Discovery / Advertisement (RFC 7450 §5.1.2 v6 form).
	 * Mutually exclusive with IFLA_AMT_LOCAL_IP — exactly one must be
	 * supplied at link creation. Gateway-mode only uses IFLA_AMT_LOCAL_IP
	 * today; v6 gateway support is out of scope.
	 */
	IFLA_AMT_LOCAL_IP6,
	/* This attribute specifies the number of hash buckets used to index
	 * the per-tunnel groups[] hash table. Default AMT_HSIZE (256). At
	 * high tunnel counts the average chain length is nr_tunnels/buckets,
	 * which dominates Membership-Update lookup cost; bumping buckets to
	 * approximately match peak tunnel count keeps the cost amortised
	 * O(1). Must be a power of two. Allocation is per-tunnel
	 * (sizeof(struct hlist_head) * hash_buckets) so larger values trade
	 * kernel slab for lookup speed.
	 */
	IFLA_AMT_HASH_BUCKETS,
	/* This attribute specifies the maximum number of multicast groups a
	 * single gateway may aggregate behind one tunnel. Default
	 * AMT_MAX_GROUP (32). Client-edge boxes serving many channels can
	 * exceed this; raising the cap permits a single gateway to join
	 * up to N groups before the 33rd join is refused with ENOSPC.
	 */
	IFLA_AMT_MAX_GROUPS,
	/* This attribute specifies how many TX/RX queues the amt netdev is
	 * created with. Default 1 (preserves existing behavior). Larger
	 * values let the kernel pick distinct txq locks per CPU at
	 * dev_queue_xmit time, so concurrent multicast-forwarding softirqs
	 * fanning out to many distinct (S,G) tunnels can encap in parallel
	 * rather than serializing on a single _xmit_lock. Capped at
	 * AMT_MAX_QUEUES (the allocation reserves slots up front).
	 */
	IFLA_AMT_NUM_QUEUES,
	__IFLA_AMT_MAX,
};

#define IFLA_AMT_MAX (__IFLA_AMT_MAX - 1)

#endif /* _UAPI_AMT_H_ */
