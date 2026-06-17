// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2021 Taehee Yoo <ap420073@gmail.com> */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/jhash.h>
#include <linux/if_tunnel.h>
#include <linux/net.h>
#include <linux/igmp.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <net/pkt_sched.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/inet_dscp.h>
#include <net/icmp.h>
#include <net/mld.h>
#include <net/amt.h>
#include <uapi/linux/amt.h>
#include <linux/security.h>
#include <net/gro_cells.h>
#include <net/ipv6.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <net/ipv6_stubs.h>
#endif
#include <net/if_inet6.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/inet_common.h>
#include <net/ip6_checksum.h>

static struct workqueue_struct *amt_wq;

static HLIST_HEAD(source_gc_list);
/* Lock for source_gc_list */
static spinlock_t source_gc_lock;
static struct delayed_work source_gc_wq;
static char *status_str[] = {
	"AMT_STATUS_INIT",
	"AMT_STATUS_SENT_DISCOVERY",
	"AMT_STATUS_RECEIVED_DISCOVERY",
	"AMT_STATUS_SENT_ADVERTISEMENT",
	"AMT_STATUS_RECEIVED_ADVERTISEMENT",
	"AMT_STATUS_SENT_REQUEST",
	"AMT_STATUS_RECEIVED_REQUEST",
	"AMT_STATUS_SENT_QUERY",
	"AMT_STATUS_RECEIVED_QUERY",
	"AMT_STATUS_SENT_UPDATE",
	"AMT_STATUS_RECEIVED_UPDATE",
};

static char *type_str[] = {
	"", /* Type 0 is not defined */
	"AMT_MSG_DISCOVERY",
	"AMT_MSG_ADVERTISEMENT",
	"AMT_MSG_REQUEST",
	"AMT_MSG_MEMBERSHIP_QUERY",
	"AMT_MSG_MEMBERSHIP_UPDATE",
	"AMT_MSG_MULTICAST_DATA",
	"AMT_MSG_TEARDOWN",
};

static char *action_str[] = {
	"AMT_ACT_GMI",
	"AMT_ACT_GMI_ZERO",
	"AMT_ACT_GT",
	"AMT_ACT_STATUS_FWD_NEW",
	"AMT_ACT_STATUS_D_FWD_NEW",
	"AMT_ACT_STATUS_NONE_NEW",
	"AMT_ACT_UPSTREAM_LEAVE",
};

static struct igmpv3_grec igmpv3_zero_grec;

#if IS_ENABLED(CONFIG_IPV6)
#define MLD2_ALL_NODE_INIT { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } }
static struct in6_addr mld2_all_node = MLD2_ALL_NODE_INIT;
static struct mld2_grec mldv2_zero_grec;
#endif

static struct amt_skb_cb *amt_skb_cb(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct amt_skb_cb) + sizeof(struct tc_skb_cb) >
		     sizeof_field(struct sk_buff, cb));

	return (struct amt_skb_cb *)((void *)skb->cb +
		sizeof(struct tc_skb_cb));
}

static void __amt_source_gc_work(void)
{
	struct amt_source_node *snode;
	struct hlist_head gc_list;
	struct hlist_node *t;

	spin_lock_bh(&source_gc_lock);
	hlist_move_list(&source_gc_list, &gc_list);
	spin_unlock_bh(&source_gc_lock);

	hlist_for_each_entry_safe(snode, t, &gc_list, node) {
		hlist_del_rcu(&snode->node);
		kfree_rcu(snode, rcu);
	}
}

static void amt_source_gc_work(struct work_struct *work)
{
	__amt_source_gc_work();

	spin_lock_bh(&source_gc_lock);
	mod_delayed_work(amt_wq, &source_gc_wq,
			 msecs_to_jiffies(AMT_GC_INTERVAL));
	spin_unlock_bh(&source_gc_lock);
}

static bool amt_addr_equal(const union amt_addr *a, const union amt_addr *b)
{
	return !memcmp(a, b, sizeof(union amt_addr));
}

static u32 amt_source_hash(struct amt_tunnel_list *tunnel, union amt_addr *src)
{
	u32 hash = jhash(src, sizeof(*src), tunnel->amt->hash_seed);

	return reciprocal_scale(hash, tunnel->amt->hash_buckets);
}

static bool amt_status_filter(struct amt_source_node *snode,
			      enum amt_filter filter)
{
	bool rc = false;

	switch (filter) {
	case AMT_FILTER_FWD:
		if (snode->status == AMT_SOURCE_STATUS_FWD &&
		    snode->flags == AMT_SOURCE_OLD)
			rc = true;
		break;
	case AMT_FILTER_D_FWD:
		if (snode->status == AMT_SOURCE_STATUS_D_FWD &&
		    snode->flags == AMT_SOURCE_OLD)
			rc = true;
		break;
	case AMT_FILTER_FWD_NEW:
		if (snode->status == AMT_SOURCE_STATUS_FWD &&
		    snode->flags == AMT_SOURCE_NEW)
			rc = true;
		break;
	case AMT_FILTER_D_FWD_NEW:
		if (snode->status == AMT_SOURCE_STATUS_D_FWD &&
		    snode->flags == AMT_SOURCE_NEW)
			rc = true;
		break;
	case AMT_FILTER_ALL:
		rc = true;
		break;
	case AMT_FILTER_NONE_NEW:
		if (snode->status == AMT_SOURCE_STATUS_NONE &&
		    snode->flags == AMT_SOURCE_NEW)
			rc = true;
		break;
	case AMT_FILTER_BOTH:
		if ((snode->status == AMT_SOURCE_STATUS_D_FWD ||
		     snode->status == AMT_SOURCE_STATUS_FWD) &&
		    snode->flags == AMT_SOURCE_OLD)
			rc = true;
		break;
	case AMT_FILTER_BOTH_NEW:
		if ((snode->status == AMT_SOURCE_STATUS_D_FWD ||
		     snode->status == AMT_SOURCE_STATUS_FWD) &&
		    snode->flags == AMT_SOURCE_NEW)
			rc = true;
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	return rc;
}

static struct amt_source_node *amt_lookup_src(struct amt_tunnel_list *tunnel,
					      struct amt_group_node *gnode,
					      enum amt_filter filter,
					      union amt_addr *src)
{
	u32 hash = amt_source_hash(tunnel, src);
	struct amt_source_node *snode;

	hlist_for_each_entry_rcu(snode, &gnode->sources[hash], node)
		if (amt_status_filter(snode, filter) &&
		    amt_addr_equal(&snode->source_addr, src))
			return snode;

	return NULL;
}

/* rhltable lookup key for per-tunnel groups. Keyed by (group_addr, v6)
 * only -- the inner host_addr is checked by amt_lookup_group after
 * walking the per-key list returned by rhltable_lookup. Multiple gnodes
 * with the same group but different inner hosts share an rhltable list,
 * matching the legacy hlist semantics where they shared a hash bucket.
 */
struct amt_gnode_key {
	union amt_addr		group_addr;
	bool			v6;
};

static u32 amt_gnode_key_hashfn(const void *data, u32 len, u32 seed)
{
	const struct amt_gnode_key *key = data;

	return jhash(&key->group_addr, sizeof(key->group_addr), seed) ^
	       (key->v6 ? 0x55aa55aau : 0u);
}

static u32 amt_gnode_obj_hashfn(const void *obj, u32 len, u32 seed)
{
	const struct amt_group_node *gnode = obj;

	return jhash(&gnode->group_addr, sizeof(gnode->group_addr), seed) ^
	       (gnode->v6 ? 0x55aa55aau : 0u);
}

static int amt_gnode_obj_cmpfn(struct rhashtable_compare_arg *arg,
			       const void *obj)
{
	const struct amt_gnode_key *key = arg->key;
	const struct amt_group_node *gnode = obj;

	if (gnode->v6 != key->v6)
		return 1;
	return amt_addr_equal(&gnode->group_addr, &key->group_addr) ? 0 : 1;
}

static const struct rhashtable_params amt_gnode_rht_params = {
	.head_offset		= offsetof(struct amt_group_node, rhlnode),
	.hashfn			= amt_gnode_key_hashfn,
	.obj_hashfn		= amt_gnode_obj_hashfn,
	.obj_cmpfn		= amt_gnode_obj_cmpfn,
	.automatic_shrinking	= true,
};

/* True when the per-tunnel groups_rhl bucket table is initialised and
 * safe to lookup/insert/remove against. Returns false during the brief
 * window between amt_alloc_tunnel scheduling amt_tunnel_init_work and
 * the worker completing rhltable_init in process context. Callers in
 * softirq context must check this before touching tunnel->groups_rhl;
 * the data plane drops the packet (gateway retransmits) and the
 * control plane bails out of the Update parse for this tunnel.
 *
 * acquire-ordering pairs with the smp_store_release done in
 * amt_tunnel_init_work, so all writes to groups_rhl performed by
 * rhltable_init are visible once we observe AMT_TUNNEL_INIT_READY.
 */
static inline bool amt_tunnel_groups_ready(struct amt_tunnel_list *tunnel)
{
	return atomic_read_acquire(&tunnel->init_state) ==
	       AMT_TUNNEL_INIT_READY;
}

static struct amt_group_node *amt_lookup_group(struct amt_tunnel_list *tunnel,
					       union amt_addr *group,
					       union amt_addr *host,
					       bool v6)
{
	struct amt_gnode_key key = {
		.group_addr	= *group,
		.v6		= v6,
	};
	struct amt_group_node *gnode;
	struct rhlist_head *list, *tmp;

	if (!amt_tunnel_groups_ready(tunnel))
		return NULL;

	list = rhltable_lookup(&tunnel->groups_rhl, &key,
			       amt_gnode_rht_params);
	if (!list)
		return NULL;

	rhl_for_each_entry_rcu(gnode, tmp, list, rhlnode) {
		if (amt_addr_equal(&gnode->host_addr, host))
			return gnode;
	}

	return NULL;
}

/* Forward declaration: amt_upstream_track is defined later (after the
 * refcount + emit helpers it depends on), but amt_del_group,
 * amt_source_work, amt_act_src, and amt_cleanup_srcs all need to call
 * it. The function body lives at the bottom of the upstream-emit block.
 */
static void amt_upstream_track(struct amt_dev *amt,
			       struct amt_group_node *gnode,
			       struct amt_source_node *snode, bool join);

static void amt_destroy_source(struct amt_source_node *snode)
{
	struct amt_group_node *gnode = snode->gnode;
	struct amt_tunnel_list *tunnel;

	tunnel = gnode->tunnel_list;

	if (!gnode->v6) {
		netdev_dbg(snode->gnode->amt->dev,
			   "Delete source %pI4 from %pI4\n",
			   &snode->source_addr.ip4,
			   &gnode->group_addr.ip4);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		netdev_dbg(snode->gnode->amt->dev,
			   "Delete source %pI6 from %pI6\n",
			   &snode->source_addr.ip6,
			   &gnode->group_addr.ip6);
#endif
	}

	cancel_delayed_work(&snode->source_timer);
	hlist_del_init_rcu(&snode->node);
	tunnel->nr_sources--;
	gnode->nr_sources--;
	spin_lock_bh(&source_gc_lock);
	hlist_add_head_rcu(&snode->node, &source_gc_list);
	spin_unlock_bh(&source_gc_lock);
}

static void amt_del_group(struct amt_dev *amt, struct amt_group_node *gnode)
{
	struct amt_source_node *snode;
	struct hlist_node *t;
	int i;

	if (cancel_delayed_work(&gnode->group_timer))
		dev_put(amt->dev);
	/* amt_clear_groups walks the rhltable removing every entry, so
	 * an entry that was already removed by a concurrent path (e.g.,
	 * source-list state machine transitioning the last source out)
	 * may hit -ENOENT here. That's expected and not an error -- the
	 * walker logic ignores the return value.
	 */
	rhltable_remove(&gnode->tunnel_list->groups_rhl, &gnode->rhlnode,
			amt_gnode_rht_params);
	gnode->tunnel_list->nr_groups--;

	if (!gnode->v6)
		netdev_dbg(amt->dev, "Leave group %pI4\n",
			   &gnode->group_addr.ip4);
#if IS_ENABLED(CONFIG_IPV6)
	else
		netdev_dbg(amt->dev, "Leave group %pI6\n",
			   &gnode->group_addr.ip6);
#endif
	for (i = 0; i < amt->hash_buckets; i++)
		hlist_for_each_entry_safe(snode, t, &gnode->sources[i], node) {
			/* CMT3 audit: group-teardown source removal. Emit LEAVE
			 * for every (S, G) the kernel host stack still holds.
			 * track() no-ops if filter_mode != INCLUDE, so this is
			 * benign for EXCLUDE-mode groups (where the JOIN was
			 * never emitted to begin with).
			 */
			amt_upstream_track(amt, gnode, snode, false);
			amt_destroy_source(snode);
		}

	/* tunnel->lock was acquired outside of amt_del_group()
	 * But rcu_read_lock() was acquired too so It's safe.
	 */
	kfree_rcu(gnode, rcu);
}

/* If a source timer expires with a router filter-mode for the group of
 * INCLUDE, the router concludes that traffic from this particular
 * source is no longer desired on the attached network, and deletes the
 * associated source record.
 */
static void amt_source_work(struct work_struct *work)
{
	struct amt_source_node *snode = container_of(to_delayed_work(work),
						     struct amt_source_node,
						     source_timer);
	struct amt_group_node *gnode = snode->gnode;
	struct amt_dev *amt = gnode->amt;
	struct amt_tunnel_list *tunnel;

	tunnel = gnode->tunnel_list;
	spin_lock_bh(&tunnel->lock);
	rcu_read_lock();
	if (gnode->filter_mode == MCAST_INCLUDE) {
		/* CMT3 audit: source-timer expiry in INCLUDE mode is the
		 * canonical RFC 3376 aging path -- emit LEAVE before the
		 * snode goes onto the RCU GC list.
		 */
		amt_upstream_track(amt, gnode, snode, false);
		amt_destroy_source(snode);
		if (!gnode->nr_sources)
			amt_del_group(amt, gnode);
	} else {
		/* When a router filter-mode for a group is EXCLUDE,
		 * source records are only deleted when the group timer expires
		 */
		snode->status = AMT_SOURCE_STATUS_D_FWD;
	}
	rcu_read_unlock();
	spin_unlock_bh(&tunnel->lock);
}

static void amt_act_src(struct amt_tunnel_list *tunnel,
			struct amt_group_node *gnode,
			struct amt_source_node *snode,
			enum amt_act act)
{
	struct amt_dev *amt = tunnel->amt;

	switch (act) {
	case AMT_ACT_GMI:
		mod_delayed_work(amt_wq, &snode->source_timer,
				 msecs_to_jiffies(amt_gmi(amt)));
		break;
	case AMT_ACT_GMI_ZERO:
		cancel_delayed_work(&snode->source_timer);
		break;
	case AMT_ACT_GT:
		mod_delayed_work(amt_wq, &snode->source_timer,
				 gnode->group_timer.timer.expires);
		break;
	case AMT_ACT_STATUS_FWD_NEW:
		snode->status = AMT_SOURCE_STATUS_FWD;
		snode->flags = AMT_SOURCE_NEW;
		amt_upstream_track(amt, gnode, snode, true);
		break;
	case AMT_ACT_STATUS_D_FWD_NEW:
		snode->status = AMT_SOURCE_STATUS_D_FWD;
		snode->flags = AMT_SOURCE_NEW;
		break;
	case AMT_ACT_STATUS_NONE_NEW:
		cancel_delayed_work(&snode->source_timer);
		snode->status = AMT_SOURCE_STATUS_NONE;
		snode->flags = AMT_SOURCE_NEW;
		amt_upstream_track(amt, gnode, snode, false);
		break;
	case AMT_ACT_UPSTREAM_LEAVE:
		/* Emit only the upstream host-stack LEAVE; do not touch
		 * snode->status / snode->flags / source_timer. Caller is
		 * the INCLUDE->EXCLUDE filter_mode transition path, which
		 * must drain the (S, G) refcount BEFORE filter_mode flips
		 * (amt_upstream_track no-ops once mode is EXCLUDE). The
		 * subsequent amt_cleanup_srcs / state-machine ticks own
		 * the snode lifecycle, so leaving status/flags alone here
		 * is correct and required.
		 */
		amt_upstream_track(amt, gnode, snode, false);
		break;
	default:
		WARN_ON_ONCE(1);
		return;
	}

	if (!gnode->v6)
		netdev_dbg(amt->dev, "Source %pI4 from %pI4 Acted %s\n",
			   &snode->source_addr.ip4,
			   &gnode->group_addr.ip4,
			   action_str[act]);
#if IS_ENABLED(CONFIG_IPV6)
	else
		netdev_dbg(amt->dev, "Source %pI6 from %pI6 Acted %s\n",
			   &snode->source_addr.ip6,
			   &gnode->group_addr.ip6,
			   action_str[act]);
#endif
}

static struct amt_source_node *amt_alloc_snode(struct amt_group_node *gnode,
					       union amt_addr *src)
{
	struct amt_source_node *snode;

	snode = kzalloc(sizeof(*snode), GFP_ATOMIC);
	if (!snode)
		return NULL;

	memcpy(&snode->source_addr, src, sizeof(union amt_addr));
	snode->gnode = gnode;
	snode->status = AMT_SOURCE_STATUS_NONE;
	snode->flags = AMT_SOURCE_NEW;
	INIT_HLIST_NODE(&snode->node);
	INIT_DELAYED_WORK(&snode->source_timer, amt_source_work);

	return snode;
}

/* RFC 3810 - 7.2.2.  Definition of Filter Timers
 *
 *  Router Mode          Filter Timer         Actions/Comments
 *  -----------       -----------------       ----------------
 *
 *    INCLUDE             Not Used            All listeners in
 *                                            INCLUDE mode.
 *
 *    EXCLUDE             Timer > 0           At least one listener
 *                                            in EXCLUDE mode.
 *
 *    EXCLUDE             Timer == 0          No more listeners in
 *                                            EXCLUDE mode for the
 *                                            multicast address.
 *                                            If the Requested List
 *                                            is empty, delete
 *                                            Multicast Address
 *                                            Record.  If not, switch
 *                                            to INCLUDE filter mode;
 *                                            the sources in the
 *                                            Requested List are
 *                                            moved to the Include
 *                                            List, and the Exclude
 *                                            List is deleted.
 */
static void amt_group_work(struct work_struct *work)
{
	struct amt_group_node *gnode = container_of(to_delayed_work(work),
						    struct amt_group_node,
						    group_timer);
	struct amt_tunnel_list *tunnel = gnode->tunnel_list;
	struct amt_dev *amt = gnode->amt;
	struct amt_source_node *snode;
	bool delete_group = true;
	struct hlist_node *t;
	int i, buckets;

	buckets = amt->hash_buckets;

	spin_lock_bh(&tunnel->lock);
	if (gnode->filter_mode == MCAST_INCLUDE) {
		/* Not Used */
		spin_unlock_bh(&tunnel->lock);
		goto out;
	}

	rcu_read_lock();
	for (i = 0; i < buckets; i++) {
		hlist_for_each_entry_safe(snode, t,
					  &gnode->sources[i], node) {
			if (!delayed_work_pending(&snode->source_timer) ||
			    snode->status == AMT_SOURCE_STATUS_D_FWD) {
				amt_destroy_source(snode);
			} else {
				delete_group = false;
				snode->status = AMT_SOURCE_STATUS_FWD;
			}
		}
	}
	if (delete_group)
		amt_del_group(amt, gnode);
	else
		gnode->filter_mode = MCAST_INCLUDE;
	rcu_read_unlock();
	spin_unlock_bh(&tunnel->lock);
out:
	dev_put(amt->dev);
}

/* Non-existent group is created as INCLUDE {empty}:
 *
 * RFC 3376 - 5.1. Action on Change of Interface State
 *
 * If no interface state existed for that multicast address before
 * the change (i.e., the change consisted of creating a new
 * per-interface record), or if no state exists after the change
 * (i.e., the change consisted of deleting a per-interface record),
 * then the "non-existent" state is considered to have a filter mode
 * of INCLUDE and an empty source list.
 */
static struct amt_group_node *amt_add_group(struct amt_dev *amt,
					    struct amt_tunnel_list *tunnel,
					    union amt_addr *group,
					    union amt_addr *host,
					    bool v6)
{
	struct amt_group_node *gnode;
	int err;
	int i;

	if (tunnel->nr_groups >= amt->max_groups)
		return ERR_PTR(-ENOSPC);

	/* Reject the join if the per-tunnel rhltable isn't initialised
	 * yet. amt_tunnel_init_work runs in process context within
	 * milliseconds of amt_alloc_tunnel; the gateway will retry the
	 * Update on the next 1-second AMT retransmit. Returning -EAGAIN
	 * (rather than -ENOMEM) makes the failure visible as a transient
	 * condition to the Update parse caller.
	 */
	if (!amt_tunnel_groups_ready(tunnel))
		return ERR_PTR(-EAGAIN);

	gnode = kzalloc(sizeof(*gnode) +
			(sizeof(struct hlist_head) * amt->hash_buckets),
			GFP_ATOMIC);
	if (unlikely(!gnode))
		return ERR_PTR(-ENOMEM);

	gnode->amt = amt;
	gnode->group_addr = *group;
	gnode->host_addr = *host;
	gnode->v6 = v6;
	gnode->tunnel_list = tunnel;
	gnode->filter_mode = MCAST_INCLUDE;
	INIT_DELAYED_WORK(&gnode->group_timer, amt_group_work);
	for (i = 0; i < amt->hash_buckets; i++)
		INIT_HLIST_HEAD(&gnode->sources[i]);

	err = rhltable_insert(&tunnel->groups_rhl, &gnode->rhlnode,
			      amt_gnode_rht_params);
	if (err) {
		kfree(gnode);
		return ERR_PTR(err);
	}
	tunnel->nr_groups++;

	if (!gnode->v6)
		netdev_dbg(amt->dev, "Join group %pI4\n",
			   &gnode->group_addr.ip4);
#if IS_ENABLED(CONFIG_IPV6)
	else
		netdev_dbg(amt->dev, "Join group %pI6\n",
			   &gnode->group_addr.ip6);
#endif

	return gnode;
}

static struct sk_buff *amt_build_igmp_gq(struct amt_dev *amt)
{
	u8 ra[AMT_IPHDR_OPTS] = { IPOPT_RA, 4, 0, 0 };
	int hlen = LL_RESERVED_SPACE(amt->dev);
	int tlen = amt->dev->needed_tailroom;
	struct igmpv3_query *ihv3;
	void *csum_start = NULL;
	__sum16 *csum = NULL;
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct iphdr *iph;
	unsigned int len;
	int offset;

	len = hlen + tlen + sizeof(*iph) + AMT_IPHDR_OPTS + sizeof(*ihv3);
	skb = netdev_alloc_skb_ip_align(amt->dev, len);
	if (!skb)
		return NULL;

	skb_reserve(skb, hlen);
	skb_push(skb, sizeof(*eth));
	skb->protocol = htons(ETH_P_IP);
	skb_reset_mac_header(skb);
	skb->priority = TC_PRIO_CONTROL;
	skb_put(skb, sizeof(*iph));
	skb_put_data(skb, ra, sizeof(ra));
	skb_put(skb, sizeof(*ihv3));
	skb_pull(skb, sizeof(*eth));
	skb_reset_network_header(skb);

	iph		= ip_hdr(skb);
	iph->version	= 4;
	iph->ihl	= (sizeof(struct iphdr) + AMT_IPHDR_OPTS) >> 2;
	iph->tos	= AMT_TOS;
	iph->tot_len	= htons(sizeof(*iph) + AMT_IPHDR_OPTS + sizeof(*ihv3));
	iph->frag_off	= htons(IP_DF);
	iph->ttl	= 1;
	iph->id		= 0;
	iph->protocol	= IPPROTO_IGMP;
	iph->daddr	= htonl(INADDR_ALLHOSTS_GROUP);
	iph->saddr	= htonl(INADDR_ANY);
	ip_send_check(iph);

	eth = eth_hdr(skb);
	ether_addr_copy(eth->h_source, amt->dev->dev_addr);
	ip_eth_mc_map(htonl(INADDR_ALLHOSTS_GROUP), eth->h_dest);
	eth->h_proto = htons(ETH_P_IP);

	ihv3		= skb_pull(skb, sizeof(*iph) + AMT_IPHDR_OPTS);
	skb_reset_transport_header(skb);
	ihv3->type	= IGMP_HOST_MEMBERSHIP_QUERY;
	ihv3->code	= 1;
	ihv3->group	= 0;
	ihv3->qqic	= amt->qi;
	ihv3->nsrcs	= 0;
	ihv3->resv	= 0;
	ihv3->suppress	= false;
	ihv3->qrv	= READ_ONCE(amt->net->ipv4.sysctl_igmp_qrv);
	ihv3->csum	= 0;
	csum		= &ihv3->csum;
	csum_start	= (void *)ihv3;
	*csum		= ip_compute_csum(csum_start, sizeof(*ihv3));
	offset		= skb_transport_offset(skb);
	skb->csum	= skb_checksum(skb, offset, skb->len - offset, 0);
	skb->ip_summed	= CHECKSUM_NONE;

	skb_push(skb, sizeof(*eth) + sizeof(*iph) + AMT_IPHDR_OPTS);

	return skb;
}

static void amt_update_gw_status(struct amt_dev *amt, enum amt_status status,
				 bool validate)
{
	if (validate && amt->status >= status)
		return;
	netdev_dbg(amt->dev, "Update GW status %s -> %s",
		   status_str[amt->status], status_str[status]);
	WRITE_ONCE(amt->status, status);
}

static void __amt_update_relay_status(struct amt_tunnel_list *tunnel,
				      enum amt_status status,
				      bool validate)
{
	if (validate && tunnel->status >= status)
		return;
#if IS_ENABLED(CONFIG_IPV6)
	if (tunnel->v6)
		netdev_dbg(tunnel->amt->dev,
			   "Update Tunnel(IP = %pI6c, PORT = %u) status %s -> %s",
			   &tunnel->addr.ip6, ntohs(tunnel->source_port),
			   status_str[tunnel->status], status_str[status]);
	else
#endif
		netdev_dbg(tunnel->amt->dev,
			   "Update Tunnel(IP = %pI4, PORT = %u) status %s -> %s",
			   &tunnel->addr.ip4, ntohs(tunnel->source_port),
			   status_str[tunnel->status], status_str[status]);
	tunnel->status = status;
}

static void amt_update_relay_status(struct amt_tunnel_list *tunnel,
				    enum amt_status status, bool validate)
{
	spin_lock_bh(&tunnel->lock);
	__amt_update_relay_status(tunnel, status, validate);
	spin_unlock_bh(&tunnel->lock);
}

static void amt_send_discovery(struct amt_dev *amt)
{
	struct amt_header_discovery *amtd;
	int hlen, tlen, offset;
	struct socket *sock;
	struct udphdr *udph;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct rtable *rt;
	struct flowi4 fl4;
	u32 len;
	int err;

	rcu_read_lock();
	sock = rcu_dereference(amt->sock);
	if (!sock)
		goto out;

	if (!netif_running(amt->stream_dev) || !netif_running(amt->dev))
		goto out;

	rt = ip_route_output_ports(amt->net, &fl4, sock->sk,
				   amt->discovery_ip, amt->local_ip,
				   amt->gw_port, amt->relay_port,
				   IPPROTO_UDP, 0,
				   amt->stream_dev->ifindex);
	if (IS_ERR(rt)) {
		amt->dev->stats.tx_errors++;
		goto out;
	}

	hlen = LL_RESERVED_SPACE(amt->dev);
	tlen = amt->dev->needed_tailroom;
	len = hlen + tlen + sizeof(*iph) + sizeof(*udph) + sizeof(*amtd);
	skb = netdev_alloc_skb_ip_align(amt->dev, len);
	if (!skb) {
		ip_rt_put(rt);
		amt->dev->stats.tx_errors++;
		goto out;
	}

	skb->priority = TC_PRIO_CONTROL;
	skb_dst_set(skb, &rt->dst);

	len = sizeof(*iph) + sizeof(*udph) + sizeof(*amtd);
	skb_reset_network_header(skb);
	skb_put(skb, len);
	amtd = skb_pull(skb, sizeof(*iph) + sizeof(*udph));
	amtd->version	= 0;
	amtd->type	= AMT_MSG_DISCOVERY;
	amtd->reserved	= 0;
	amtd->nonce	= amt->nonce;
	skb_push(skb, sizeof(*udph));
	skb_reset_transport_header(skb);
	udph		= udp_hdr(skb);
	udph->source	= amt->gw_port;
	udph->dest	= amt->relay_port;
	udph->len	= htons(sizeof(*udph) + sizeof(*amtd));
	udph->check	= 0;
	offset = skb_transport_offset(skb);
	skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);
	udph->check = csum_tcpudp_magic(amt->local_ip, amt->discovery_ip,
					sizeof(*udph) + sizeof(*amtd),
					IPPROTO_UDP, skb->csum);

	skb_push(skb, sizeof(*iph));
	iph		= ip_hdr(skb);
	iph->version	= 4;
	iph->ihl	= (sizeof(struct iphdr)) >> 2;
	iph->tos	= AMT_TOS;
	iph->frag_off	= 0;
	iph->ttl	= ip4_dst_hoplimit(&rt->dst);
	iph->daddr	= amt->discovery_ip;
	iph->saddr	= amt->local_ip;
	iph->protocol	= IPPROTO_UDP;
	iph->tot_len	= htons(len);

	skb->ip_summed = CHECKSUM_NONE;
	ip_select_ident(amt->net, skb, NULL);
	ip_send_check(iph);
	err = ip_local_out(amt->net, sock->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		amt->dev->stats.tx_errors++;

	amt_update_gw_status(amt, AMT_STATUS_SENT_DISCOVERY, true);
out:
	rcu_read_unlock();
}

static void amt_send_request(struct amt_dev *amt, bool v6)
{
	struct amt_header_request *amtrh;
	int hlen, tlen, offset;
	struct socket *sock;
	struct udphdr *udph;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct rtable *rt;
	struct flowi4 fl4;
	u32 len;
	int err;

	rcu_read_lock();
	sock = rcu_dereference(amt->sock);
	if (!sock)
		goto out;

	if (!netif_running(amt->stream_dev) || !netif_running(amt->dev))
		goto out;

	rt = ip_route_output_ports(amt->net, &fl4, sock->sk,
				   amt->remote_ip, amt->local_ip,
				   amt->gw_port, amt->relay_port,
				   IPPROTO_UDP, 0,
				   amt->stream_dev->ifindex);
	if (IS_ERR(rt)) {
		amt->dev->stats.tx_errors++;
		goto out;
	}

	hlen = LL_RESERVED_SPACE(amt->dev);
	tlen = amt->dev->needed_tailroom;
	len = hlen + tlen + sizeof(*iph) + sizeof(*udph) + sizeof(*amtrh);
	skb = netdev_alloc_skb_ip_align(amt->dev, len);
	if (!skb) {
		ip_rt_put(rt);
		amt->dev->stats.tx_errors++;
		goto out;
	}

	skb->priority = TC_PRIO_CONTROL;
	skb_dst_set(skb, &rt->dst);

	len = sizeof(*iph) + sizeof(*udph) + sizeof(*amtrh);
	skb_reset_network_header(skb);
	skb_put(skb, len);
	amtrh = skb_pull(skb, sizeof(*iph) + sizeof(*udph));
	amtrh->version	 = 0;
	amtrh->type	 = AMT_MSG_REQUEST;
	amtrh->reserved1 = 0;
	amtrh->p	 = v6;
	amtrh->reserved2 = 0;
	amtrh->nonce	 = amt->nonce;
	skb_push(skb, sizeof(*udph));
	skb_reset_transport_header(skb);
	udph		= udp_hdr(skb);
	udph->source	= amt->gw_port;
	udph->dest	= amt->relay_port;
	udph->len	= htons(sizeof(*amtrh) + sizeof(*udph));
	udph->check	= 0;
	offset = skb_transport_offset(skb);
	skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);
	udph->check = csum_tcpudp_magic(amt->local_ip, amt->remote_ip,
					sizeof(*udph) + sizeof(*amtrh),
					IPPROTO_UDP, skb->csum);

	skb_push(skb, sizeof(*iph));
	iph		= ip_hdr(skb);
	iph->version	= 4;
	iph->ihl	= (sizeof(struct iphdr)) >> 2;
	iph->tos	= AMT_TOS;
	iph->frag_off	= 0;
	iph->ttl	= ip4_dst_hoplimit(&rt->dst);
	iph->daddr	= amt->remote_ip;
	iph->saddr	= amt->local_ip;
	iph->protocol	= IPPROTO_UDP;
	iph->tot_len	= htons(len);

	skb->ip_summed = CHECKSUM_NONE;
	ip_select_ident(amt->net, skb, NULL);
	ip_send_check(iph);
	err = ip_local_out(amt->net, sock->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		amt->dev->stats.tx_errors++;

out:
	rcu_read_unlock();
}

static void amt_send_igmp_gq(struct amt_dev *amt,
			     struct amt_tunnel_list *tunnel)
{
	struct sk_buff *skb;

	skb = amt_build_igmp_gq(amt);
	if (!skb)
		return;

	amt_skb_cb(skb)->tunnel = tunnel;
	dev_queue_xmit(skb);
}

#if IS_ENABLED(CONFIG_IPV6)
static struct sk_buff *amt_build_mld_gq(struct amt_dev *amt)
{
	u8 ra[AMT_IP6HDR_OPTS] = { IPPROTO_ICMPV6, 0, IPV6_TLV_ROUTERALERT,
				   2, 0, 0, IPV6_TLV_PAD1, IPV6_TLV_PAD1 };
	int hlen = LL_RESERVED_SPACE(amt->dev);
	int tlen = amt->dev->needed_tailroom;
	struct mld2_query *mld2q;
	void *csum_start = NULL;
	struct ipv6hdr *ip6h;
	struct sk_buff *skb;
	struct ethhdr *eth;
	u32 len;

	len = hlen + tlen + sizeof(*ip6h) + sizeof(ra) + sizeof(*mld2q);
	skb = netdev_alloc_skb_ip_align(amt->dev, len);
	if (!skb)
		return NULL;

	skb_reserve(skb, hlen);
	skb_push(skb, sizeof(*eth));
	skb_reset_mac_header(skb);
	eth = eth_hdr(skb);
	skb->priority = TC_PRIO_CONTROL;
	skb->protocol = htons(ETH_P_IPV6);
	skb_put_zero(skb, sizeof(*ip6h));
	skb_put_data(skb, ra, sizeof(ra));
	skb_put_zero(skb, sizeof(*mld2q));
	skb_pull(skb, sizeof(*eth));
	skb_reset_network_header(skb);
	ip6h			= ipv6_hdr(skb);
	ip6h->payload_len	= htons(sizeof(ra) + sizeof(*mld2q));
	ip6h->nexthdr		= NEXTHDR_HOP;
	ip6h->hop_limit		= 1;
	ip6h->daddr		= mld2_all_node;
	ip6_flow_hdr(ip6h, 0, 0);

	if (ipv6_dev_get_saddr(amt->net, amt->dev, &ip6h->daddr, 0,
			       &ip6h->saddr)) {
		amt->dev->stats.tx_errors++;
		kfree_skb(skb);
		return NULL;
	}

	eth->h_proto = htons(ETH_P_IPV6);
	ether_addr_copy(eth->h_source, amt->dev->dev_addr);
	ipv6_eth_mc_map(&mld2_all_node, eth->h_dest);

	skb_pull(skb, sizeof(*ip6h) + sizeof(ra));
	skb_reset_transport_header(skb);
	mld2q			= (struct mld2_query *)icmp6_hdr(skb);
	mld2q->mld2q_mrc	= htons(1);
	mld2q->mld2q_type	= ICMPV6_MGM_QUERY;
	mld2q->mld2q_code	= 0;
	mld2q->mld2q_cksum	= 0;
	mld2q->mld2q_resv1	= 0;
	mld2q->mld2q_resv2	= 0;
	mld2q->mld2q_suppress	= 0;
	mld2q->mld2q_qrv	= amt->qrv;
	mld2q->mld2q_nsrcs	= 0;
	mld2q->mld2q_qqic	= amt->qi;
	csum_start		= (void *)mld2q;
	mld2q->mld2q_cksum = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
					     sizeof(*mld2q),
					     IPPROTO_ICMPV6,
					     csum_partial(csum_start,
							  sizeof(*mld2q), 0));

	skb->ip_summed = CHECKSUM_NONE;
	skb_push(skb, sizeof(*eth) + sizeof(*ip6h) + sizeof(ra));
	return skb;
}

static void amt_send_mld_gq(struct amt_dev *amt, struct amt_tunnel_list *tunnel)
{
	struct sk_buff *skb;

	skb = amt_build_mld_gq(amt);
	if (!skb)
		return;

	amt_skb_cb(skb)->tunnel = tunnel;
	dev_queue_xmit(skb);
}
#else
static void amt_send_mld_gq(struct amt_dev *amt, struct amt_tunnel_list *tunnel)
{
}
#endif

static bool amt_queue_event(struct amt_dev *amt, enum amt_event event,
			    struct sk_buff *skb)
{
	int index;

	spin_lock_bh(&amt->lock);
	if (amt->nr_events >= AMT_MAX_EVENTS) {
		spin_unlock_bh(&amt->lock);
		return 1;
	}

	index = (amt->event_idx + amt->nr_events) % AMT_MAX_EVENTS;
	amt->events[index].event = event;
	amt->events[index].skb = skb;
	amt->nr_events++;
	amt->event_idx %= AMT_MAX_EVENTS;
	queue_work(amt_wq, &amt->event_wq);
	spin_unlock_bh(&amt->lock);

	return 0;
}

static void amt_secret_work(struct work_struct *work)
{
	struct amt_dev *amt = container_of(to_delayed_work(work),
					   struct amt_dev,
					   secret_wq);

	spin_lock_bh(&amt->lock);
	get_random_bytes(&amt->key, sizeof(siphash_key_t));
	spin_unlock_bh(&amt->lock);
	mod_delayed_work(amt_wq, &amt->secret_wq,
			 msecs_to_jiffies(AMT_SECRET_TIMEOUT));
}

static void amt_event_send_discovery(struct amt_dev *amt)
{
	if (amt->status > AMT_STATUS_SENT_DISCOVERY)
		goto out;
	get_random_bytes(&amt->nonce, sizeof(__be32));

	amt_send_discovery(amt);
out:
	mod_delayed_work(amt_wq, &amt->discovery_wq,
			 msecs_to_jiffies(AMT_DISCOVERY_TIMEOUT));
}

static void amt_discovery_work(struct work_struct *work)
{
	struct amt_dev *amt = container_of(to_delayed_work(work),
					   struct amt_dev,
					   discovery_wq);

	if (amt_queue_event(amt, AMT_EVENT_SEND_DISCOVERY, NULL))
		mod_delayed_work(amt_wq, &amt->discovery_wq,
				 msecs_to_jiffies(AMT_DISCOVERY_TIMEOUT));
}

static void amt_event_send_request(struct amt_dev *amt)
{
	u32 exp;

	if (amt->status < AMT_STATUS_RECEIVED_ADVERTISEMENT)
		goto out;

	if (amt->req_cnt > AMT_MAX_REQ_COUNT) {
		netdev_dbg(amt->dev, "Gateway is not ready");
		amt->qi = AMT_INIT_REQ_TIMEOUT;
		WRITE_ONCE(amt->ready4, false);
		WRITE_ONCE(amt->ready6, false);
		amt->remote_ip = 0;
		amt_update_gw_status(amt, AMT_STATUS_INIT, false);
		amt->req_cnt = 0;
		amt->nonce = 0;
		goto out;
	}

	if (!amt->req_cnt) {
		WRITE_ONCE(amt->ready4, false);
		WRITE_ONCE(amt->ready6, false);
		get_random_bytes(&amt->nonce, sizeof(__be32));
	}

	amt_send_request(amt, false);
	amt_send_request(amt, true);
	amt_update_gw_status(amt, AMT_STATUS_SENT_REQUEST, true);
	amt->req_cnt++;
out:
	exp = min_t(u32, (1 * (1 << amt->req_cnt)), AMT_MAX_REQ_TIMEOUT);
	mod_delayed_work(amt_wq, &amt->req_wq, msecs_to_jiffies(exp * 1000));
}

static void amt_req_work(struct work_struct *work)
{
	struct amt_dev *amt = container_of(to_delayed_work(work),
					   struct amt_dev,
					   req_wq);

	if (amt_queue_event(amt, AMT_EVENT_SEND_REQUEST, NULL))
		mod_delayed_work(amt_wq, &amt->req_wq,
				 msecs_to_jiffies(100));
}

static bool amt_send_membership_update(struct amt_dev *amt,
				       struct sk_buff *skb,
				       bool v6)
{
	struct amt_header_membership_update *amtmu;
	struct socket *sock;
	struct iphdr *iph;
	struct flowi4 fl4;
	struct rtable *rt;
	int err;

	sock = rcu_dereference_bh(amt->sock);
	if (!sock)
		return true;

	err = skb_cow_head(skb, LL_RESERVED_SPACE(amt->dev) + sizeof(*amtmu) +
			   sizeof(*iph) + sizeof(struct udphdr));
	if (err)
		return true;

	skb_reset_inner_headers(skb);
	memset(&fl4, 0, sizeof(struct flowi4));
	fl4.flowi4_oif         = amt->stream_dev->ifindex;
	fl4.daddr              = amt->remote_ip;
	fl4.saddr              = amt->local_ip;
	fl4.flowi4_dscp         = inet_dsfield_to_dscp(AMT_TOS);
	fl4.flowi4_proto       = IPPROTO_UDP;
	rt = ip_route_output_key(amt->net, &fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(amt->dev, "no route to %pI4\n", &amt->remote_ip);
		return true;
	}

	amtmu			= skb_push(skb, sizeof(*amtmu));
	amtmu->version		= 0;
	amtmu->type		= AMT_MSG_MEMBERSHIP_UPDATE;
	amtmu->reserved		= 0;
	amtmu->nonce		= amt->nonce;
	amtmu->response_mac	= amt->mac;

	if (!v6)
		skb_set_inner_protocol(skb, htons(ETH_P_IP));
	else
		skb_set_inner_protocol(skb, htons(ETH_P_IPV6));
	udp_tunnel_xmit_skb(rt, sock->sk, skb,
			    fl4.saddr,
			    fl4.daddr,
			    AMT_TOS,
			    ip4_dst_hoplimit(&rt->dst),
			    0,
			    amt->gw_port,
			    amt->relay_port,
			    false,
			    false, 0);
	amt_update_gw_status(amt, AMT_STATUS_SENT_UPDATE, true);
	return false;
}

static void amt_send_multicast_data(struct amt_dev *amt,
				    const struct sk_buff *oskb,
				    struct amt_tunnel_list *tunnel,
				    bool v6)
{
	struct amt_header_mcast_data *amtmd;
	struct socket *sock;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct flowi4 fl4;
	struct rtable *rt;

	sock = rcu_dereference_bh(amt->sock);
	if (!sock)
		return;

	skb = skb_copy_expand(oskb, sizeof(*amtmd) + sizeof(*iph) +
			      sizeof(struct udphdr), 0, GFP_ATOMIC);
	if (!skb)
		return;

	skb_reset_inner_headers(skb);
	memset(&fl4, 0, sizeof(struct flowi4));
	fl4.flowi4_oif         = amt->stream_dev->ifindex;
	fl4.daddr              = tunnel->addr.ip4;
	fl4.saddr              = amt->local_ip;
	fl4.flowi4_proto       = IPPROTO_UDP;
	rt = ip_route_output_key(amt->net, &fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(amt->dev, "no route to %pI4\n", &tunnel->addr.ip4);
		kfree_skb(skb);
		return;
	}

	amtmd = skb_push(skb, sizeof(*amtmd));
	amtmd->version = 0;
	amtmd->reserved = 0;
	amtmd->type = AMT_MSG_MULTICAST_DATA;

	if (!v6)
		skb_set_inner_protocol(skb, htons(ETH_P_IP));
	else
		skb_set_inner_protocol(skb, htons(ETH_P_IPV6));
	udp_tunnel_xmit_skb(rt, sock->sk, skb,
			    fl4.saddr,
			    fl4.daddr,
			    AMT_TOS,
			    ip4_dst_hoplimit(&rt->dst),
			    0,
			    amt->relay_port,
			    tunnel->source_port,
			    false,
			    false, 0);
}

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6-outer transport variant of amt_send_multicast_data.
 *
 * Forwards an upstream multicast packet down a v6 tunnel after
 * prepending the 2-byte AMT Multicast Data header. The inner
 * payload is whatever the relay copied from the upstream MRIB —
 * IPv4 or IPv6 multicast is supported via the existing inner_protocol
 * marker (controlled by `v6`). Outer transport is v6, gated on the
 * caller (amt_dev_xmit dispatches on tunnel->v6).
 */
static void amt_send_multicast_data_v6(struct amt_dev *amt,
				       const struct sk_buff *oskb,
				       struct amt_tunnel_list *tunnel,
				       bool v6)
{
	struct amt_header_mcast_data *amtmd;
	struct dst_entry *dst;
	struct socket *sock;
	struct sk_buff *skb;
	struct flowi6 fl6;

	sock = rcu_dereference_bh(amt->sock);
	if (!sock)
		return;

	skb = skb_copy_expand(oskb, sizeof(*amtmd) + sizeof(struct ipv6hdr) +
			      sizeof(struct udphdr), 0, GFP_ATOMIC);
	if (!skb)
		return;

	skb_reset_inner_headers(skb);
	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif		= amt->stream_dev->ifindex;
	fl6.flowi6_proto	= IPPROTO_UDP;
	fl6.daddr		= tunnel->addr.ip6;
	fl6.saddr		= amt->local_ipv6;
	fl6.fl6_dport		= tunnel->source_port;
	fl6.fl6_sport		= amt->relay_port;

	dst = ipv6_stub->ipv6_dst_lookup_flow(amt->net, sock->sk, &fl6, NULL);
	if (IS_ERR(dst)) {
		amt->dev->stats.tx_errors++;
		netdev_dbg(amt->dev, "no route to %pI6c\n", &tunnel->addr.ip6);
		kfree_skb(skb);
		return;
	}

	amtmd		= skb_push(skb, sizeof(*amtmd));
	amtmd->version	= 0;
	amtmd->reserved	= 0;
	amtmd->type	= AMT_MSG_MULTICAST_DATA;

	if (!v6)
		skb_set_inner_protocol(skb, htons(ETH_P_IP));
	else
		skb_set_inner_protocol(skb, htons(ETH_P_IPV6));

	udp_tunnel6_xmit_skb(dst, sock->sk, skb, amt->dev,
			     &amt->local_ipv6, &tunnel->addr.ip6,
			     0,
			     ip6_dst_hoplimit(dst),
			     0,
			     amt->relay_port,
			     tunnel->source_port,
			     false, 0);
}
#endif /* CONFIG_IPV6 */

static bool amt_send_membership_query(struct amt_dev *amt,
				      struct sk_buff *skb,
				      struct amt_tunnel_list *tunnel,
				      bool v6)
{
	struct amt_header_membership_query *amtmq;
	struct socket *sock;
	struct rtable *rt;
	struct flowi4 fl4;
	int err;

	sock = rcu_dereference_bh(amt->sock);
	if (!sock)
		return true;

	err = skb_cow_head(skb, LL_RESERVED_SPACE(amt->dev) + sizeof(*amtmq) +
			   sizeof(struct iphdr) + sizeof(struct udphdr));
	if (err)
		return true;

	skb_reset_inner_headers(skb);
	memset(&fl4, 0, sizeof(struct flowi4));
	fl4.flowi4_oif         = amt->stream_dev->ifindex;
	fl4.daddr              = tunnel->addr.ip4;
	fl4.saddr              = amt->local_ip;
	fl4.flowi4_dscp         = inet_dsfield_to_dscp(AMT_TOS);
	fl4.flowi4_proto       = IPPROTO_UDP;
	rt = ip_route_output_key(amt->net, &fl4);
	if (IS_ERR(rt)) {
		netdev_dbg(amt->dev, "no route to %pI4\n", &tunnel->addr.ip4);
		return true;
	}

	amtmq		= skb_push(skb, sizeof(*amtmq));
	amtmq->version	= 0;
	amtmq->type	= AMT_MSG_MEMBERSHIP_QUERY;
	amtmq->reserved = 0;
	amtmq->l	= 0;
	amtmq->g	= 0;
	amtmq->nonce	= tunnel->nonce;
	amtmq->response_mac = tunnel->mac;

	if (!v6)
		skb_set_inner_protocol(skb, htons(ETH_P_IP));
	else
		skb_set_inner_protocol(skb, htons(ETH_P_IPV6));
	udp_tunnel_xmit_skb(rt, sock->sk, skb,
			    fl4.saddr,
			    fl4.daddr,
			    AMT_TOS,
			    ip4_dst_hoplimit(&rt->dst),
			    0,
			    amt->relay_port,
			    tunnel->source_port,
			    false,
			    false, 0);
	amt_update_relay_status(tunnel, AMT_STATUS_SENT_QUERY, true);
	return false;
}

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6-outer transport variant of amt_send_membership_query.
 *
 * The relay's encap socket is bound to a single family — when the
 * relay was created with IFLA_AMT_LOCAL_IP6 the gateway endpoints
 * tracked in amt->tunnel_list carry tunnel->v6 + tunnel->addr.ip6, and
 * the Membership Query response built by amt_dev_xmit must be
 * tunneled out over the v6 stack rather than v4.
 *
 * The inner-multicast-family bool `v6` is unchanged in meaning
 * (controls skb_set_inner_protocol — ETH_P_IP vs ETH_P_IPV6 for the
 * IGMP-vs-MLD query inside the AMT encap). What changes from the
 * v4 sibling is the outer leg: ipv6_stub for the route lookup,
 * udp_tunnel6_xmit_skb for the actual TX so the UDP checksum is
 * computed correctly over the v6 pseudo-header (RFC 8200 §8.1
 * disallows checksum zero over IPv6).
 */
static bool amt_send_membership_query_v6(struct amt_dev *amt,
					 struct sk_buff *skb,
					 struct amt_tunnel_list *tunnel,
					 bool v6)
{
	struct amt_header_membership_query *amtmq;
	struct dst_entry *dst;
	struct socket *sock;
	struct flowi6 fl6;
	int err;

	sock = rcu_dereference_bh(amt->sock);
	if (!sock) {
		amt->dev->stats.tx_errors++;
		return true;
	}

	err = skb_cow_head(skb, LL_RESERVED_SPACE(amt->dev) + sizeof(*amtmq) +
			   sizeof(struct ipv6hdr) + sizeof(struct udphdr));
	if (err) {
		amt->dev->stats.tx_errors++;
		return true;
	}

	skb_reset_inner_headers(skb);
	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif		= amt->stream_dev->ifindex;
	fl6.flowi6_proto	= IPPROTO_UDP;
	fl6.daddr		= tunnel->addr.ip6;
	fl6.saddr		= amt->local_ipv6;
	fl6.fl6_dport		= tunnel->source_port;
	fl6.fl6_sport		= amt->relay_port;

	dst = ipv6_stub->ipv6_dst_lookup_flow(amt->net, sock->sk, &fl6, NULL);
	if (IS_ERR(dst)) {
		amt->dev->stats.tx_errors++;
		netdev_dbg(amt->dev, "no route to %pI6c\n", &tunnel->addr.ip6);
		return true;
	}

	amtmq		    = skb_push(skb, sizeof(*amtmq));
	amtmq->version	    = 0;
	amtmq->type	    = AMT_MSG_MEMBERSHIP_QUERY;
	amtmq->reserved	    = 0;
	amtmq->l	    = 0;
	amtmq->g	    = 0;
	amtmq->nonce	    = tunnel->nonce;
	amtmq->response_mac = tunnel->mac;

	if (!v6)
		skb_set_inner_protocol(skb, htons(ETH_P_IP));
	else
		skb_set_inner_protocol(skb, htons(ETH_P_IPV6));

	udp_tunnel6_xmit_skb(dst, sock->sk, skb, amt->dev,
			     &amt->local_ipv6, &tunnel->addr.ip6,
			     0,
			     ip6_dst_hoplimit(dst),
			     0,
			     amt->relay_port,
			     tunnel->source_port,
			     false, 0);
	amt_update_relay_status(tunnel, AMT_STATUS_SENT_QUERY, true);
	return false;
}
#endif /* CONFIG_IPV6 */

static netdev_tx_t amt_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct amt_dev *amt = netdev_priv(dev);
	struct amt_tunnel_list *tunnel;
	union amt_addr group = {0,};
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6hdr *ip6h;
	struct mld_msg *mld;
#endif
	bool report = false;
	struct igmphdr *ih;
	bool query = false;
	struct iphdr *iph;
	bool data = false;
	bool v6 = false;

	iph = ip_hdr(skb);
	if (iph->version == 4) {
		if (!ipv4_is_multicast(iph->daddr))
			goto free;

		if (!ip_mc_check_igmp(skb)) {
			ih = igmp_hdr(skb);
			switch (ih->type) {
			case IGMPV3_HOST_MEMBERSHIP_REPORT:
			case IGMP_HOST_MEMBERSHIP_REPORT:
				report = true;
				break;
			case IGMP_HOST_MEMBERSHIP_QUERY:
				query = true;
				break;
			default:
				goto free;
			}
		} else {
			data = true;
		}
		v6 = false;
		group.ip4 = iph->daddr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (iph->version == 6) {
		ip6h = ipv6_hdr(skb);
		if (!ipv6_addr_is_multicast(&ip6h->daddr))
			goto free;

		if (!ipv6_mc_check_mld(skb)) {
			mld = (struct mld_msg *)skb_transport_header(skb);
			switch (mld->mld_type) {
			case ICMPV6_MGM_REPORT:
			case ICMPV6_MLD2_REPORT:
				report = true;
				break;
			case ICMPV6_MGM_QUERY:
				query = true;
				break;
			default:
				goto free;
			}
		} else {
			data = true;
		}
		v6 = true;
		group.ip6 = ip6h->daddr;
#endif
	} else {
		dev->stats.tx_errors++;
		goto free;
	}

	if (!pskb_may_pull(skb, sizeof(struct ethhdr)))
		goto free;

	skb_pull(skb, sizeof(struct ethhdr));

	if (amt->mode == AMT_MODE_GATEWAY) {
		/* Gateway only passes IGMP/MLD packets */
		if (!report)
			goto free;
		if ((!v6 && !READ_ONCE(amt->ready4)) ||
		    (v6 && !READ_ONCE(amt->ready6)))
			goto free;
		if (amt_send_membership_update(amt, skb,  v6))
			goto free;
		goto unlock;
	} else if (amt->mode == AMT_MODE_RELAY) {
		if (query) {
			tunnel = amt_skb_cb(skb)->tunnel;
			if (!tunnel) {
				WARN_ON(1);
				goto free;
			}

			/* Do not forward unexpected query.
			 *
			 * Outer transport family is fixed at tunnel-create
			 * time by the relay's encap-socket family (v4 vs v6);
			 * the inner-multicast `v6` arg is independent and
			 * picks IGMP vs MLD inside the AMT encap.
			 */
#if IS_ENABLED(CONFIG_IPV6)
			if (tunnel->v6) {
				if (amt_send_membership_query_v6(amt, skb,
								 tunnel, v6))
					goto free;
			} else
#endif
			if (amt_send_membership_query(amt, skb, tunnel, v6))
				goto free;
			goto unlock;
		}

		if (!data)
			goto free;
		list_for_each_entry_rcu(tunnel, &amt->tunnel_list, list) {
			struct amt_gnode_key key = { .v6 = v6 };
			struct rhlist_head *rhl;

			if (!amt_tunnel_groups_ready(tunnel))
				continue;

#if IS_ENABLED(CONFIG_IPV6)
			if (v6)
				key.group_addr.ip6 = ip6h->daddr;
			else
#endif
				key.group_addr.ip4 = iph->daddr;

			rhl = rhltable_lookup(&tunnel->groups_rhl, &key,
					      amt_gnode_rht_params);
			if (!rhl)
				continue;

			/* Existence check only. Matches legacy semantics:
			 * pre-rhltable code walked the group bucket and
			 * broke on the first matching gnode via `goto
			 * found`. The new shape is identical -- any gnode
			 * for (group, v6) on this tunnel is sufficient to
			 * forward the encap, and the relay delivers to
			 * whichever inner host(s) are subscribed via the
			 * gateway endpoint. We do NOT iterate the rhl list:
			 * each tunnel encaps exactly once per upstream
			 * packet, and walking the rest of the list would
			 * emit duplicates for multi-host-same-group joins.
			 * The rhltable choice (vs plain rhashtable) is
			 * driven by amt_lookup_group's need for the full
			 * list at the control-plane site, not this fastpath.
			 * Outer-transport family is tunnel-fixed
			 * (tunnel->v6); inner-mcast family `v6` is the
			 * passed-in flag.
			 */
#if IS_ENABLED(CONFIG_IPV6)
			if (tunnel->v6)
				amt_send_multicast_data_v6(amt, skb, tunnel,
							   v6);
			else
#endif
				amt_send_multicast_data(amt, skb, tunnel, v6);
		}
	}

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
free:
	dev_kfree_skb(skb);
unlock:
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static int amt_parse_type(struct sk_buff *skb)
{
	struct amt_header *amth;

	if (!pskb_may_pull(skb, sizeof(struct udphdr) +
			   sizeof(struct amt_header)))
		return -1;

	amth = (struct amt_header *)(udp_hdr(skb) + 1);

	if (amth->version != 0)
		return -1;

	if (amth->type >= __AMT_MSG_MAX || !amth->type)
		return -1;
	return amth->type;
}

static void amt_clear_groups(struct amt_tunnel_list *tunnel)
{
	struct amt_dev *amt = tunnel->amt;
	struct amt_group_node *gnode;
	struct rhashtable_iter iter;

	/* If the rhltable was never initialised (init worker failed or
	 * tunnel destroyed before the worker ran), there are no groups
	 * to clear. amt_tunnel_destroy still has to decide whether to
	 * call rhltable_destroy, which it gates on the same state check.
	 */
	if (!amt_tunnel_groups_ready(tunnel))
		return;

	spin_lock_bh(&tunnel->lock);
	rhltable_walk_enter(&tunnel->groups_rhl, &iter);
	rhashtable_walk_start(&iter);
	while ((gnode = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(gnode)) {
			/* -EAGAIN from rhashtable_walk_next means the table
			 * was rehashed mid-walk; restart from the cursor's
			 * current position. Any other error is fatal.
			 */
			if (PTR_ERR(gnode) == -EAGAIN)
				continue;
			break;
		}
		rcu_read_lock();
		amt_del_group(amt, gnode);
		rcu_read_unlock();
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	spin_unlock_bh(&tunnel->lock);
}

/* Process-context worker that completes per-tunnel rhltable setup.
 * Scheduled from amt_alloc_tunnel (softirq) because rhltable_init
 * calls bucket_table_alloc(GFP_KERNEL) which cannot run from softirq.
 *
 * Until this completes the tunnel exists but its groups_rhl is
 * unusable -- amt_tunnel_groups_ready() returns false, and Update
 * processing drops with -EAGAIN. The window is bounded by amt_wq
 * scheduling latency (microseconds to low milliseconds under normal
 * load) which is well under the 1-second AMT gateway retransmit
 * interval.
 *
 * smp_store_release pairs with the atomic_read_acquire in
 * amt_tunnel_groups_ready: any writes to groups_rhl made by
 * rhltable_init are visible to other CPUs once they observe READY.
 */
static void amt_tunnel_init_work(struct work_struct *work)
{
	struct amt_tunnel_list *tunnel = container_of(work,
						      struct amt_tunnel_list,
						      init_wq);
	int err;

	err = rhltable_init(&tunnel->groups_rhl, &amt_gnode_rht_params);
	if (err) {
		netdev_warn(tunnel->amt->dev,
			    "amt: rhltable_init failed (%d); tunnel will be torn down\n",
			    err);
		atomic_set(&tunnel->init_state, AMT_TUNNEL_INIT_FAILED);
		return;
	}

	/* Release-store so the rhltable's bucket-table writes are
	 * publication-safe to any subsequent acquire-load.
	 */
	atomic_set_release(&tunnel->init_state, AMT_TUNNEL_INIT_READY);
}

/* Teardown helper used by amt_tunnel_expire and amt_stop. Caller
 * must already have removed `tunnel` from amt->tunnel_list and
 * called amt_clear_groups so the rhltable has no remaining entries.
 *
 * cancel_work_sync drains a pending init worker -- it may still be
 * running concurrently or queued and not yet started. Calling it
 * unconditionally is safe (no-op for completed workers).
 *
 * rhltable_destroy is gated on the state being READY; if init
 * never completed (still PENDING or FAILED), the bucket table was
 * never allocated and destroying would crash. Both paths converge
 * on kfree_rcu so the tunnel itself is freed after an RCU grace
 * period -- consistent with the legacy free site that this helper
 * replaces.
 */
static void amt_tunnel_destroy(struct amt_tunnel_list *tunnel)
{
	cancel_work_sync(&tunnel->init_wq);

	if (atomic_read(&tunnel->init_state) == AMT_TUNNEL_INIT_READY)
		rhltable_destroy(&tunnel->groups_rhl);

	kfree_rcu(tunnel, rcu);
}

static void amt_tunnel_expire(struct work_struct *work)
{
	struct amt_tunnel_list *tunnel = container_of(to_delayed_work(work),
						      struct amt_tunnel_list,
						      gc_wq);
	struct amt_dev *amt = tunnel->amt;

	spin_lock_bh(&amt->lock);
	rcu_read_lock();
	list_del_rcu(&tunnel->list);
	amt->nr_tunnels--;
	amt_clear_groups(tunnel);
	rcu_read_unlock();
	spin_unlock_bh(&amt->lock);
	amt_tunnel_destroy(tunnel);
}

static void amt_cleanup_srcs(struct amt_dev *amt,
			     struct amt_tunnel_list *tunnel,
			     struct amt_group_node *gnode)
{
	struct amt_source_node *snode;
	struct hlist_node *t;
	int i;

	/* Delete old sources */
	for (i = 0; i < amt->hash_buckets; i++) {
		hlist_for_each_entry_safe(snode, t, &gnode->sources[i], node) {
			if (snode->flags == AMT_SOURCE_OLD) {
				/* CMT3 audit: state-machine reconciliation
				 * source removal. A source that was FWD/OLD
				 * (not refreshed by the new report) had its
				 * JOIN emitted at FWD_NEW time; emit the
				 * paired LEAVE before freeing.
				 */
				amt_upstream_track(amt, gnode, snode, false);
				amt_destroy_source(snode);
			}
		}
	}

	/* switch from new to old */
	for (i = 0; i < amt->hash_buckets; i++)  {
		hlist_for_each_entry_rcu(snode, &gnode->sources[i], node) {
			snode->flags = AMT_SOURCE_OLD;
			if (!gnode->v6)
				netdev_dbg(snode->gnode->amt->dev,
					   "Add source as OLD %pI4 from %pI4\n",
					   &snode->source_addr.ip4,
					   &gnode->group_addr.ip4);
#if IS_ENABLED(CONFIG_IPV6)
			else
				netdev_dbg(snode->gnode->amt->dev,
					   "Add source as OLD %pI6 from %pI6\n",
					   &snode->source_addr.ip6,
					   &gnode->group_addr.ip6);
#endif
		}
	}
}

static void amt_add_srcs(struct amt_dev *amt, struct amt_tunnel_list *tunnel,
			 struct amt_group_node *gnode, void *grec,
			 bool v6)
{
	struct igmpv3_grec *igmp_grec;
	struct amt_source_node *snode;
#if IS_ENABLED(CONFIG_IPV6)
	struct mld2_grec *mld_grec;
#endif
	union amt_addr src = {0,};
	u16 nsrcs;
	u32 hash;
	int i;

	if (!v6) {
		igmp_grec = grec;
		nsrcs = ntohs(igmp_grec->grec_nsrcs);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		mld_grec = grec;
		nsrcs = ntohs(mld_grec->grec_nsrcs);
#else
	return;
#endif
	}
	for (i = 0; i < nsrcs; i++) {
		if (tunnel->nr_sources >= amt->max_sources)
			return;
		if (!v6)
			src.ip4 = igmp_grec->grec_src[i];
#if IS_ENABLED(CONFIG_IPV6)
		else
			memcpy(&src.ip6, &mld_grec->grec_src[i],
			       sizeof(struct in6_addr));
#endif
		if (amt_lookup_src(tunnel, gnode, AMT_FILTER_ALL, &src))
			continue;

		snode = amt_alloc_snode(gnode, &src);
		if (snode) {
			hash = amt_source_hash(tunnel, &snode->source_addr);
			hlist_add_head_rcu(&snode->node, &gnode->sources[hash]);
			tunnel->nr_sources++;
			gnode->nr_sources++;

			if (!gnode->v6)
				netdev_dbg(snode->gnode->amt->dev,
					   "Add source as NEW %pI4 from %pI4\n",
					   &snode->source_addr.ip4,
					   &gnode->group_addr.ip4);
#if IS_ENABLED(CONFIG_IPV6)
			else
				netdev_dbg(snode->gnode->amt->dev,
					   "Add source as NEW %pI6 from %pI6\n",
					   &snode->source_addr.ip6,
					   &gnode->group_addr.ip6);
#endif
		}
	}
}

/* Router State   Report Rec'd New Router State
 * ------------   ------------ ----------------
 * EXCLUDE (X,Y)  IS_IN (A)    EXCLUDE (X+A,Y-A)
 *
 * -----------+-----------+-----------+
 *            |    OLD    |    NEW    |
 * -----------+-----------+-----------+
 *    FWD     |     X     |    X+A    |
 * -----------+-----------+-----------+
 *    D_FWD   |     Y     |    Y-A    |
 * -----------+-----------+-----------+
 *    NONE    |           |     A     |
 * -----------+-----------+-----------+
 *
 * a) Received sources are NONE/NEW
 * b) All NONE will be deleted by amt_cleanup_srcs().
 * c) All OLD will be deleted by amt_cleanup_srcs().
 * d) After delete, NEW source will be switched to OLD.
 */
static void amt_lookup_act_srcs(struct amt_tunnel_list *tunnel,
				struct amt_group_node *gnode,
				void *grec,
				enum amt_ops ops,
				enum amt_filter filter,
				enum amt_act act,
				bool v6)
{
	struct amt_dev *amt = tunnel->amt;
	struct amt_source_node *snode;
	struct igmpv3_grec *igmp_grec;
#if IS_ENABLED(CONFIG_IPV6)
	struct mld2_grec *mld_grec;
#endif
	union amt_addr src = {0,};
	struct hlist_node *t;
	u16 nsrcs;
	int i, j;

	if (!v6) {
		igmp_grec = grec;
		nsrcs = ntohs(igmp_grec->grec_nsrcs);
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		mld_grec = grec;
		nsrcs = ntohs(mld_grec->grec_nsrcs);
#else
	return;
#endif
	}

	memset(&src, 0, sizeof(union amt_addr));
	switch (ops) {
	case AMT_OPS_INT:
		/* A*B */
		for (i = 0; i < nsrcs; i++) {
			if (!v6)
				src.ip4 = igmp_grec->grec_src[i];
#if IS_ENABLED(CONFIG_IPV6)
			else
				memcpy(&src.ip6, &mld_grec->grec_src[i],
				       sizeof(struct in6_addr));
#endif
			snode = amt_lookup_src(tunnel, gnode, filter, &src);
			if (!snode)
				continue;
			amt_act_src(tunnel, gnode, snode, act);
		}
		break;
	case AMT_OPS_UNI:
		/* A+B */
		for (i = 0; i < amt->hash_buckets; i++) {
			hlist_for_each_entry_safe(snode, t, &gnode->sources[i],
						  node) {
				if (amt_status_filter(snode, filter))
					amt_act_src(tunnel, gnode, snode, act);
			}
		}
		for (i = 0; i < nsrcs; i++) {
			if (!v6)
				src.ip4 = igmp_grec->grec_src[i];
#if IS_ENABLED(CONFIG_IPV6)
			else
				memcpy(&src.ip6, &mld_grec->grec_src[i],
				       sizeof(struct in6_addr));
#endif
			snode = amt_lookup_src(tunnel, gnode, filter, &src);
			if (!snode)
				continue;
			amt_act_src(tunnel, gnode, snode, act);
		}
		break;
	case AMT_OPS_SUB:
		/* A-B */
		for (i = 0; i < amt->hash_buckets; i++) {
			hlist_for_each_entry_safe(snode, t, &gnode->sources[i],
						  node) {
				if (!amt_status_filter(snode, filter))
					continue;
				for (j = 0; j < nsrcs; j++) {
					if (!v6)
						src.ip4 = igmp_grec->grec_src[j];
#if IS_ENABLED(CONFIG_IPV6)
					else
						memcpy(&src.ip6,
						       &mld_grec->grec_src[j],
						       sizeof(struct in6_addr));
#endif
					if (amt_addr_equal(&snode->source_addr,
							   &src))
						goto out_sub;
				}
				amt_act_src(tunnel, gnode, snode, act);
				continue;
out_sub:;
			}
		}
		break;
	case AMT_OPS_SUB_REV:
		/* B-A */
		for (i = 0; i < nsrcs; i++) {
			if (!v6)
				src.ip4 = igmp_grec->grec_src[i];
#if IS_ENABLED(CONFIG_IPV6)
			else
				memcpy(&src.ip6, &mld_grec->grec_src[i],
				       sizeof(struct in6_addr));
#endif
			snode = amt_lookup_src(tunnel, gnode, AMT_FILTER_ALL,
					       &src);
			if (!snode) {
				snode = amt_lookup_src(tunnel, gnode,
						       filter, &src);
				if (snode)
					amt_act_src(tunnel, gnode, snode, act);
			}
		}
		break;
	default:
		netdev_dbg(amt->dev, "Invalid type\n");
		return;
	}
}

static void amt_mcast_is_in_handler(struct amt_dev *amt,
				    struct amt_tunnel_list *tunnel,
				    struct amt_group_node *gnode,
				    void *grec, void *zero_grec, bool v6)
{
	if (gnode->filter_mode == MCAST_INCLUDE) {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * INCLUDE (A)    IS_IN (B)    INCLUDE (A+B)           (B)=GMI
 */
		/* Update IS_IN (B) as FWD/NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_NONE_NEW,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* Update INCLUDE (A) as NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* (B)=GMI */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_FWD_NEW,
				    AMT_ACT_GMI,
				    v6);
	} else {
/* State        Actions
 * ------------   ------------ ----------------        -------
 * EXCLUDE (X,Y)  IS_IN (A)    EXCLUDE (X+A,Y-A)       (A)=GMI
 */
		/* Update (A) in (X, Y) as NONE/NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_BOTH,
				    AMT_ACT_STATUS_NONE_NEW,
				    v6);
		/* Update FWD/OLD as FWD/NEW */
		amt_lookup_act_srcs(tunnel, gnode, zero_grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* Update IS_IN (A) as FWD/NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_NONE_NEW,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* Update EXCLUDE (, Y-A) as D_FWD_NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
	}
}

static void amt_mcast_is_ex_handler(struct amt_dev *amt,
				    struct amt_tunnel_list *tunnel,
				    struct amt_group_node *gnode,
				    void *grec, void *zero_grec, bool v6)
{
	if (gnode->filter_mode == MCAST_INCLUDE) {
/* Router State   Report Rec'd  New Router State         Actions
 * ------------   ------------  ----------------         -------
 * INCLUDE (A)    IS_EX (B)     EXCLUDE (A*B,B-A)        (B-A)=0
 *                                                       Delete (A-B)
 *                                                       Group Timer=GMI
 */
		/* EXCLUDE(A*B, ) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE(, B-A) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
		/* (B-A)=0 */
		amt_lookup_act_srcs(tunnel, gnode, zero_grec, AMT_OPS_UNI,
				    AMT_FILTER_D_FWD_NEW,
				    AMT_ACT_GMI_ZERO,
				    v6);
		/* Group Timer=GMI */
		if (!mod_delayed_work(amt_wq, &gnode->group_timer,
				      msecs_to_jiffies(amt_gmi(amt))))
			dev_hold(amt->dev);
		/* Drain upstream host-stack LEAVEs for A-B BEFORE flipping
		 * filter_mode. amt_upstream_track no-ops once filter_mode
		 * is MCAST_EXCLUDE, so without this drain the subsequent
		 * amt_cleanup_srcs would silently delete A-B snodes while
		 * the (S, G) refcount on the kernel host stack stays held
		 * forever. A-and-B kept their refcount via the FWD_NEW pass
		 * above; B-A is D_FWD_NEW (status==D_FWD, no upstream
		 * impact). Filter AMT_FILTER_FWD picks only FWD-OLD, which
		 * after the prior FWD_NEW pass is exactly A-B.
		 */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB,
				    AMT_FILTER_FWD,
				    AMT_ACT_UPSTREAM_LEAVE,
				    v6);
		gnode->filter_mode = MCAST_EXCLUDE;
		/* Delete (A-B) will be worked by amt_cleanup_srcs(). */
	} else {
/* Router State   Report Rec'd  New Router State	Actions
 * ------------   ------------  ----------------	-------
 * EXCLUDE (X,Y)  IS_EX (A)     EXCLUDE (A-Y,Y*A)	(A-X-Y)=GMI
 *							Delete (X-A)
 *							Delete (Y-A)
 *							Group Timer=GMI
 */
		/* EXCLUDE (A-Y, ) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE (, Y*A ) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
		/* (A-X-Y)=GMI */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_BOTH_NEW,
				    AMT_ACT_GMI,
				    v6);
		/* Group Timer=GMI */
		if (!mod_delayed_work(amt_wq, &gnode->group_timer,
				      msecs_to_jiffies(amt_gmi(amt))))
			dev_hold(amt->dev);
		/* Delete (X-A), (Y-A) will be worked by amt_cleanup_srcs(). */
	}
}

static void amt_mcast_to_in_handler(struct amt_dev *amt,
				    struct amt_tunnel_list *tunnel,
				    struct amt_group_node *gnode,
				    void *grec, void *zero_grec, bool v6)
{
	if (gnode->filter_mode == MCAST_INCLUDE) {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * INCLUDE (A)    TO_IN (B)    INCLUDE (A+B)           (B)=GMI
 *						       Send Q(G,A-B)
 */
		/* Update TO_IN (B) sources as FWD/NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_NONE_NEW,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* Update INCLUDE (A) sources as NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* (B)=GMI */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_FWD_NEW,
				    AMT_ACT_GMI,
				    v6);
	} else {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * EXCLUDE (X,Y)  TO_IN (A)    EXCLUDE (X+A,Y-A)       (A)=GMI
 *						       Send Q(G,X-A)
 *						       Send Q(G)
 */
		/* Update TO_IN (A) sources as FWD/NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_NONE_NEW,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* Update EXCLUDE(X,) sources as FWD/NEW */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE (, Y-A)
		 * (A) are already switched to FWD_NEW.
		 * So, D_FWD/OLD -> D_FWD/NEW is okay.
		 */
		amt_lookup_act_srcs(tunnel, gnode, zero_grec, AMT_OPS_UNI,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
		/* (A)=GMI
		 * Only FWD_NEW will have (A) sources.
		 */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_FWD_NEW,
				    AMT_ACT_GMI,
				    v6);
	}
}

static void amt_mcast_to_ex_handler(struct amt_dev *amt,
				    struct amt_tunnel_list *tunnel,
				    struct amt_group_node *gnode,
				    void *grec, void *zero_grec, bool v6)
{
	if (gnode->filter_mode == MCAST_INCLUDE) {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * INCLUDE (A)    TO_EX (B)    EXCLUDE (A*B,B-A)       (B-A)=0
 *						       Delete (A-B)
 *						       Send Q(G,A*B)
 *						       Group Timer=GMI
 */
		/* EXCLUDE (A*B, ) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE (, B-A) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
		/* (B-A)=0 */
		amt_lookup_act_srcs(tunnel, gnode, zero_grec, AMT_OPS_UNI,
				    AMT_FILTER_D_FWD_NEW,
				    AMT_ACT_GMI_ZERO,
				    v6);
		/* Group Timer=GMI */
		if (!mod_delayed_work(amt_wq, &gnode->group_timer,
				      msecs_to_jiffies(amt_gmi(amt))))
			dev_hold(amt->dev);
		/* Drain upstream host-stack LEAVEs for A-B BEFORE flipping
		 * filter_mode. See amt_mcast_is_ex_handler for the full
		 * rationale: the leak path is identical: amt_cleanup_srcs
		 * would otherwise destroy the A-B snodes after filter_mode
		 * is EXCLUDE, at which point amt_upstream_track no-ops and
		 * the (S, G) refcount on the kernel host stack leaks.
		 */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB,
				    AMT_FILTER_FWD,
				    AMT_ACT_UPSTREAM_LEAVE,
				    v6);
		gnode->filter_mode = MCAST_EXCLUDE;
		/* Delete (A-B) will be worked by amt_cleanup_srcs(). */
	} else {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * EXCLUDE (X,Y)  TO_EX (A)    EXCLUDE (A-Y,Y*A)       (A-X-Y)=Group Timer
 *						       Delete (X-A)
 *						       Delete (Y-A)
 *						       Send Q(G,A-Y)
 *						       Group Timer=GMI
 */
		/* Update (A-X-Y) as NONE/OLD */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_BOTH,
				    AMT_ACT_GT,
				    v6);
		/* EXCLUDE (A-Y, ) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE (, Y*A) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
		/* Group Timer=GMI */
		if (!mod_delayed_work(amt_wq, &gnode->group_timer,
				      msecs_to_jiffies(amt_gmi(amt))))
			dev_hold(amt->dev);
		/* Delete (X-A), (Y-A) will be worked by amt_cleanup_srcs(). */
	}
}

static void amt_mcast_allow_handler(struct amt_dev *amt,
				    struct amt_tunnel_list *tunnel,
				    struct amt_group_node *gnode,
				    void *grec, void *zero_grec, bool v6)
{
	if (gnode->filter_mode == MCAST_INCLUDE) {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * INCLUDE (A)    ALLOW (B)    INCLUDE (A+B)	       (B)=GMI
 */
		/* INCLUDE (A+B) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* (B)=GMI */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_FWD_NEW,
				    AMT_ACT_GMI,
				    v6);
	} else {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * EXCLUDE (X,Y)  ALLOW (A)    EXCLUDE (X+A,Y-A)       (A)=GMI
 */
		/* EXCLUDE (X+A, ) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE (, Y-A) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
		/* (A)=GMI
		 * All (A) source are now FWD/NEW status.
		 */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_INT,
				    AMT_FILTER_FWD_NEW,
				    AMT_ACT_GMI,
				    v6);
	}
}

static void amt_mcast_block_handler(struct amt_dev *amt,
				    struct amt_tunnel_list *tunnel,
				    struct amt_group_node *gnode,
				    void *grec, void *zero_grec, bool v6)
{
	if (gnode->filter_mode == MCAST_INCLUDE) {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * INCLUDE (A)    BLOCK (B)    INCLUDE (A)             Send Q(G,A*B)
 */
		/* INCLUDE (A) */
		amt_lookup_act_srcs(tunnel, gnode, zero_grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
	} else {
/* Router State   Report Rec'd New Router State        Actions
 * ------------   ------------ ----------------        -------
 * EXCLUDE (X,Y)  BLOCK (A)    EXCLUDE (X+(A-Y),Y)     (A-X-Y)=Group Timer
 *						       Send Q(G,A-Y)
 */
		/* (A-X-Y)=Group Timer */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_BOTH,
				    AMT_ACT_GT,
				    v6);
		/* EXCLUDE (X, ) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE (X+(A-Y) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_SUB_REV,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_FWD_NEW,
				    v6);
		/* EXCLUDE (, Y) */
		amt_lookup_act_srcs(tunnel, gnode, grec, AMT_OPS_UNI,
				    AMT_FILTER_D_FWD,
				    AMT_ACT_STATUS_D_FWD_NEW,
				    v6);
	}
}

/* RFC 3376
 * 7.3.2. In the Presence of Older Version Group Members
 *
 * When Group Compatibility Mode is IGMPv2, a router internally
 * translates the following IGMPv2 messages for that group to their
 * IGMPv3 equivalents:
 *
 * IGMPv2 Message                IGMPv3 Equivalent
 * --------------                -----------------
 * Report                        IS_EX( {} )
 * Leave                         TO_IN( {} )
 */
static void amt_igmpv2_report_handler(struct amt_dev *amt, struct sk_buff *skb,
				      struct amt_tunnel_list *tunnel)
{
	struct igmphdr *ih = igmp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct amt_group_node *gnode;
	union amt_addr group, host;

	memset(&group, 0, sizeof(union amt_addr));
	group.ip4 = ih->group;
	memset(&host, 0, sizeof(union amt_addr));
	host.ip4 = iph->saddr;

	gnode = amt_lookup_group(tunnel, &group, &host, false);
	if (!gnode) {
		gnode = amt_add_group(amt, tunnel, &group, &host, false);
		if (!IS_ERR(gnode)) {
			gnode->filter_mode = MCAST_EXCLUDE;
			if (!mod_delayed_work(amt_wq, &gnode->group_timer,
					      msecs_to_jiffies(amt_gmi(amt))))
				dev_hold(amt->dev);
		} else if (PTR_ERR(gnode) == -EAGAIN) {
			/* Tunnel still in INIT_PENDING; the gateway will
			 * retransmit the IGMPv2 report on the next AMT
			 * Membership Update cycle (~1 s). Make the deferral
			 * visible via dynamic_debug for operators tracing
			 * "join not happening" symptoms.
			 */
			net_ratelimited_function(netdev_dbg, amt->dev,
				"IGMPv2 join deferred: amt tunnel init pending\n");
		}
	}
}

/* RFC 3376
 * 7.3.2. In the Presence of Older Version Group Members
 *
 * When Group Compatibility Mode is IGMPv2, a router internally
 * translates the following IGMPv2 messages for that group to their
 * IGMPv3 equivalents:
 *
 * IGMPv2 Message                IGMPv3 Equivalent
 * --------------                -----------------
 * Report                        IS_EX( {} )
 * Leave                         TO_IN( {} )
 */
static void amt_igmpv2_leave_handler(struct amt_dev *amt, struct sk_buff *skb,
				     struct amt_tunnel_list *tunnel)
{
	struct igmphdr *ih = igmp_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct amt_group_node *gnode;
	union amt_addr group, host;

	memset(&group, 0, sizeof(union amt_addr));
	group.ip4 = ih->group;
	memset(&host, 0, sizeof(union amt_addr));
	host.ip4 = iph->saddr;

	gnode = amt_lookup_group(tunnel, &group, &host, false);
	if (gnode)
		amt_del_group(amt, gnode);
}

static void amt_igmpv3_report_handler(struct amt_dev *amt, struct sk_buff *skb,
				      struct amt_tunnel_list *tunnel)
{
	struct igmpv3_report *ihrv3 = igmpv3_report_hdr(skb);
	int len = skb_transport_offset(skb) + sizeof(*ihrv3);
	void *zero_grec = (void *)&igmpv3_zero_grec;
	struct iphdr *iph = ip_hdr(skb);
	struct amt_group_node *gnode;
	union amt_addr group, host;
	struct igmpv3_grec *grec;
	u16 nsrcs;
	int i;

	for (i = 0; i < ntohs(ihrv3->ngrec); i++) {
		len += sizeof(*grec);
		if (!ip_mc_may_pull(skb, len))
			break;

		grec = (void *)(skb->data + len - sizeof(*grec));
		nsrcs = ntohs(grec->grec_nsrcs);

		len += nsrcs * sizeof(__be32);
		if (!ip_mc_may_pull(skb, len))
			break;

		memset(&group, 0, sizeof(union amt_addr));
		group.ip4 = grec->grec_mca;
		memset(&host, 0, sizeof(union amt_addr));
		host.ip4 = iph->saddr;
		gnode = amt_lookup_group(tunnel, &group, &host, false);
		if (!gnode) {
			gnode = amt_add_group(amt, tunnel, &group, &host,
					      false);
			if (IS_ERR(gnode)) {
				if (PTR_ERR(gnode) == -EAGAIN)
					net_ratelimited_function(netdev_dbg,
						amt->dev,
						"IGMPv3 grec join deferred: amt tunnel init pending\n");
				continue;
			}
		}

		amt_add_srcs(amt, tunnel, gnode, grec, false);
		switch (grec->grec_type) {
		case IGMPV3_MODE_IS_INCLUDE:
			amt_mcast_is_in_handler(amt, tunnel, gnode, grec,
						zero_grec, false);
			break;
		case IGMPV3_MODE_IS_EXCLUDE:
			amt_mcast_is_ex_handler(amt, tunnel, gnode, grec,
						zero_grec, false);
			break;
		case IGMPV3_CHANGE_TO_INCLUDE:
			amt_mcast_to_in_handler(amt, tunnel, gnode, grec,
						zero_grec, false);
			break;
		case IGMPV3_CHANGE_TO_EXCLUDE:
			amt_mcast_to_ex_handler(amt, tunnel, gnode, grec,
						zero_grec, false);
			break;
		case IGMPV3_ALLOW_NEW_SOURCES:
			amt_mcast_allow_handler(amt, tunnel, gnode, grec,
						zero_grec, false);
			break;
		case IGMPV3_BLOCK_OLD_SOURCES:
			amt_mcast_block_handler(amt, tunnel, gnode, grec,
						zero_grec, false);
			break;
		default:
			break;
		}
		amt_cleanup_srcs(amt, tunnel, gnode);
	}
}

/* caller held tunnel->lock */
static void amt_igmp_report_handler(struct amt_dev *amt, struct sk_buff *skb,
				    struct amt_tunnel_list *tunnel)
{
	struct igmphdr *ih = igmp_hdr(skb);

	switch (ih->type) {
	case IGMPV3_HOST_MEMBERSHIP_REPORT:
		amt_igmpv3_report_handler(amt, skb, tunnel);
		break;
	case IGMPV2_HOST_MEMBERSHIP_REPORT:
		amt_igmpv2_report_handler(amt, skb, tunnel);
		break;
	case IGMP_HOST_LEAVE_MESSAGE:
		amt_igmpv2_leave_handler(amt, skb, tunnel);
		break;
	default:
		break;
	}
}

#if IS_ENABLED(CONFIG_IPV6)
/* RFC 3810
 * 8.3.2. In the Presence of MLDv1 Multicast Address Listeners
 *
 * When Multicast Address Compatibility Mode is MLDv2, a router acts
 * using the MLDv2 protocol for that multicast address.  When Multicast
 * Address Compatibility Mode is MLDv1, a router internally translates
 * the following MLDv1 messages for that multicast address to their
 * MLDv2 equivalents:
 *
 * MLDv1 Message                 MLDv2 Equivalent
 * --------------                -----------------
 * Report                        IS_EX( {} )
 * Done                          TO_IN( {} )
 */
static void amt_mldv1_report_handler(struct amt_dev *amt, struct sk_buff *skb,
				     struct amt_tunnel_list *tunnel)
{
	struct mld_msg *mld = (struct mld_msg *)icmp6_hdr(skb);
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct amt_group_node *gnode;
	union amt_addr group, host;

	memcpy(&group.ip6, &mld->mld_mca, sizeof(struct in6_addr));
	memcpy(&host.ip6, &ip6h->saddr, sizeof(struct in6_addr));

	gnode = amt_lookup_group(tunnel, &group, &host, true);
	if (!gnode) {
		gnode = amt_add_group(amt, tunnel, &group, &host, true);
		if (!IS_ERR(gnode)) {
			gnode->filter_mode = MCAST_EXCLUDE;
			if (!mod_delayed_work(amt_wq, &gnode->group_timer,
					      msecs_to_jiffies(amt_gmi(amt))))
				dev_hold(amt->dev);
		} else if (PTR_ERR(gnode) == -EAGAIN) {
			net_ratelimited_function(netdev_dbg, amt->dev,
				"MLDv1 join deferred: amt tunnel init pending\n");
		}
	}
}

/* RFC 3810
 * 8.3.2. In the Presence of MLDv1 Multicast Address Listeners
 *
 * When Multicast Address Compatibility Mode is MLDv2, a router acts
 * using the MLDv2 protocol for that multicast address.  When Multicast
 * Address Compatibility Mode is MLDv1, a router internally translates
 * the following MLDv1 messages for that multicast address to their
 * MLDv2 equivalents:
 *
 * MLDv1 Message                 MLDv2 Equivalent
 * --------------                -----------------
 * Report                        IS_EX( {} )
 * Done                          TO_IN( {} )
 */
static void amt_mldv1_leave_handler(struct amt_dev *amt, struct sk_buff *skb,
				    struct amt_tunnel_list *tunnel)
{
	struct mld_msg *mld = (struct mld_msg *)icmp6_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct amt_group_node *gnode;
	union amt_addr group, host;

	memcpy(&group.ip6, &mld->mld_mca, sizeof(struct in6_addr));
	memset(&host, 0, sizeof(union amt_addr));
	host.ip4 = iph->saddr;

	gnode = amt_lookup_group(tunnel, &group, &host, true);
	if (gnode) {
		amt_del_group(amt, gnode);
		return;
	}
}

static void amt_mldv2_report_handler(struct amt_dev *amt, struct sk_buff *skb,
				     struct amt_tunnel_list *tunnel)
{
	struct mld2_report *mld2r = (struct mld2_report *)icmp6_hdr(skb);
	int len = skb_transport_offset(skb) + sizeof(*mld2r);
	void *zero_grec = (void *)&mldv2_zero_grec;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct amt_group_node *gnode;
	union amt_addr group, host;
	struct mld2_grec *grec;
	u16 nsrcs;
	int i;

	for (i = 0; i < ntohs(mld2r->mld2r_ngrec); i++) {
		len += sizeof(*grec);
		if (!ipv6_mc_may_pull(skb, len))
			break;

		grec = (void *)(skb->data + len - sizeof(*grec));
		nsrcs = ntohs(grec->grec_nsrcs);

		len += nsrcs * sizeof(struct in6_addr);
		if (!ipv6_mc_may_pull(skb, len))
			break;

		memset(&group, 0, sizeof(union amt_addr));
		group.ip6 = grec->grec_mca;
		memset(&host, 0, sizeof(union amt_addr));
		host.ip6 = ip6h->saddr;
		gnode = amt_lookup_group(tunnel, &group, &host, true);
		if (!gnode) {
			gnode = amt_add_group(amt, tunnel, &group, &host,
					      ETH_P_IPV6);
			if (IS_ERR(gnode)) {
				if (PTR_ERR(gnode) == -EAGAIN)
					net_ratelimited_function(netdev_dbg,
						amt->dev,
						"MLDv2 grec join deferred: amt tunnel init pending\n");
				continue;
			}
		}

		amt_add_srcs(amt, tunnel, gnode, grec, true);
		switch (grec->grec_type) {
		case MLD2_MODE_IS_INCLUDE:
			amt_mcast_is_in_handler(amt, tunnel, gnode, grec,
						zero_grec, true);
			break;
		case MLD2_MODE_IS_EXCLUDE:
			amt_mcast_is_ex_handler(amt, tunnel, gnode, grec,
						zero_grec, true);
			break;
		case MLD2_CHANGE_TO_INCLUDE:
			amt_mcast_to_in_handler(amt, tunnel, gnode, grec,
						zero_grec, true);
			break;
		case MLD2_CHANGE_TO_EXCLUDE:
			amt_mcast_to_ex_handler(amt, tunnel, gnode, grec,
						zero_grec, true);
			break;
		case MLD2_ALLOW_NEW_SOURCES:
			amt_mcast_allow_handler(amt, tunnel, gnode, grec,
						zero_grec, true);
			break;
		case MLD2_BLOCK_OLD_SOURCES:
			amt_mcast_block_handler(amt, tunnel, gnode, grec,
						zero_grec, true);
			break;
		default:
			break;
		}
		amt_cleanup_srcs(amt, tunnel, gnode);
	}
}

/* caller held tunnel->lock */
static void amt_mld_report_handler(struct amt_dev *amt, struct sk_buff *skb,
				   struct amt_tunnel_list *tunnel)
{
	struct mld_msg *mld = (struct mld_msg *)icmp6_hdr(skb);

	switch (mld->mld_type) {
	case ICMPV6_MGM_REPORT:
		amt_mldv1_report_handler(amt, skb, tunnel);
		break;
	case ICMPV6_MLD2_REPORT:
		amt_mldv2_report_handler(amt, skb, tunnel);
		break;
	case ICMPV6_MGM_REDUCTION:
		amt_mldv1_leave_handler(amt, skb, tunnel);
		break;
	default:
		break;
	}
}
#endif

static bool amt_advertisement_handler(struct amt_dev *amt, struct sk_buff *skb)
{
	struct amt_header_advertisement *amta;
	int hdr_size;

	hdr_size = sizeof(*amta) + sizeof(struct udphdr);
	if (!pskb_may_pull(skb, hdr_size))
		return true;

	amta = (struct amt_header_advertisement *)(udp_hdr(skb) + 1);
	if (!amta->ip4)
		return true;

	if (amta->reserved || amta->version)
		return true;

	if (ipv4_is_loopback(amta->ip4) || ipv4_is_multicast(amta->ip4) ||
	    ipv4_is_zeronet(amta->ip4))
		return true;

	if (amt->status != AMT_STATUS_SENT_DISCOVERY ||
	    amt->nonce != amta->nonce)
		return true;

	amt->remote_ip = amta->ip4;
	netdev_dbg(amt->dev, "advertised remote ip = %pI4\n", &amt->remote_ip);
	mod_delayed_work(amt_wq, &amt->req_wq, 0);

	amt_update_gw_status(amt, AMT_STATUS_RECEIVED_ADVERTISEMENT, true);
	return false;
}

static bool amt_multicast_data_handler(struct amt_dev *amt, struct sk_buff *skb)
{
	struct amt_header_mcast_data *amtmd;
	int hdr_size, len, err;
	struct ethhdr *eth;
	struct iphdr *iph;

	if (READ_ONCE(amt->status) != AMT_STATUS_SENT_UPDATE)
		return true;

	hdr_size = sizeof(*amtmd) + sizeof(struct udphdr);
	if (!pskb_may_pull(skb, hdr_size))
		return true;

	amtmd = (struct amt_header_mcast_data *)(udp_hdr(skb) + 1);
	if (amtmd->reserved || amtmd->version)
		return true;

	if (iptunnel_pull_header(skb, hdr_size, htons(ETH_P_IP), false))
		return true;

	skb_reset_network_header(skb);
	skb_push(skb, sizeof(*eth));
	skb_reset_mac_header(skb);
	skb_pull(skb, sizeof(*eth));
	eth = eth_hdr(skb);

	if (!pskb_may_pull(skb, sizeof(*iph)))
		return true;
	iph = ip_hdr(skb);

	if (iph->version == 4) {
		if (!ipv4_is_multicast(iph->daddr))
			return true;
		skb->protocol = htons(ETH_P_IP);
		eth->h_proto = htons(ETH_P_IP);
		ip_eth_mc_map(iph->daddr, eth->h_dest);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (iph->version == 6) {
		struct ipv6hdr *ip6h;

		if (!pskb_may_pull(skb, sizeof(*ip6h)))
			return true;

		ip6h = ipv6_hdr(skb);
		if (!ipv6_addr_is_multicast(&ip6h->daddr))
			return true;
		skb->protocol = htons(ETH_P_IPV6);
		eth->h_proto = htons(ETH_P_IPV6);
		ipv6_eth_mc_map(&ip6h->daddr, eth->h_dest);
#endif
	} else {
		return true;
	}

	skb->pkt_type = PACKET_MULTICAST;
	skb->ip_summed = CHECKSUM_NONE;
	len = skb->len;
	err = gro_cells_receive(&amt->gro_cells, skb);
	if (likely(err == NET_RX_SUCCESS))
		dev_sw_netstats_rx_add(amt->dev, len);
	else
		amt->dev->stats.rx_dropped++;

	return false;
}

static bool amt_membership_query_handler(struct amt_dev *amt,
					 struct sk_buff *skb)
{
	struct amt_header_membership_query *amtmq;
	struct igmpv3_query *ihv3;
	struct ethhdr *eth, *oeth;
	struct iphdr *iph;
	int hdr_size, len;

	hdr_size = sizeof(*amtmq) + sizeof(struct udphdr);
	if (!pskb_may_pull(skb, hdr_size))
		return true;

	amtmq = (struct amt_header_membership_query *)(udp_hdr(skb) + 1);
	if (amtmq->reserved || amtmq->version)
		return true;

	if (amtmq->nonce != amt->nonce)
		return true;

	hdr_size -= sizeof(*eth);
	if (iptunnel_pull_header(skb, hdr_size, htons(ETH_P_TEB), false))
		return true;

	oeth = eth_hdr(skb);
	skb_reset_mac_header(skb);
	skb_pull(skb, sizeof(*eth));
	skb_reset_network_header(skb);
	eth = eth_hdr(skb);
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return true;

	iph = ip_hdr(skb);
	if (iph->version == 4) {
		if (READ_ONCE(amt->ready4))
			return true;

		if (!pskb_may_pull(skb, sizeof(*iph) + AMT_IPHDR_OPTS +
				   sizeof(*ihv3)))
			return true;

		if (!ipv4_is_multicast(iph->daddr))
			return true;

		ihv3 = skb_pull(skb, sizeof(*iph) + AMT_IPHDR_OPTS);
		skb_reset_transport_header(skb);
		skb_push(skb, sizeof(*iph) + AMT_IPHDR_OPTS);
		WRITE_ONCE(amt->ready4, true);
		amt->mac = amtmq->response_mac;
		amt->req_cnt = 0;
		amt->qi = ihv3->qqic;
		skb->protocol = htons(ETH_P_IP);
		eth->h_proto = htons(ETH_P_IP);
		ip_eth_mc_map(iph->daddr, eth->h_dest);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (iph->version == 6) {
		struct mld2_query *mld2q;
		struct ipv6hdr *ip6h;

		if (READ_ONCE(amt->ready6))
			return true;

		if (!pskb_may_pull(skb, sizeof(*ip6h) + AMT_IP6HDR_OPTS +
				   sizeof(*mld2q)))
			return true;

		ip6h = ipv6_hdr(skb);
		if (!ipv6_addr_is_multicast(&ip6h->daddr))
			return true;

		mld2q = skb_pull(skb, sizeof(*ip6h) + AMT_IP6HDR_OPTS);
		skb_reset_transport_header(skb);
		skb_push(skb, sizeof(*ip6h) + AMT_IP6HDR_OPTS);
		WRITE_ONCE(amt->ready6, true);
		amt->mac = amtmq->response_mac;
		amt->req_cnt = 0;
		amt->qi = mld2q->mld2q_qqic;
		skb->protocol = htons(ETH_P_IPV6);
		eth->h_proto = htons(ETH_P_IPV6);
		ipv6_eth_mc_map(&ip6h->daddr, eth->h_dest);
#endif
	} else {
		return true;
	}

	ether_addr_copy(eth->h_source, oeth->h_source);
	skb->pkt_type = PACKET_MULTICAST;
	skb->ip_summed = CHECKSUM_NONE;
	len = skb->len;
	local_bh_disable();
	if (__netif_rx(skb) == NET_RX_SUCCESS) {
		amt_update_gw_status(amt, AMT_STATUS_RECEIVED_QUERY, true);
		dev_sw_netstats_rx_add(amt->dev, len);
	} else {
		amt->dev->stats.rx_dropped++;
	}
	local_bh_enable();

	return false;
}

static bool amt_update_handler(struct amt_dev *amt, struct sk_buff *skb)
{
	struct amt_header_membership_update *amtmu;
	struct amt_tunnel_list *tunnel;
	struct ethhdr *eth;
	struct iphdr *iph;
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6hdr *ip6h = NULL;
#endif
	int len, hdr_size;
	bool is_v6;

	/* The relay's encap socket is family-bound; every tunnel under
	 * amt->tunnel_list shares that family. Snapshot the outer source
	 * before iptunnel_pull_header strips the AMT+UDP encap (the
	 * outer IP header itself stays in skb headroom so the captured
	 * pointers remain valid through the pull).
	 */
	is_v6 = !ipv6_addr_any(&amt->local_ipv6);
#if IS_ENABLED(CONFIG_IPV6)
	if (is_v6)
		ip6h = ipv6_hdr(skb);
	else
#endif
		iph = ip_hdr(skb);

	hdr_size = sizeof(*amtmu) + sizeof(struct udphdr);
	if (!pskb_may_pull(skb, hdr_size))
		return true;

	amtmu = (struct amt_header_membership_update *)(udp_hdr(skb) + 1);
	if (amtmu->reserved || amtmu->version)
		return true;

	if (iptunnel_pull_header(skb, hdr_size, skb->protocol, false))
		return true;

	skb_reset_network_header(skb);

	list_for_each_entry_rcu(tunnel, &amt->tunnel_list, list) {
		if (tunnel->v6 != is_v6)
			continue;
#if IS_ENABLED(CONFIG_IPV6)
		if (is_v6) {
			if (!ipv6_addr_equal(&tunnel->addr.ip6, &ip6h->saddr))
				continue;
		} else
#endif
		if (tunnel->addr.ip4 != iph->saddr)
			continue;

		if ((amtmu->nonce == tunnel->nonce &&
		     amtmu->response_mac == tunnel->mac)) {
			mod_delayed_work(amt_wq, &tunnel->gc_wq,
					 msecs_to_jiffies(amt_gmi(amt)) * 3);
			goto report;
		} else {
			netdev_dbg(amt->dev, "Invalid MAC\n");
			return true;
		}
	}

	return true;

report:
	if (!pskb_may_pull(skb, sizeof(*iph)))
		return true;

	iph = ip_hdr(skb);
	if (iph->version == 4) {
		if (ip_mc_check_igmp(skb)) {
			netdev_dbg(amt->dev, "Invalid IGMP\n");
			return true;
		}

		spin_lock_bh(&tunnel->lock);
		amt_igmp_report_handler(amt, skb, tunnel);
		spin_unlock_bh(&tunnel->lock);

		skb_push(skb, sizeof(struct ethhdr));
		skb_reset_mac_header(skb);
		eth = eth_hdr(skb);
		skb->protocol = htons(ETH_P_IP);
		eth->h_proto = htons(ETH_P_IP);
		ip_eth_mc_map(iph->daddr, eth->h_dest);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (iph->version == 6) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);

		if (ipv6_mc_check_mld(skb)) {
			netdev_dbg(amt->dev, "Invalid MLD\n");
			return true;
		}

		spin_lock_bh(&tunnel->lock);
		amt_mld_report_handler(amt, skb, tunnel);
		spin_unlock_bh(&tunnel->lock);

		skb_push(skb, sizeof(struct ethhdr));
		skb_reset_mac_header(skb);
		eth = eth_hdr(skb);
		skb->protocol = htons(ETH_P_IPV6);
		eth->h_proto = htons(ETH_P_IPV6);
		ipv6_eth_mc_map(&ip6h->daddr, eth->h_dest);
#endif
	} else {
		netdev_dbg(amt->dev, "Unsupported Protocol\n");
		return true;
	}

	skb_pull(skb, sizeof(struct ethhdr));
	skb->pkt_type = PACKET_MULTICAST;
	skb->ip_summed = CHECKSUM_NONE;
	len = skb->len;
	if (__netif_rx(skb) == NET_RX_SUCCESS) {
		amt_update_relay_status(tunnel, AMT_STATUS_RECEIVED_UPDATE,
					true);
		dev_sw_netstats_rx_add(amt->dev, len);
	} else {
		amt->dev->stats.rx_dropped++;
	}

	return false;
}

static void amt_send_advertisement(struct amt_dev *amt, __be32 nonce,
				   __be32 daddr, __be16 dport)
{
	struct amt_header_advertisement *amta;
	int hlen, tlen, offset;
	struct socket *sock;
	struct udphdr *udph;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct rtable *rt;
	struct flowi4 fl4;
	u32 len;
	int err;

	rcu_read_lock();
	sock = rcu_dereference(amt->sock);
	if (!sock)
		goto out;

	if (!netif_running(amt->stream_dev) || !netif_running(amt->dev))
		goto out;

	rt = ip_route_output_ports(amt->net, &fl4, sock->sk,
				   daddr, amt->local_ip,
				   dport, amt->relay_port,
				   IPPROTO_UDP, 0,
				   amt->stream_dev->ifindex);
	if (IS_ERR(rt)) {
		amt->dev->stats.tx_errors++;
		goto out;
	}

	hlen = LL_RESERVED_SPACE(amt->dev);
	tlen = amt->dev->needed_tailroom;
	len = hlen + tlen + sizeof(*iph) + sizeof(*udph) + sizeof(*amta);
	skb = netdev_alloc_skb_ip_align(amt->dev, len);
	if (!skb) {
		ip_rt_put(rt);
		amt->dev->stats.tx_errors++;
		goto out;
	}

	skb->priority = TC_PRIO_CONTROL;
	skb_dst_set(skb, &rt->dst);

	len = sizeof(*iph) + sizeof(*udph) + sizeof(*amta);
	skb_reset_network_header(skb);
	skb_put(skb, len);
	amta = skb_pull(skb, sizeof(*iph) + sizeof(*udph));
	amta->version	= 0;
	amta->type	= AMT_MSG_ADVERTISEMENT;
	amta->reserved	= 0;
	amta->nonce	= nonce;
	amta->ip4	= amt->local_ip;
	skb_push(skb, sizeof(*udph));
	skb_reset_transport_header(skb);
	udph		= udp_hdr(skb);
	udph->source	= amt->relay_port;
	udph->dest	= dport;
	udph->len	= htons(sizeof(*amta) + sizeof(*udph));
	udph->check	= 0;
	offset = skb_transport_offset(skb);
	skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);
	udph->check = csum_tcpudp_magic(amt->local_ip, daddr,
					sizeof(*udph) + sizeof(*amta),
					IPPROTO_UDP, skb->csum);

	skb_push(skb, sizeof(*iph));
	iph		= ip_hdr(skb);
	iph->version	= 4;
	iph->ihl	= (sizeof(struct iphdr)) >> 2;
	iph->tos	= AMT_TOS;
	iph->frag_off	= 0;
	iph->ttl	= ip4_dst_hoplimit(&rt->dst);
	iph->daddr	= daddr;
	iph->saddr	= amt->local_ip;
	iph->protocol	= IPPROTO_UDP;
	iph->tot_len	= htons(len);

	skb->ip_summed = CHECKSUM_NONE;
	ip_select_ident(amt->net, skb, NULL);
	ip_send_check(iph);
	err = ip_local_out(amt->net, sock->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		amt->dev->stats.tx_errors++;

out:
	rcu_read_unlock();
}

#if IS_ENABLED(CONFIG_IPV6)
/* Send the IPv6 form of the Relay Advertisement message to a gateway.
 *
 * Mirrors amt_send_advertisement() — same control-plane semantics, same
 * sk_buff / skb_dst / skb_push layout — but builds the 24-byte v6 wire
 * form (RFC 7450 §5.1.2) and emits over the v6 stack: ipv6_stub for the
 * route lookup (no hard CONFIG_IPV6=y dep), csum_ipv6_magic for the UDP
 * checksum (mandatory over IPv6 per RFC 8200 §8.1), ip6_local_out for
 * transmit.
 */
static void amt_send_advertisement_v6(struct amt_dev *amt, __be32 nonce,
				      const struct in6_addr *daddr,
				      __be16 dport)
{
	struct amt_header_advertisement_v6 *amta;
	int hlen, tlen, offset;
	struct dst_entry *dst;
	struct socket *sock;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	struct sk_buff *skb;
	struct flowi6 fl6;
	u32 len;
	int err;

	rcu_read_lock();
	sock = rcu_dereference(amt->sock);
	if (!sock)
		goto out;

	if (!netif_running(amt->stream_dev) || !netif_running(amt->dev))
		goto out;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_oif		= amt->stream_dev->ifindex;
	fl6.flowi6_proto	= IPPROTO_UDP;
	fl6.daddr		= *daddr;
	fl6.saddr		= amt->local_ipv6;
	fl6.fl6_dport		= dport;
	fl6.fl6_sport		= amt->relay_port;

	dst = ipv6_stub->ipv6_dst_lookup_flow(amt->net, sock->sk, &fl6, NULL);
	if (IS_ERR(dst)) {
		amt->dev->stats.tx_errors++;
		goto out;
	}

	hlen = LL_RESERVED_SPACE(amt->dev);
	tlen = amt->dev->needed_tailroom;
	len  = hlen + tlen + sizeof(*ip6h) + sizeof(*udph) + sizeof(*amta);
	skb  = netdev_alloc_skb_ip_align(amt->dev, len);
	if (!skb) {
		dst_release(dst);
		amt->dev->stats.tx_errors++;
		goto out;
	}

	skb->priority = TC_PRIO_CONTROL;
	skb_dst_set(skb, dst);

	len = sizeof(*ip6h) + sizeof(*udph) + sizeof(*amta);
	skb_reset_network_header(skb);
	skb_put(skb, len);
	amta = skb_pull(skb, sizeof(*ip6h) + sizeof(*udph));
	amta->version	= 0;
	amta->type	= AMT_MSG_ADVERTISEMENT;
	amta->reserved	= 0;
	amta->nonce	= nonce;
	amta->ip6	= amt->local_ipv6;

	skb_push(skb, sizeof(*udph));
	skb_reset_transport_header(skb);
	udph		= udp_hdr(skb);
	udph->source	= amt->relay_port;
	udph->dest	= dport;
	udph->len	= htons(sizeof(*amta) + sizeof(*udph));
	udph->check	= 0;
	offset = skb_transport_offset(skb);
	skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);
	udph->check = csum_ipv6_magic(&amt->local_ipv6, daddr,
				      sizeof(*udph) + sizeof(*amta),
				      IPPROTO_UDP, skb->csum);
	/* RFC 8200 §8.1: a UDP datagram with checksum zero is invalid over
	 * IPv6; if the computed checksum collapsed to zero, transmit the
	 * one's-complement-equivalent 0xFFFF instead.
	 */
	if (udph->check == 0)
		udph->check = CSUM_MANGLED_0;

	skb_push(skb, sizeof(*ip6h));
	skb_reset_network_header(skb);
	ip6h		   = ipv6_hdr(skb);
	ip6_flow_hdr(ip6h, 0, 0);
	ip6h->payload_len  = htons(sizeof(*udph) + sizeof(*amta));
	ip6h->nexthdr	   = IPPROTO_UDP;
	ip6h->hop_limit	   = ip6_dst_hoplimit(skb_dst(skb));
	ip6h->saddr	   = amt->local_ipv6;
	ip6h->daddr	   = *daddr;

	skb->ip_summed = CHECKSUM_NONE;
	err = ip6_local_out(amt->net, sock->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		amt->dev->stats.tx_errors++;

out:
	rcu_read_unlock();
}
#endif /* CONFIG_IPV6 */

static bool amt_discovery_handler(struct amt_dev *amt, struct sk_buff *skb)
{
	struct amt_header_discovery *amtd;
	struct udphdr *udph;

	if (!pskb_may_pull(skb, sizeof(*udph) + sizeof(*amtd)))
		return true;

	udph = udp_hdr(skb);
	amtd = (struct amt_header_discovery *)(udp_hdr(skb) + 1);

	if (amtd->reserved || amtd->version)
		return true;

#if IS_ENABLED(CONFIG_IPV6)
	/* For a v6-mode relay the encap socket is bound AF_INET6 (see
	 * amt_create_sock), so any AMT Discovery delivered up to this
	 * handler arrived over an IPv6 outer header. Per RFC 7450 §5.2 the
	 * Relay Advertisement form is dictated by the same outer IP
	 * version, so dispatch to the v6 builder rather than read iph as
	 * IPv4 (which would type-confuse the v6 header).
	 */
	if (!ipv6_addr_any(&amt->local_ipv6)) {
		const struct ipv6hdr *ip6h = ipv6_hdr(skb);

		amt_send_advertisement_v6(amt, amtd->nonce, &ip6h->saddr,
					  udph->source);
	} else
#endif
	{
		const struct iphdr *iph = ip_hdr(skb);

		amt_send_advertisement(amt, amtd->nonce, iph->saddr,
				       udph->source);
	}

	return false;
}

static bool amt_request_handler(struct amt_dev *amt, struct sk_buff *skb)
{
	struct amt_header_request *amtrh;
	struct amt_tunnel_list *tunnel;
	unsigned long long key;
	struct udphdr *udph;
	struct iphdr *iph;
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6hdr *ip6h = NULL;
#endif
	bool is_v6;
	u64 mac;

	if (!pskb_may_pull(skb, sizeof(*udph) + sizeof(*amtrh)))
		return true;

	udph = udp_hdr(skb);
	amtrh = (struct amt_header_request *)(udp_hdr(skb) + 1);

	if (amtrh->reserved1 || amtrh->reserved2 || amtrh->version)
		return true;

	/* The relay's encap socket is bound to a single family (see
	 * amt_create_sock — AF_INET or AF_INET6 driven by amt->local_ipv6).
	 * Tunnels are therefore created in the family the relay is in.
	 * Snapshot the outer source header up front (mirrors
	 * amt_update_handler) and resolve the gateway endpoint from it.
	 * is_v6 is the single source of truth for the rest of the function.
	 */
	is_v6 = !ipv6_addr_any(&amt->local_ipv6);
#if IS_ENABLED(CONFIG_IPV6)
	if (is_v6)
		ip6h = ipv6_hdr(skb);
	else
#endif
		iph = ip_hdr(skb);

	list_for_each_entry_rcu(tunnel, &amt->tunnel_list, list) {
		if (tunnel->v6 != is_v6)
			continue;
#if IS_ENABLED(CONFIG_IPV6)
		if (is_v6) {
			if (ipv6_addr_equal(&tunnel->addr.ip6, &ip6h->saddr))
				goto send;
			continue;
		}
#endif
		if (tunnel->addr.ip4 == iph->saddr)
			goto send;
	}

	spin_lock_bh(&amt->lock);
	if (amt->nr_tunnels >= amt->max_tunnels) {
		spin_unlock_bh(&amt->lock);
		icmp_ndo_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
		return true;
	}

	tunnel = kzalloc(sizeof(*tunnel), GFP_ATOMIC);
	if (!tunnel) {
		spin_unlock_bh(&amt->lock);
		return true;
	}

	tunnel->source_port = udph->source;
	tunnel->v6	    = is_v6;
#if IS_ENABLED(CONFIG_IPV6)
	if (is_v6)
		tunnel->addr.ip6 = ip6h->saddr;
	else
#endif
		tunnel->addr.ip4 = iph->saddr;

	memcpy(&key, &tunnel->key, sizeof(unsigned long long));
	tunnel->amt = amt;
	spin_lock_init(&tunnel->lock);

	/* Per-tunnel groups_rhl is initialised by amt_tunnel_init_work in
	 * process context (rhltable_init wants GFP_KERNEL). Mark the
	 * tunnel PENDING here; the worker flips to READY once the
	 * bucket table is allocated. Until then amt_tunnel_groups_ready
	 * returns false and all hash-touching paths bail out.
	 *
	 * Scheduled on system_unbound_wq rather than amt_wq because
	 * amt_wq is shared with event dispatch (amt_event_work), the
	 * discovery/request retry workers, source/group/tunnel timers,
	 * and gc. Under churn -- e.g., a burst of joins/leaves
	 * arriving while a tunnel's bucket table is being allocated --
	 * a private slot on amt_wq could be starved by those other
	 * workers and widen the gateway -EAGAIN retry window past the
	 * 1 s AMT retransmit. system_unbound_wq is per-NUMA-node,
	 * concurrent, and uncontended with amt_wq's bookkeeping.
	 */
	atomic_set(&tunnel->init_state, AMT_TUNNEL_INIT_PENDING);
	INIT_WORK(&tunnel->init_wq, amt_tunnel_init_work);
	queue_work(system_unbound_wq, &tunnel->init_wq);

	INIT_DELAYED_WORK(&tunnel->gc_wq, amt_tunnel_expire);

	list_add_tail_rcu(&tunnel->list, &amt->tunnel_list);
	tunnel->key = amt->key;
	__amt_update_relay_status(tunnel, AMT_STATUS_RECEIVED_REQUEST, true);
	amt->nr_tunnels++;
	mod_delayed_work(amt_wq, &tunnel->gc_wq,
			 msecs_to_jiffies(amt_gmi(amt)));
	spin_unlock_bh(&amt->lock);

send:
	/* Update source_port on every Request, not just on tunnel create.
	 *
	 * Tunnel lookup above matches on outer-saddr only, so a gateway that
	 * reconnects from a new ephemeral UDP source port within the tunnel
	 * GMI window (default ~125s) hits the existing tunnel struct. Without
	 * this assignment tunnel->source_port stayed pinned to whatever port
	 * the FIRST Request used, and every subsequent Membership Query went
	 * to that stale port — the gateway listens on its new ephemeral port,
	 * never receives the Query, and the handshake stalls with QueryFailed.
	 *
	 * RFC 7450 doesn't specify what happens when a gateway re-Requests
	 * with a new source port mid-tunnel; the upstream amt module treats
	 * the (outer-saddr) tuple as the tunnel identity but uses the port
	 * from the current Request's UDP header to address the response. The
	 * two were silently desynchronizing on tunnel reuse.
	 */
	tunnel->source_port = udph->source;
	tunnel->nonce = amtrh->nonce;
	/* MAC mixes the gateway-side identity (saddr, source port, nonce)
	 * keyed by tunnel->key. The v4 and v6 paths use different siphash
	 * APIs because the v4 saddr fits in three u32s while the v6 saddr
	 * is 16 bytes:
	 *
	 *   v4: siphash_3u32(ip4, source_port, nonce, key)
	 *   v6: siphash(&{addr, nonce, source_port}, sizeof(buf), key)
	 *
	 * Note the field order in the v6 packed buffer is
	 * {addr, nonce, port} rather than {addr, port, nonce} — the order
	 * is irrelevant to siphash's domain-separation strength so long as
	 * the same packing is used everywhere a tunnel MAC is computed.
	 * tunnel->key is the same input in both branches, so the
	 * gateway-vs-relay binding strength is preserved across families.
	 */
#if IS_ENABLED(CONFIG_IPV6)
	if (is_v6) {
		struct {
			struct in6_addr	addr;
			__be32		nonce;
			__be16		port;
		} __packed buf = {
			.addr  = tunnel->addr.ip6,
			.nonce = tunnel->nonce,
			.port  = tunnel->source_port,
		};
		mac = siphash(&buf, sizeof(buf), &tunnel->key);
	} else
#endif
	{
		mac = siphash_3u32((__force u32)tunnel->addr.ip4,
				   (__force u32)tunnel->source_port,
				   (__force u32)tunnel->nonce,
				   &tunnel->key);
	}
	tunnel->mac = mac >> 16;

	if (!netif_running(amt->dev) || !netif_running(amt->stream_dev))
		return true;

	if (!amtrh->p)
		amt_send_igmp_gq(amt, tunnel);
	else
		amt_send_mld_gq(amt, tunnel);

	return false;
}

static void amt_gw_rcv(struct amt_dev *amt, struct sk_buff *skb)
{
	int type = amt_parse_type(skb);
	int err = 1;

	if (type == -1)
		goto drop;

	if (amt->mode == AMT_MODE_GATEWAY) {
		switch (type) {
		case AMT_MSG_ADVERTISEMENT:
			err = amt_advertisement_handler(amt, skb);
			break;
		case AMT_MSG_MEMBERSHIP_QUERY:
			err = amt_membership_query_handler(amt, skb);
			if (!err)
				return;
			break;
		default:
			netdev_dbg(amt->dev, "Invalid type of Gateway\n");
			break;
		}
	}
drop:
	if (err) {
		amt->dev->stats.rx_dropped++;
		kfree_skb(skb);
	} else {
		consume_skb(skb);
	}
}

static int amt_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct amt_dev *amt;
	struct iphdr *iph;
	int type;
	bool err;

	rcu_read_lock_bh();
	amt = rcu_dereference_sk_user_data(sk);
	if (!amt) {
		err = true;
		kfree_skb(skb);
		goto out;
	}

	skb->dev = amt->dev;
	iph = ip_hdr(skb);
	type = amt_parse_type(skb);
	if (type == -1) {
		err = true;
		goto drop;
	}

	if (amt->mode == AMT_MODE_GATEWAY) {
		switch (type) {
		case AMT_MSG_ADVERTISEMENT:
			if (iph->saddr != amt->discovery_ip) {
				netdev_dbg(amt->dev, "Invalid Relay IP\n");
				err = true;
				goto drop;
			}
			if (amt_queue_event(amt, AMT_EVENT_RECEIVE, skb)) {
				netdev_dbg(amt->dev, "AMT Event queue full\n");
				err = true;
				goto drop;
			}
			goto out;
		case AMT_MSG_MULTICAST_DATA:
			if (iph->saddr != amt->remote_ip) {
				netdev_dbg(amt->dev, "Invalid Relay IP\n");
				err = true;
				goto drop;
			}
			err = amt_multicast_data_handler(amt, skb);
			if (err)
				goto drop;
			else
				goto out;
		case AMT_MSG_MEMBERSHIP_QUERY:
			if (iph->saddr != amt->remote_ip) {
				netdev_dbg(amt->dev, "Invalid Relay IP\n");
				err = true;
				goto drop;
			}
			if (amt_queue_event(amt, AMT_EVENT_RECEIVE, skb)) {
				netdev_dbg(amt->dev, "AMT Event queue full\n");
				err = true;
				goto drop;
			}
			goto out;
		default:
			err = true;
			netdev_dbg(amt->dev, "Invalid type of Gateway\n");
			break;
		}
	} else {
		switch (type) {
		case AMT_MSG_DISCOVERY:
			err = amt_discovery_handler(amt, skb);
			break;
		case AMT_MSG_REQUEST:
			err = amt_request_handler(amt, skb);
			break;
		case AMT_MSG_MEMBERSHIP_UPDATE:
			err = amt_update_handler(amt, skb);
			if (err)
				goto drop;
			else
				goto out;
		default:
			err = true;
			netdev_dbg(amt->dev, "Invalid type of relay\n");
			break;
		}
	}
drop:
	if (err) {
		amt->dev->stats.rx_dropped++;
		kfree_skb(skb);
	} else {
		consume_skb(skb);
	}
out:
	rcu_read_unlock_bh();
	return 0;
}

static void amt_event_work(struct work_struct *work)
{
	struct amt_dev *amt = container_of(work, struct amt_dev, event_wq);
	struct sk_buff *skb;
	u8 event;
	int i;

	for (i = 0; i < AMT_MAX_EVENTS; i++) {
		spin_lock_bh(&amt->lock);
		if (amt->nr_events == 0) {
			spin_unlock_bh(&amt->lock);
			return;
		}
		event = amt->events[amt->event_idx].event;
		skb = amt->events[amt->event_idx].skb;
		amt->events[amt->event_idx].event = AMT_EVENT_NONE;
		amt->events[amt->event_idx].skb = NULL;
		amt->nr_events--;
		amt->event_idx++;
		amt->event_idx %= AMT_MAX_EVENTS;
		spin_unlock_bh(&amt->lock);

		switch (event) {
		case AMT_EVENT_RECEIVE:
			amt_gw_rcv(amt, skb);
			break;
		case AMT_EVENT_SEND_DISCOVERY:
			amt_event_send_discovery(amt);
			break;
		case AMT_EVENT_SEND_REQUEST:
			amt_event_send_request(amt);
			break;
		default:
			kfree_skb(skb);
			break;
		}
	}
}

static int amt_err_lookup(struct sock *sk, struct sk_buff *skb)
{
	struct amt_dev *amt;
	int type;

	rcu_read_lock_bh();
	amt = rcu_dereference_sk_user_data(sk);
	if (!amt)
		goto out;

	if (amt->mode != AMT_MODE_GATEWAY)
		goto drop;

	type = amt_parse_type(skb);
	if (type == -1)
		goto drop;

	netdev_dbg(amt->dev, "Received IGMP Unreachable of %s\n",
		   type_str[type]);
	switch (type) {
	case AMT_MSG_DISCOVERY:
		break;
	case AMT_MSG_REQUEST:
	case AMT_MSG_MEMBERSHIP_UPDATE:
		if (READ_ONCE(amt->status) >= AMT_STATUS_RECEIVED_ADVERTISEMENT)
			mod_delayed_work(amt_wq, &amt->req_wq, 0);
		break;
	default:
		goto drop;
	}
out:
	rcu_read_unlock_bh();
	return 0;
drop:
	rcu_read_unlock_bh();
	amt->dev->stats.rx_dropped++;
	return 0;
}

static struct socket *amt_create_sock(struct net *net, __be16 port, bool is_v6)
{
	struct udp_port_cfg udp_conf;
	struct socket *sock;
	int err;

	memset(&udp_conf, 0, sizeof(udp_conf));
	if (is_v6) {
#if IS_ENABLED(CONFIG_IPV6)
		udp_conf.family = AF_INET6;
		udp_conf.local_ip6 = in6addr_any;
		udp_conf.use_udp6_tx_checksums = true;
		udp_conf.use_udp6_rx_checksums = true;
		/* The v6 amt relay netdev is created in PARALLEL with the v4
		 * one (amtr + amtr6 in the same netns, both on relay_port).
		 * Without V6ONLY=1 the in6addr_any bind dual-stacks onto
		 * 0.0.0.0:relay_port too, which the v4 amt netdev's encap
		 * socket already owns -> EADDRINUSE on netlink RTM_NEWLINK.
		 * Keep the v6 socket strictly v6 so the two coexist.
		 */
		udp_conf.ipv6_v6only = true;
#else
		return ERR_PTR(-EAFNOSUPPORT);
#endif
	} else {
		udp_conf.family = AF_INET;
		udp_conf.local_ip.s_addr = htonl(INADDR_ANY);
	}

	udp_conf.local_udp_port = port;

	err = udp_sock_create(net, &udp_conf, &sock);
	if (err < 0)
		return ERR_PTR(err);

	return sock;
}

static int amt_socket_create(struct amt_dev *amt)
{
	struct udp_tunnel_sock_cfg tunnel_cfg;
	struct socket *sock;

	sock = amt_create_sock(amt->net, amt->relay_port,
			       !ipv6_addr_any(&amt->local_ipv6));
	if (IS_ERR(sock))
		return PTR_ERR(sock);

	/* Mark socket as an encapsulation socket */
	memset(&tunnel_cfg, 0, sizeof(tunnel_cfg));
	tunnel_cfg.sk_user_data = amt;
	tunnel_cfg.encap_type = 1;
	tunnel_cfg.encap_rcv = amt_rcv;
	tunnel_cfg.encap_err_lookup = amt_err_lookup;
	tunnel_cfg.encap_destroy = NULL;
	setup_udp_tunnel_sock(amt->net, sock, &tunnel_cfg);

	rcu_assign_pointer(amt->sock, sock);
	return 0;
}

/* Defined further down (next to amt_dev_init). Forward-declared here so
 * amt_dev_open and amt_dev_stop can wire them without reordering the file.
 */
static void amt_upstream_setup_open(struct amt_dev *amt);
static void amt_upstream_teardown_stop(struct amt_dev *amt);

static int amt_dev_open(struct net_device *dev)
{
	struct amt_dev *amt = netdev_priv(dev);
	int err;

	amt->ready4 = false;
	amt->ready6 = false;
	amt->event_idx = 0;
	amt->nr_events = 0;

	err = amt_socket_create(amt);
	if (err)
		return err;

	amt_upstream_setup_open(amt); /* non-fatal */

	amt->req_cnt = 0;
	amt->remote_ip = 0;
	amt->nonce = 0;
	get_random_bytes(&amt->key, sizeof(siphash_key_t));

	amt->status = AMT_STATUS_INIT;
	if (amt->mode == AMT_MODE_GATEWAY) {
		mod_delayed_work(amt_wq, &amt->discovery_wq, 0);
		mod_delayed_work(amt_wq, &amt->req_wq, 0);
	} else if (amt->mode == AMT_MODE_RELAY) {
		mod_delayed_work(amt_wq, &amt->secret_wq,
				 msecs_to_jiffies(AMT_SECRET_TIMEOUT));
	}
	return err;
}

static int amt_dev_stop(struct net_device *dev)
{
	struct amt_dev *amt = netdev_priv(dev);
	struct amt_tunnel_list *tunnel, *tmp;
	struct socket *sock;
	struct sk_buff *skb;
	int i;

	/* Fence the upstream emit path before any other teardown — flips
	 * upstream_active=false (gates track + worker dispatch) and frees
	 * any not-yet-drained pending entries. Sockets and refcount tables
	 * intentionally persist; see amt_upstream_teardown_stop header.
	 */
	amt_upstream_teardown_stop(amt);

	cancel_delayed_work_sync(&amt->req_wq);
	cancel_delayed_work_sync(&amt->discovery_wq);
	cancel_delayed_work_sync(&amt->secret_wq);

	/* shutdown */
	sock = rtnl_dereference(amt->sock);
	RCU_INIT_POINTER(amt->sock, NULL);
	synchronize_net();
	if (sock)
		udp_tunnel_sock_release(sock);

	cancel_work_sync(&amt->event_wq);
	for (i = 0; i < AMT_MAX_EVENTS; i++) {
		skb = amt->events[i].skb;
		kfree_skb(skb);
		amt->events[i].event = AMT_EVENT_NONE;
		amt->events[i].skb = NULL;
	}

	amt->ready4 = false;
	amt->ready6 = false;
	amt->req_cnt = 0;
	amt->remote_ip = 0;

	list_for_each_entry_safe(tunnel, tmp, &amt->tunnel_list, list) {
		list_del_rcu(&tunnel->list);
		amt->nr_tunnels--;
		cancel_delayed_work_sync(&tunnel->gc_wq);
		amt_clear_groups(tunnel);
		amt_tunnel_destroy(tunnel);
	}

	return 0;
}

/* Forward declaration: full definition near upstream_setsockopt_slow_count_show
 * (where its attrs are defined). Wired into amt_type::groups below so the
 * sysfs entries are auto-created at device_add() (inside register_netdevice)
 * and auto-removed at device_del() (inside unregister_netdevice). Explicit
 * sysfs_create_group/sysfs_remove_group are race-prone: priv_destructor runs
 * AFTER device_del has nulled kobj->sd, so sysfs_remove_group there OOPSes
 * dereferencing a NULL parent kernfs_node. Letting device_type::groups own
 * lifetime matches vxlan/geneve and the rest of the netdev tree.
 */
static const struct attribute_group amt_upstream_group;

static const struct attribute_group *amt_groups[] = {
	&amt_upstream_group,
	NULL,
};

static const struct device_type amt_type = {
	.name = "amt",
	.groups = amt_groups,
};

/* Upstream IGMPv3/MLDv2 host-stack membership refcount tables.
 *
 * The relay decap path delivers gateway Membership Updates that need to be
 * mirrored as host-stack joins/leaves on the underlying stream_dev so the
 * kernel's existing IGMP/MLD state machine drives the on-wire IGMPv3/MLDv2
 * reports. Many gateways may join the same (S, G), so we refcount per
 * (group, source) and only emit on the 0->1 and 1->0 transitions; all
 * intermediate ops are pure refcount bumps. v4 and v6 are parallel
 * implementations behind a CONFIG_IPV6 guard.
 *
 * Locking: upstream_lock is taken with spin_lock_bh() because callers may
 * run in softirq (gateway decap) or process context. The lock is dropped
 * before any sleeping work (setsockopt is queued onto upstream_work).
 */
static u32 amt_upstream_hash(__be32 grp, __be32 src)
{
	return jhash_2words((__force u32)grp, (__force u32)src, 0) &
	       (AMT_UPSTREAM_HASH_SIZE - 1);
}

/* Caller holds amt->upstream_lock. */
static struct amt_upstream_entry *
amt_upstream_find(struct amt_dev *amt, __be32 grp, __be32 src)
{
	struct amt_upstream_entry *e;
	u32 h = amt_upstream_hash(grp, src);

	hlist_for_each_entry(e, &amt->upstream[h], node)
		if (e->group == grp && e->source == src)
			return e;
	return NULL;
}

/* Returns true if this op needs to be emitted on the wire (0->1 or 1->0). */
static bool amt_upstream_refcount(struct amt_dev *amt, __be32 grp, __be32 src,
				  enum amt_upstream_op op)
{
	struct amt_upstream_entry *e;
	bool emit = false;

	spin_lock_bh(&amt->upstream_lock);
	e = amt_upstream_find(amt, grp, src);
	if (op == AMT_UPSTREAM_JOIN) {
		if (e) {
			e->refcount++;
		} else {
			e = kzalloc(sizeof(*e), GFP_ATOMIC);
			if (!e)
				goto out;
			e->group = grp;
			e->source = src;
			e->refcount = 1;
			hlist_add_head(&e->node,
				       &amt->upstream[amt_upstream_hash(grp, src)]);
			emit = true;
		}
	} else { /* LEAVE */
		if (!e)
			goto out;
		if (--e->refcount == 0) {
			hlist_del(&e->node);
			kfree(e);
			emit = true;
		}
	}
out:
	spin_unlock_bh(&amt->upstream_lock);
	return emit;
}

/*
 * Create a kernel-only UDP socket in amt->net, bind it to stream_dev by
 * ifindex, and publish it via rcu_assign_pointer to *out. SO_BINDTOIFINDEX
 * (sock_bindtoindex) is preferred over snapshotting an IP because the
 * stream_dev's address may change at runtime; the ifindex is stable for
 * the lifetime of the underlying netdev.
 *
 * The socket is used solely to carry IGMPv3/MLDv2 host-stack memberships
 * via setsockopt(IP_ADD_SOURCE_MEMBERSHIP / MCAST_JOIN_SOURCE_GROUP) — it
 * never sends or receives data directly.
 */
static int amt_upstream_sock_create(struct amt_dev *amt, int family,
				    struct socket __rcu **out)
{
	struct socket *sock;
	int err;

	err = sock_create_kern(amt->net, family, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (err < 0)
		return err;

	err = sock_bindtoindex(sock->sk, amt->stream_dev->ifindex, true);
	if (err < 0) {
		sock_release(sock);
		return err;
	}

	rcu_assign_pointer(*out, sock);
	return 0;
}

/* Bump per-namespace IGMP source-filter limit to fit relay scale. The
 * default igmp_max_msf is 10 (net/ipv4/sysctl_net_ipv4.c), which a relay
 * easily exceeds — every distinct source filtered across all (S, G) joins
 * counts toward this cap. Direct struct write; no /proc write needed.
 *
 * IPv6 note: kernel 6.8 does NOT expose a `mld_max_msf` sysctl. There is
 * no equivalent field on netns_sysctl_ipv6 (verified against
 * include/net/netns/ipv6.h, 6.8.0-117-generic headers). MLDv2 source
 * filter sizing is governed by per-socket allocation paths and the
 * compile-time MLD2_MAX_RECORDS limit, neither of which is tunable from
 * a kernel module. Skipped here intentionally — if a future kernel adds
 * the field, mirror the v4 bump under a build-time guard.
 */
static void amt_upstream_bump_msf_limits(struct amt_dev *amt)
{
	struct net *net = amt->net;
	int prev_v4 = net->ipv4.sysctl_igmp_max_msf;

	if (prev_v4 < 65536) {
		net->ipv4.sysctl_igmp_max_msf = 65536;
		netdev_info(amt->dev,
		    "upstream: raised net.ipv4.igmp_max_msf %d -> 65536 (netns-wide)\n",
		    prev_v4);
	}
}

/*
 * Snapshot the primary IPv4 address of stream_dev. setsockopt(IP_ADD_SOURCE_MEMBERSHIP)
 * uses imr_interface (an IP, not an ifindex) to locate the device, so we
 * walk in_dev->ifa_list under RCU and grab the first one.
 */
static __be32 amt_stream_dev_primary_v4(struct amt_dev *amt)
{
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	__be32 addr = 0;

	if (!amt->stream_dev)
		return 0;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(amt->stream_dev);
	if (in_dev) {
		ifa = rcu_dereference(in_dev->ifa_list);
		if (ifa)
			addr = ifa->ifa_local;
	}
	rcu_read_unlock();
	return addr;
}

/*
 * Emit a single IGMPv3 state-change on stream_dev via the kernel host stack.
 *
 * Lifecycle invariant: sockets persist across stop/start cycles. They are
 * created in amt_dev_open (only if NULL) and released ONLY in
 * amt_dev_destructor (post-rtnl). This is required because sock_release of
 * an IGMP/MLD membership-carrying UDP sock acquires rtnl_lock inside
 * ip_mc_drop_socket (v6.8 net/ipv4/igmp.c) / ipv6_sock_mc_close
 * (net/ipv6/mcast.c); releasing under amt_dev_stop's rtnl would recurse.
 *
 * Race-freedom against destructor teardown comes from Commit 4's ordering:
 * destructor does cancel_work_sync(upstream_worker) BEFORE
 * RCU_INIT_POINTER(stream_sock_v4, NULL); synchronize_net(); sock_release().
 * Once cancel_work_sync returns, no worker is mid-setsockopt; sock_release
 * is then safe.
 *
 * The sock_hold(sock->sk) / sock_put(sock->sk) here is defensive:
 *   - sock_hold bumps sk_refcnt on the inner struct sock, NOT on the outer
 *     struct socket envelope. So it does NOT by itself keep the socket
 *     envelope alive across sock_release.
 *   - It guards against future refactors that might bypass the worker
 *     (e.g. a synchronous emit path) by keeping sk-derived state alive
 *     through the setsockopt call.
 *   - Without the worker-cancel-before-release ordering, the envelope
 *     dereference at sock->ops->setsockopt(sock, ...) post-RCU is unsafe
 *     regardless of refcount.
 */
static int amt_upstream_emit_v4(struct amt_dev *amt, __be32 grp, __be32 src,
				enum amt_upstream_op op)
{
	struct socket *sock;
	struct net_device *sdev = amt->stream_dev;
	struct ip_mreq_source mreqs;
	__be32 ifaddr;
	int optname, rc;

	if (!sdev || !READ_ONCE(amt->upstream_active))
		return -ESHUTDOWN;

	rcu_read_lock();
	sock = rcu_dereference(amt->stream_sock_v4);
	if (sock)
		sock_hold(sock->sk);
	rcu_read_unlock();
	if (!sock)
		return -ENODEV;

	ifaddr = amt_stream_dev_primary_v4(amt);
	if (!ifaddr) {
		sock_put(sock->sk);
		netdev_dbg(amt->dev, "upstream: %s has no IPv4 yet; deferring\n",
			   sdev->name);
		return -EADDRNOTAVAIL;
	}

	mreqs.imr_multiaddr  = grp;
	mreqs.imr_interface  = ifaddr;
	mreqs.imr_sourceaddr = src;
	optname = (op == AMT_UPSTREAM_JOIN) ? IP_ADD_SOURCE_MEMBERSHIP
					    : IP_DROP_SOURCE_MEMBERSHIP;

	{
		ktime_t t0 = ktime_get();
		u64 ns;

		/* Worker-vs-destructor cancel_work_sync ordering keeps this sock
		 * envelope alive (see function header). sock_hold above is sk-level
		 * defense, not envelope-level protection.
		 */
		rc = sock->ops->setsockopt(sock, IPPROTO_IP, optname,
					   KERNEL_SOCKPTR(&mreqs), sizeof(mreqs));
		ns = ktime_to_ns(ktime_sub(ktime_get(), t0));
		if (unlikely(ns > 1000ULL * NSEC_PER_MSEC)) {
			atomic_inc(&amt->upstream_setsockopt_slow_count);
			net_ratelimited_function(netdev_warn, amt->dev,
			    "upstream: v4 setsockopt(%s) took %llu ms, possible rtnl contention\n",
			    optname == IP_ADD_SOURCE_MEMBERSHIP ? "ADD" : "DROP",
			    ns / NSEC_PER_MSEC);
		}
	}
	sock_put(sock->sk);
	return rc;
}

#if IS_ENABLED(CONFIG_IPV6)
/* Same lifecycle invariants as amt_upstream_emit_v4 -- see above. */
static int amt_upstream_emit_v6(struct amt_dev *amt,
				const struct in6_addr *grp,
				const struct in6_addr *src,
				enum amt_upstream_op op)
{
	struct socket *sock;
	struct net_device *sdev = amt->stream_dev;
	struct group_source_req gsr;
	struct sockaddr_in6 *sin6;
	int optname, rc;

	if (!sdev || !READ_ONCE(amt->upstream_active))
		return -ESHUTDOWN;

	rcu_read_lock();
	sock = rcu_dereference(amt->stream_sock_v6);
	if (sock)
		sock_hold(sock->sk);
	rcu_read_unlock();
	if (!sock)
		return -ENODEV;

	memset(&gsr, 0, sizeof(gsr));
	gsr.gsr_interface = sdev->ifindex;

	sin6 = (struct sockaddr_in6 *)&gsr.gsr_group;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = *grp;

	sin6 = (struct sockaddr_in6 *)&gsr.gsr_source;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = *src;

	optname = (op == AMT_UPSTREAM_JOIN) ? MCAST_JOIN_SOURCE_GROUP
					    : MCAST_LEAVE_SOURCE_GROUP;

	{
		ktime_t t0 = ktime_get();
		u64 ns;

		/* Same lifecycle invariants as amt_upstream_emit_v4 -- see above. */
		rc = sock->ops->setsockopt(sock, IPPROTO_IPV6, optname,
					   KERNEL_SOCKPTR(&gsr), sizeof(gsr));
		ns = ktime_to_ns(ktime_sub(ktime_get(), t0));
		if (unlikely(ns > 1000ULL * NSEC_PER_MSEC)) {
			atomic_inc(&amt->upstream_setsockopt_slow_count);
			net_ratelimited_function(netdev_warn, amt->dev,
			    "upstream: v6 setsockopt(%s) took %llu ms, possible rtnl contention\n",
			    optname == MCAST_JOIN_SOURCE_GROUP ? "JOIN" : "LEAVE",
			    ns / NSEC_PER_MSEC);
		}
	}
	sock_put(sock->sk);
	return rc;
}
#endif

#if IS_ENABLED(CONFIG_IPV6)
static u32 amt_upstream_hash_v6(const struct in6_addr *grp,
				const struct in6_addr *src)
{
	u32 h;

	h = jhash(grp->s6_addr32, sizeof(grp->s6_addr32), 0);
	h = jhash(src->s6_addr32, sizeof(src->s6_addr32), h);
	return h & (AMT_UPSTREAM_HASH_SIZE - 1);
}

/* Caller holds amt->upstream_lock. */
static struct amt_upstream_entry_v6 *
amt_upstream_find_v6(struct amt_dev *amt, const struct in6_addr *grp,
		     const struct in6_addr *src)
{
	struct amt_upstream_entry_v6 *e;
	u32 h = amt_upstream_hash_v6(grp, src);

	hlist_for_each_entry(e, &amt->upstream_v6[h], node)
		if (ipv6_addr_equal(&e->group, grp) &&
		    ipv6_addr_equal(&e->source, src))
			return e;
	return NULL;
}

static bool amt_upstream_refcount_v6(struct amt_dev *amt,
				     const struct in6_addr *grp,
				     const struct in6_addr *src,
				     enum amt_upstream_op op)
{
	struct amt_upstream_entry_v6 *e;
	bool emit = false;

	spin_lock_bh(&amt->upstream_lock);
	e = amt_upstream_find_v6(amt, grp, src);
	if (op == AMT_UPSTREAM_JOIN) {
		if (e) {
			e->refcount++;
		} else {
			e = kzalloc(sizeof(*e), GFP_ATOMIC);
			if (!e)
				goto out;
			e->group = *grp;
			e->source = *src;
			e->refcount = 1;
			hlist_add_head(&e->node,
				       &amt->upstream_v6[amt_upstream_hash_v6(grp, src)]);
			emit = true;
		}
	} else { /* LEAVE */
		if (!e)
			goto out;
		if (--e->refcount == 0) {
			hlist_del(&e->node);
			kfree(e);
			emit = true;
		}
	}
out:
	spin_unlock_bh(&amt->upstream_lock);
	return emit;
}
#endif

/* Only caller is amt_upstream_worker; static gives the compiler enough
 * visibility now that INIT_WORK wires the worker in amt_dev_init.
 */
static void
amt_upstream_drain_pending(struct amt_dev *amt, struct list_head *out)
{
	spin_lock_bh(&amt->upstream_pending_lock);
	list_splice_init(&amt->upstream_pending, out);
	spin_unlock_bh(&amt->upstream_pending_lock);
}

/* Registered via INIT_WORK in amt_dev_init; dispatched from amt_upstream_track
 * (softirq path) via queue_work() once at least one (S, G) transition is
 * pending.
 */
static void
amt_upstream_worker(struct work_struct *work)
{
	struct amt_dev *amt = container_of(work, struct amt_dev, upstream_work);
	struct amt_upstream_pending *p, *tmp;
	LIST_HEAD(local);
	bool requeue;

	if (!READ_ONCE(amt->upstream_active))
		return;

	amt_upstream_drain_pending(amt, &local);
	list_for_each_entry_safe(p, tmp, &local, link) {
		int err;

		if (!READ_ONCE(amt->upstream_active)) {
			/* Stop raced with this drain. Treat as emit-failure so
			 * the refcount table stays in sync with the kernel host
			 * stack (which has no record of this emit) -- sockets
			 * and refcount tables persist across stop/start cycles
			 * per CMT4 lifecycle, so dropping the entry without
			 * rollback would desync state for the next bring-up.
			 */
			err = -ESHUTDOWN;
		} else if (p->family == AF_INET) {
			err = amt_upstream_emit_v4(amt, p->group_v4, p->source_v4, p->op);
#if IS_ENABLED(CONFIG_IPV6)
		} else if (p->family == AF_INET6) {
			err = amt_upstream_emit_v6(amt, &p->group_v6, &p->source_v6, p->op);
#endif
		} else {
			WARN_ON_ONCE(1);
			err = -EINVAL;
		}

		if (err) {
			/* A9: roll back refcount so a future gateway join
			 * becomes a 0->1 transition again and retries the emit.
			 * Applies to BOTH the stop-race (ESHUTDOWN) path and
			 * real emit failures -- track() already mutated the
			 * refcount before enqueueing, and the kernel host stack
			 * has no record of this emit, so symmetry requires the
			 * refcount table mirror that absence.
			 */
			if (p->family == AF_INET)
				amt_upstream_refcount(amt, p->group_v4, p->source_v4,
				    p->op == AMT_UPSTREAM_JOIN ? AMT_UPSTREAM_LEAVE
							       : AMT_UPSTREAM_JOIN);
#if IS_ENABLED(CONFIG_IPV6)
			else if (p->family == AF_INET6)
				amt_upstream_refcount_v6(amt, &p->group_v6, &p->source_v6,
				    p->op == AMT_UPSTREAM_JOIN ? AMT_UPSTREAM_LEAVE
							       : AMT_UPSTREAM_JOIN);
#endif
			/* ESHUTDOWN is expected during stop; don't spam the
			 * ratelimited warn log for it.
			 */
			if (err != -ESHUTDOWN)
				net_ratelimited_function(netdev_warn, amt->dev,
				    "upstream emit failed; rolled back refcount (family=%d, err=%d)\n",
				    p->family, err);
		}

		list_del(&p->link);
		kfree(p);
	}

	/* CMT2: drain race window. If softirq enqueued between our drain and
	 * here, queue_work() it called may have returned false (work was still
	 * running). Re-check and self-requeue.
	 */
	spin_lock_bh(&amt->upstream_pending_lock);
	requeue = !list_empty(&amt->upstream_pending);
	spin_unlock_bh(&amt->upstream_pending_lock);
	if (requeue && READ_ONCE(amt->upstream_active))
		queue_work(amt_wq, &amt->upstream_work);
}

/*
 * Called from amt_act_src (softirq). Refcounts (S, G) interest and enqueues
 * an emit op if this is a 0<->1 transition. Family is derived from gnode->v6.
 *
 * Refcount-first ordering: we look up + mutate the refcount table BEFORE
 * allocating the pending entry, so non-transition softirq calls (the common
 * case for 2nd+ gateway joining the same (S, G)) don't pay an allocation cost.
 * On OOM after a transition, we roll back the refcount.
 */
#ifdef AMT_TEST_ENABLED
static atomic_t amt_upstream_test_leave_emits;
static bool amt_upstream_test_suppress_queue;
#endif

static void amt_upstream_track(struct amt_dev *amt, struct amt_group_node *gnode,
			       struct amt_source_node *snode, bool join)
{
	enum amt_upstream_op op = join ? AMT_UPSTREAM_JOIN : AMT_UPSTREAM_LEAVE;
	struct amt_upstream_pending *p;
	bool need_emit;

	if (gnode->filter_mode != MCAST_INCLUDE)
		return;
	if (!READ_ONCE(amt->upstream_active))
		return;

	if (!gnode->v6) {
		__be32 grp = gnode->group_addr.ip4;
		__be32 src = snode->source_addr.ip4;

		need_emit = amt_upstream_refcount(amt, grp, src, op);
		if (!need_emit)
			return;

		p = kzalloc(sizeof(*p), GFP_ATOMIC);
		if (!p) {
			amt_upstream_refcount(amt, grp, src,
			    op == AMT_UPSTREAM_JOIN ? AMT_UPSTREAM_LEAVE
						    : AMT_UPSTREAM_JOIN);
			netdev_dbg(amt->dev, "upstream OOM dropping %s\n",
				   join ? "JOIN" : "LEAVE");
			return;
		}
		p->family = AF_INET;
		p->group_v4 = grp;
		p->source_v4 = src;
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		const struct in6_addr *grp = &gnode->group_addr.ip6;
		const struct in6_addr *src = &snode->source_addr.ip6;

		if (ipv6_addr_any(src))
			return;	/* malformed SSM */

		need_emit = amt_upstream_refcount_v6(amt, grp, src, op);
		if (!need_emit)
			return;

		p = kzalloc(sizeof(*p), GFP_ATOMIC);
		if (!p) {
			amt_upstream_refcount_v6(amt, grp, src,
			    op == AMT_UPSTREAM_JOIN ? AMT_UPSTREAM_LEAVE
						    : AMT_UPSTREAM_JOIN);
			netdev_dbg(amt->dev, "upstream OOM dropping %s\n",
				   join ? "JOIN" : "LEAVE");
			return;
		}
		p->family = AF_INET6;
		p->group_v6 = *grp;
		p->source_v6 = *src;
#endif
	}
	p->op = op;
#ifdef AMT_TEST_ENABLED
	if (!join)
		atomic_inc(&amt_upstream_test_leave_emits);
#endif

	spin_lock_bh(&amt->upstream_pending_lock);
	list_add_tail(&p->link, &amt->upstream_pending);
	spin_unlock_bh(&amt->upstream_pending_lock);
#ifdef AMT_TEST_ENABLED
	if (READ_ONCE(amt_upstream_test_suppress_queue))
		return;
#endif
	queue_work(amt_wq, &amt->upstream_work);
}

/*
 * Bring up the upstream membership plumbing. Called from amt_dev_open under
 * rtnl_lock. Idempotent across down/up cycles: stream_sock_v{4,6} are only
 * (re-)created if NULL. Sockets persist across cycles and are released
 * exclusively in amt_dev_destructor — see header comment on
 * amt_upstream_emit_v4 for the full rationale (sock_release acquires
 * rtnl_lock internally in 6.8 ip_mc_drop_socket / ipv6_sock_mc_close).
 *
 * Non-fatal: a failure to create either socket logs a warn and leaves
 * upstream_active false (or true if the other family came up). The relay
 * data path continues to work; only host-stack joins are skipped on the
 * failed family. This avoids a partial-init failure mode that would force
 * the user to ifdown/ifup just to retry.
 */
static void amt_upstream_setup_open(struct amt_dev *amt)
{
	bool any = false;
	int err;

	amt_upstream_bump_msf_limits(amt);

	if (!rcu_access_pointer(amt->stream_sock_v4)) {
		err = amt_upstream_sock_create(amt, PF_INET, &amt->stream_sock_v4);
		if (err)
			netdev_warn(amt->dev,
				    "upstream: v4 sock create failed (%d)\n", err);
	}
	if (rcu_access_pointer(amt->stream_sock_v4))
		any = true;

#if IS_ENABLED(CONFIG_IPV6)
	if (!rcu_access_pointer(amt->stream_sock_v6)) {
		err = amt_upstream_sock_create(amt, PF_INET6, &amt->stream_sock_v6);
		if (err)
			netdev_warn(amt->dev,
				    "upstream: v6 sock create failed (%d)\n", err);
	}
	if (rcu_access_pointer(amt->stream_sock_v6))
		any = true;
#endif

	if (any)
		WRITE_ONCE(amt->upstream_active, true);
	else
		netdev_warn(amt->dev,
			    "upstream: both v4 and v6 sock create failed; emit disabled\n");
}

/*
 * Called from amt_dev_stop (rtnl held). MUST NOT release stream sockets
 * here — sock_release of an IGMP/MLD-carrying UDP sock acquires rtnl_lock
 * inside ip_mc_drop_socket / ipv6_sock_mc_close (verified v6.8). Releasing
 * here would recursively grab rtnl and hang.
 *
 * Sockets persist across stop/start cycles and are released in
 * amt_dev_destructor (post-rtnl). Refcount tables persist too — they
 * mirror the kernel host stack's per-sock mc_list, which also persists.
 *
 * Worker handling:
 *   - upstream_active=false gates new enqueues (amt_upstream_track) and
 *     dispatch (worker top-of-loop bails).
 *   - Workers mid-setsockopt complete naturally — sock_hold/sock_put
 *     keeps the sk alive.
 *   - cancel_work_sync lives in amt_dev_destructor (post-rtnl), not here.
 */
static void amt_upstream_teardown_stop(struct amt_dev *amt)
{
	struct amt_upstream_pending *p, *tmp;
	LIST_HEAD(local);

	WRITE_ONCE(amt->upstream_active, false);

	amt_upstream_drain_pending(amt, &local);
	list_for_each_entry_safe(p, tmp, &local, link) {
		list_del(&p->link);
		kfree(p);
	}
}

static ssize_t upstream_setsockopt_slow_count_show(struct device *dev,
						   struct device_attribute *attr,
						   char *buf)
{
	struct net_device *netdev = to_net_dev(dev);
	struct amt_dev *amt = netdev_priv(netdev);

	return sysfs_emit(buf, "%u\n",
		atomic_read(&amt->upstream_setsockopt_slow_count));
}
static DEVICE_ATTR_RO(upstream_setsockopt_slow_count);

static struct attribute *amt_upstream_attrs[] = {
	&dev_attr_upstream_setsockopt_slow_count.attr,
	NULL,
};

static const struct attribute_group amt_upstream_group = {
	.name = "upstream",
	.attrs = amt_upstream_attrs,
};

static int amt_dev_init(struct net_device *dev)
{
	struct amt_dev *amt = netdev_priv(dev);
	int err;

	amt->dev = dev;
	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	err = gro_cells_init(&amt->gro_cells, dev);
	if (err) {
		free_percpu(dev->tstats);
		return err;
	}

	{
		int i;

		spin_lock_init(&amt->upstream_lock);
		spin_lock_init(&amt->upstream_pending_lock);
		INIT_LIST_HEAD(&amt->upstream_pending);
		INIT_WORK(&amt->upstream_work, amt_upstream_worker);
		for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++)
			INIT_HLIST_HEAD(&amt->upstream[i]);
#if IS_ENABLED(CONFIG_IPV6)
		for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++)
			INIT_HLIST_HEAD(&amt->upstream_v6[i]);
#endif
		WRITE_ONCE(amt->upstream_active, false);
		atomic_set(&amt->upstream_setsockopt_slow_count, 0);
	}

	return 0;
}

/*
 * Called from netdev_run_todo AFTER rtnl is dropped. This is where we:
 *   1. cancel_work_sync the worker (any in-flight worker emit completes)
 *   2. sock_release the membership-carrying sockets (acquires rtnl
 *      internally inside ip_mc_drop_socket / ipv6_sock_mc_close — safe
 *      here because we're post-rtnl)
 *   3. Free hash table entries
 *
 * Ordering matters: cancel_work_sync FIRST so no worker is mid-setsockopt
 * when we release sockets. Then null + release sockets. Then free tables
 * (worker won't touch them after cancel_work_sync completes).
 */
static void amt_dev_destructor(struct net_device *dev)
{
	struct amt_dev *amt = netdev_priv(dev);
	struct amt_upstream_entry *e;
	struct hlist_node *next;
	struct socket *sock4;
#if IS_ENABLED(CONFIG_IPV6)
	struct socket *sock6;
	struct amt_upstream_entry_v6 *e6;
#endif
	int i;

	/* Note: sysfs cleanup is handled by device_type::groups auto-removal at
	 * device_del() (inside unregister_netdevice). Do NOT call
	 * sysfs_remove_group(&dev->dev.kobj, ...) here — by the time
	 * priv_destructor runs in netdev_run_todo, kobj->sd is already NULL and
	 * the kernfs lookup OOPSes. See amt_type::groups wiring.
	 */
	cancel_work_sync(&amt->upstream_work);

	/* Defensive: drain any pending entries. Normally teardown_stop drained
	 * them before the destructor runs, but a never-opened or failed-open
	 * path could leave entries.
	 */
	{
		struct amt_upstream_pending *p, *tmp;
		LIST_HEAD(local);

		amt_upstream_drain_pending(amt, &local);
		list_for_each_entry_safe(p, tmp, &local, link) {
			list_del(&p->link);
			kfree(p);
		}
	}

	sock4 = rcu_dereference_protected(amt->stream_sock_v4, 1);
	RCU_INIT_POINTER(amt->stream_sock_v4, NULL);
#if IS_ENABLED(CONFIG_IPV6)
	sock6 = rcu_dereference_protected(amt->stream_sock_v6, 1);
	RCU_INIT_POINTER(amt->stream_sock_v6, NULL);
#endif
	if (sock4)
		sock_release(sock4);
#if IS_ENABLED(CONFIG_IPV6)
	if (sock6)
		sock_release(sock6);
#endif

	spin_lock_bh(&amt->upstream_lock);
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(e, next, &amt->upstream[i], node) {
			hlist_del(&e->node);
			kfree(e);
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(e6, next, &amt->upstream_v6[i], node) {
			hlist_del(&e6->node);
			kfree(e6);
		}
	}
#endif
	spin_unlock_bh(&amt->upstream_lock);
}

static void amt_dev_uninit(struct net_device *dev)
{
	struct amt_dev *amt = netdev_priv(dev);

	gro_cells_destroy(&amt->gro_cells);
	free_percpu(dev->tstats);
}

static const struct net_device_ops amt_netdev_ops = {
	.ndo_init               = amt_dev_init,
	.ndo_uninit             = amt_dev_uninit,
	.ndo_open		= amt_dev_open,
	.ndo_stop		= amt_dev_stop,
	.ndo_start_xmit         = amt_dev_xmit,
	.ndo_get_stats64        = dev_get_tstats64,
};

static void amt_link_setup(struct net_device *dev)
{
	dev->netdev_ops         = &amt_netdev_ops;
	dev->needs_free_netdev  = true;
	dev->priv_destructor    = amt_dev_destructor;
	SET_NETDEV_DEVTYPE(dev, &amt_type);
	dev->min_mtu		= ETH_MIN_MTU;
	dev->max_mtu		= ETH_MAX_MTU;
	dev->type		= ARPHRD_NONE;
	dev->flags		= IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
	dev->hard_header_len	= 0;
	dev->addr_len		= 0;
	dev->priv_flags		|= IFF_NO_QUEUE;
	dev->lltx		= true;
	dev->features		|= NETIF_F_GSO_SOFTWARE;
	dev->netns_immutable		= true;
	dev->hw_features	|= NETIF_F_SG | NETIF_F_HW_CSUM;
	dev->hw_features	|= NETIF_F_FRAGLIST | NETIF_F_RXCSUM;
	dev->hw_features	|= NETIF_F_GSO_SOFTWARE;
	eth_hw_addr_random(dev);
	eth_zero_addr(dev->broadcast);
	ether_setup(dev);
}

static const struct nla_policy amt_policy[IFLA_AMT_MAX + 1] = {
	[IFLA_AMT_MODE]		= { .type = NLA_U32 },
	[IFLA_AMT_RELAY_PORT]	= { .type = NLA_U16 },
	[IFLA_AMT_GATEWAY_PORT]	= { .type = NLA_U16 },
	[IFLA_AMT_LINK]		= { .type = NLA_U32 },
	[IFLA_AMT_LOCAL_IP]	= { .len = sizeof_field(struct iphdr, daddr) },
	[IFLA_AMT_REMOTE_IP]	= { .len = sizeof_field(struct iphdr, daddr) },
	[IFLA_AMT_DISCOVERY_IP]	= { .len = sizeof_field(struct iphdr, daddr) },
	[IFLA_AMT_MAX_TUNNELS]	= { .type = NLA_U32 },
	[IFLA_AMT_LOCAL_IP6]	= NLA_POLICY_EXACT_LEN(sizeof(struct in6_addr)),
	[IFLA_AMT_HASH_BUCKETS]	= { .type = NLA_U32 },
	[IFLA_AMT_MAX_GROUPS]	= { .type = NLA_U32 },
	[IFLA_AMT_NUM_QUEUES]	= { .type = NLA_U32 },
};

static int amt_validate(struct nlattr *tb[], struct nlattr *data[],
			struct netlink_ext_ack *extack)
{
	if (!data)
		return -EINVAL;

	if (!data[IFLA_AMT_LINK]) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_AMT_LINK],
				    "Link attribute is required");
		return -EINVAL;
	}

	if (!data[IFLA_AMT_MODE]) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_AMT_MODE],
				    "Mode attribute is required");
		return -EINVAL;
	}

	if (nla_get_u32(data[IFLA_AMT_MODE]) > AMT_MODE_MAX) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_AMT_MODE],
				    "Mode attribute is not valid");
		return -EINVAL;
	}

	if (!data[IFLA_AMT_LOCAL_IP] && !data[IFLA_AMT_LOCAL_IP6]) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Local IPv4 or IPv6 attribute is required");
		return -EINVAL;
	}

	if (data[IFLA_AMT_LOCAL_IP] && data[IFLA_AMT_LOCAL_IP6]) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Local IPv4 and IPv6 are mutually exclusive");
		return -EINVAL;
	}

	if (data[IFLA_AMT_LOCAL_IP6] &&
	    nla_get_u32(data[IFLA_AMT_MODE]) == AMT_MODE_GATEWAY) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_AMT_LOCAL_IP6],
				    "Local IPv6 is only supported in relay mode");
		return -EINVAL;
	}

	if (!data[IFLA_AMT_DISCOVERY_IP] &&
	    nla_get_u32(data[IFLA_AMT_MODE]) == AMT_MODE_GATEWAY) {
		NL_SET_ERR_MSG_ATTR(extack, data[IFLA_AMT_LOCAL_IP],
				    "Discovery attribute is required");
		return -EINVAL;
	}

	return 0;
}

static int amt_newlink(struct net_device *dev,
		       struct rtnl_newlink_params *params,
		       struct netlink_ext_ack *extack)
{
	struct net *net = rtnl_newlink_link_net(params);
	struct amt_dev *amt = netdev_priv(dev);
	struct nlattr **data = params->data;
	struct nlattr **tb = params->tb;
	int err = -EINVAL;

	amt->net = net;
	amt->mode = nla_get_u32(data[IFLA_AMT_MODE]);

	if (data[IFLA_AMT_MAX_TUNNELS] &&
	    nla_get_u32(data[IFLA_AMT_MAX_TUNNELS]))
		amt->max_tunnels = nla_get_u32(data[IFLA_AMT_MAX_TUNNELS]);
	else
		amt->max_tunnels = AMT_MAX_TUNNELS;

	spin_lock_init(&amt->lock);
	if (data[IFLA_AMT_MAX_GROUPS] &&
	    nla_get_u32(data[IFLA_AMT_MAX_GROUPS]))
		amt->max_groups = nla_get_u32(data[IFLA_AMT_MAX_GROUPS]);
	else
		amt->max_groups = AMT_MAX_GROUP;
	amt->max_sources = AMT_MAX_SOURCE;
	if (data[IFLA_AMT_HASH_BUCKETS] &&
	    nla_get_u32(data[IFLA_AMT_HASH_BUCKETS]))
		/* No power-of-two constraint: bucket selection runs through
		 * reciprocal_scale() which is uniform for any positive count.
		 * Userspace picks any value sized to its peak nr_groups; we
		 * only consume it as the flex-array stride for
		 * gnode->sources[] (still hlist-backed, unlike the
		 * tunnel->groups_rhl rhltable migrated in this series).
		 */
		amt->hash_buckets = nla_get_u32(data[IFLA_AMT_HASH_BUCKETS]);
	else
		amt->hash_buckets = AMT_HSIZE;
	amt->nr_tunnels = 0;
	get_random_bytes(&amt->hash_seed, sizeof(amt->hash_seed));
	amt->stream_dev = dev_get_by_index(net,
					   nla_get_u32(data[IFLA_AMT_LINK]));
	if (!amt->stream_dev) {
		NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_LINK],
				    "Can't find stream device");
		return -ENODEV;
	}

	if (amt->stream_dev->type != ARPHRD_ETHER) {
		NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_LINK],
				    "Invalid stream device type");
		goto err;
	}

	if (data[IFLA_AMT_LOCAL_IP6]) {
		amt->local_ipv6 = nla_get_in6_addr(data[IFLA_AMT_LOCAL_IP6]);
		if (ipv6_addr_loopback(&amt->local_ipv6) ||
		    ipv6_addr_any(&amt->local_ipv6) ||
		    ipv6_addr_is_multicast(&amt->local_ipv6)) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_LOCAL_IP6],
					    "Invalid Local IPv6 address");
			goto err;
		}
	} else {
		amt->local_ip = nla_get_in_addr(data[IFLA_AMT_LOCAL_IP]);
		if (ipv4_is_loopback(amt->local_ip) ||
		    ipv4_is_zeronet(amt->local_ip) ||
		    ipv4_is_multicast(amt->local_ip)) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_LOCAL_IP],
					    "Invalid Local address");
			goto err;
		}
	}

	if (data[IFLA_AMT_RELAY_PORT])
		amt->relay_port = nla_get_be16(data[IFLA_AMT_RELAY_PORT]);
	else
		amt->relay_port = htons(IANA_AMT_UDP_PORT);

	if (data[IFLA_AMT_GATEWAY_PORT])
		amt->gw_port = nla_get_be16(data[IFLA_AMT_GATEWAY_PORT]);
	else
		amt->gw_port = htons(IANA_AMT_UDP_PORT);

	if (!amt->relay_port) {
		NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_DISCOVERY_IP],
				    "relay port must not be 0");
		goto err;
	}
	if (amt->mode == AMT_MODE_RELAY) {
		amt->qrv = READ_ONCE(amt->net->ipv4.sysctl_igmp_qrv);
		amt->qri = 10;
		dev->needed_headroom = amt->stream_dev->needed_headroom +
				       AMT_RELAY_HLEN;
		dev->mtu = amt->stream_dev->mtu - AMT_RELAY_HLEN;
		dev->max_mtu = dev->mtu;
		dev->min_mtu = ETH_MIN_MTU + AMT_RELAY_HLEN;
	} else {
		if (!data[IFLA_AMT_DISCOVERY_IP]) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_DISCOVERY_IP],
					    "discovery must be set in gateway mode");
			goto err;
		}
		if (!amt->gw_port) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_DISCOVERY_IP],
					    "gateway port must not be 0");
			goto err;
		}
		amt->remote_ip = 0;
		amt->discovery_ip = nla_get_in_addr(data[IFLA_AMT_DISCOVERY_IP]);
		if (ipv4_is_loopback(amt->discovery_ip) ||
		    ipv4_is_zeronet(amt->discovery_ip) ||
		    ipv4_is_multicast(amt->discovery_ip)) {
			NL_SET_ERR_MSG_ATTR(extack, tb[IFLA_AMT_DISCOVERY_IP],
					    "discovery must be unicast");
			goto err;
		}

		dev->needed_headroom = amt->stream_dev->needed_headroom +
				       AMT_GW_HLEN;
		dev->mtu = amt->stream_dev->mtu - AMT_GW_HLEN;
		dev->max_mtu = dev->mtu;
		dev->min_mtu = ETH_MIN_MTU + AMT_GW_HLEN;
	}
	amt->qi = AMT_INIT_QUERY_INTERVAL;

	/* Optional multi-queue override. Default to a single live queue so
	 * an upgrade from a single-queue baseline keeps the same TX hash
	 * behavior. .get_num_tx_queues / .get_num_rx_queues return
	 * AMT_MAX_QUEUES for the ALLOCATION so that a subsequent
	 * netif_set_real_num_*_queues can raise without re-alloc, but the
	 * default operating shape MUST be one queue or every existing
	 * `ip link add ... type amt` invocation silently gets 32-way TX
	 * hashing post-upgrade. Both branches below explicitly call
	 * netif_set_real_num_*_queues -- the else with q=1 is the
	 * default that preserves the pre-multiqueue ABI exactly.
	 */
	{
		u32 q = 1;

		if (data[IFLA_AMT_NUM_QUEUES] &&
		    nla_get_u32(data[IFLA_AMT_NUM_QUEUES])) {
			q = nla_get_u32(data[IFLA_AMT_NUM_QUEUES]);
			if (q > AMT_MAX_QUEUES) {
				NL_SET_ERR_MSG_ATTR(extack,
						    data[IFLA_AMT_NUM_QUEUES],
						    "num_queues exceeds AMT_MAX_QUEUES");
				err = -EINVAL;
				goto err;
			}
		}
		err = netif_set_real_num_tx_queues(dev, q);
		if (err)
			goto err;
		err = netif_set_real_num_rx_queues(dev, q);
		if (err)
			goto err;
	}

	err = register_netdevice(dev);
	if (err < 0) {
		netdev_dbg(dev, "failed to register new netdev %d\n", err);
		goto err;
	}

	/* No explicit sysfs_create_group here: amt_type::groups auto-creates the
	 * "upstream/" group inside register_netdevice's device_add(), and
	 * unregister_netdevice's device_del() removes it. Explicit pairing is
	 * race-prone — see amt_dev_destructor comment.
	 */
	err = netdev_upper_dev_link(amt->stream_dev, dev, extack);
	if (err < 0) {
		unregister_netdevice(dev);
		goto err;
	}

	INIT_DELAYED_WORK(&amt->discovery_wq, amt_discovery_work);
	INIT_DELAYED_WORK(&amt->req_wq, amt_req_work);
	INIT_DELAYED_WORK(&amt->secret_wq, amt_secret_work);
	INIT_WORK(&amt->event_wq, amt_event_work);
	INIT_LIST_HEAD(&amt->tunnel_list);
	return 0;
err:
	dev_put(amt->stream_dev);
	return err;
}

static void amt_dellink(struct net_device *dev, struct list_head *head)
{
	struct amt_dev *amt = netdev_priv(dev);

	unregister_netdevice_queue(dev, head);
	netdev_upper_dev_unlink(amt->stream_dev, dev);
	dev_put(amt->stream_dev);
}

static size_t amt_get_size(const struct net_device *dev)
{
	return nla_total_size(sizeof(__u32)) + /* IFLA_AMT_MODE */
	       nla_total_size(sizeof(__u16)) + /* IFLA_AMT_RELAY_PORT */
	       nla_total_size(sizeof(__u16)) + /* IFLA_AMT_GATEWAY_PORT */
	       nla_total_size(sizeof(__u32)) + /* IFLA_AMT_LINK */
	       nla_total_size(sizeof(__u32)) + /* IFLA_MAX_TUNNELS */
	       nla_total_size(sizeof(__u32)) + /* IFLA_AMT_HASH_BUCKETS */
	       nla_total_size(sizeof(__u32)) + /* IFLA_AMT_MAX_GROUPS */
	       nla_total_size(sizeof(__u32)) + /* IFLA_AMT_NUM_QUEUES */
	       nla_total_size(sizeof(struct iphdr)) + /* IFLA_AMT_DISCOVERY_IP */
	       nla_total_size(sizeof(struct iphdr)) + /* IFLA_AMT_REMOTE_IP */
	       nla_total_size(sizeof(struct iphdr)) + /* IFLA_AMT_LOCAL_IP */
	       nla_total_size(sizeof(struct in6_addr)); /* IFLA_AMT_LOCAL_IP6 */
}

static int amt_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct amt_dev *amt = netdev_priv(dev);

	if (nla_put_u32(skb, IFLA_AMT_MODE, amt->mode))
		goto nla_put_failure;
	if (nla_put_be16(skb, IFLA_AMT_RELAY_PORT, amt->relay_port))
		goto nla_put_failure;
	if (nla_put_be16(skb, IFLA_AMT_GATEWAY_PORT, amt->gw_port))
		goto nla_put_failure;
	if (nla_put_u32(skb, IFLA_AMT_LINK, amt->stream_dev->ifindex))
		goto nla_put_failure;
	/* Emit exactly one of LOCAL_IP / LOCAL_IP6 -- whichever family the
	 * relay was created with. amt_newlink rejects both being set, so
	 * exactly one is meaningful. Userspace tools (iproute2 `ip -d link
	 * show`) read the attribute back to decide which family the relay
	 * is in; if we always emitted LOCAL_IP, a v6 relay would advertise
	 * local 0.0.0.0 and `ip link` would silently render it as a v4
	 * relay.
	 */
	if (!ipv6_addr_any(&amt->local_ipv6)) {
		if (nla_put_in6_addr(skb, IFLA_AMT_LOCAL_IP6,
				     &amt->local_ipv6))
			goto nla_put_failure;
	} else {
		if (nla_put_in_addr(skb, IFLA_AMT_LOCAL_IP, amt->local_ip))
			goto nla_put_failure;
	}
	if (nla_put_in_addr(skb, IFLA_AMT_DISCOVERY_IP, amt->discovery_ip))
		goto nla_put_failure;
	if (amt->remote_ip)
		if (nla_put_in_addr(skb, IFLA_AMT_REMOTE_IP, amt->remote_ip))
			goto nla_put_failure;
	if (nla_put_u32(skb, IFLA_AMT_MAX_TUNNELS, amt->max_tunnels))
		goto nla_put_failure;
	if (nla_put_u32(skb, IFLA_AMT_HASH_BUCKETS, amt->hash_buckets))
		goto nla_put_failure;
	if (nla_put_u32(skb, IFLA_AMT_MAX_GROUPS, amt->max_groups))
		goto nla_put_failure;
	if (nla_put_u32(skb, IFLA_AMT_NUM_QUEUES, dev->real_num_tx_queues))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static unsigned int amt_get_num_tx_queues(void)
{
	return AMT_MAX_QUEUES;
}

static unsigned int amt_get_num_rx_queues(void)
{
	return AMT_MAX_QUEUES;
}

static struct rtnl_link_ops amt_link_ops __read_mostly = {
	.kind		= "amt",
	.maxtype	= IFLA_AMT_MAX,
	.policy		= amt_policy,
	.priv_size	= sizeof(struct amt_dev),
	.setup		= amt_link_setup,
	.validate	= amt_validate,
	.newlink	= amt_newlink,
	.dellink	= amt_dellink,
	.get_size       = amt_get_size,
	.fill_info      = amt_fill_info,
	/* Allocate the netdev with AMT_MAX_QUEUES TX/RX slots so amt_newlink
	 * can pick the live count via netif_set_real_num_{tx,rx}_queues.
	 * Without these callbacks, alloc_netdev_mqs would reserve a single
	 * slot and any later set_real_num call would EINVAL.
	 */
	.get_num_tx_queues = amt_get_num_tx_queues,
	.get_num_rx_queues = amt_get_num_rx_queues,
};

static struct net_device *amt_lookup_upper_dev(struct net_device *dev)
{
	struct net_device *upper_dev;
	struct amt_dev *amt;

	for_each_netdev(dev_net(dev), upper_dev) {
		if (netif_is_amt(upper_dev)) {
			amt = netdev_priv(upper_dev);
			if (amt->stream_dev == dev)
				return upper_dev;
		}
	}

	return NULL;
}

static int amt_device_event(struct notifier_block *unused,
			    unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct net_device *upper_dev;
	struct amt_dev *amt;
	LIST_HEAD(list);
	int new_mtu;

	upper_dev = amt_lookup_upper_dev(dev);
	if (!upper_dev)
		return NOTIFY_DONE;
	amt = netdev_priv(upper_dev);

	switch (event) {
	case NETDEV_UNREGISTER:
		amt_dellink(amt->dev, &list);
		unregister_netdevice_many(&list);
		break;
	case NETDEV_CHANGEMTU:
		if (amt->mode == AMT_MODE_RELAY)
			new_mtu = dev->mtu - AMT_RELAY_HLEN;
		else
			new_mtu = dev->mtu - AMT_GW_HLEN;

		dev_set_mtu(amt->dev, new_mtu);
		break;
	case NETDEV_DOWN:
		/* stream_dev went down. Gate the upstream emit path so the
		 * worker stops queuing setsockopt calls that would fail with
		 * -ENETDOWN and burn CPU retrying. The refcount table is
		 * intentionally left alive — when the stream_dev returns,
		 * NETDEV_UP below resumes emit. The kernel host stack drops
		 * its (S, G) memberships on dev_close, so on resume the
		 * next gateway Membership Update repopulates them via the
		 * normal IS_IN/TO_IN path.
		 */
		netdev_info(amt->dev,
			    "upstream: stream_dev %s went DOWN; pausing upstream emit\n",
			    dev->name);
		WRITE_ONCE(amt->upstream_active, false);
		break;
	case NETDEV_UP:
		/* stream_dev came back up; allow the worker to dispatch
		 * setsockopt again. Refcount-table rationale: see
		 * NETDEV_DOWN above — we trust the next gateway Membership
		 * Update to re-emit kernel-host-stack IGMP joins.
		 */
		netdev_info(amt->dev,
			    "upstream: stream_dev %s came UP; resuming upstream emit\n",
			    dev->name);
		WRITE_ONCE(amt->upstream_active, true);
		break;
	case NETDEV_CHANGEADDR:
		/* L2 (MAC) address change on stream_dev. Upstream sockets
		 * are bound by ifindex (sock_bindtoindex), not by L2 or
		 * source address, so setsockopt continues to target the
		 * same iface. The kernel rewrites the L2 src on outbound
		 * frames from the current dev->dev_addr automatically.
		 * No upstream state change needed — logged for
		 * observability only. (IPv4/IPv6 address adds/removes
		 * arrive via inetaddr/inet6addr notifiers separately and
		 * are not observed by this netdev notifier.)
		 */
		netdev_info(amt->dev,
			    "upstream: stream_dev %s L2 address changed\n",
			    dev->name);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block amt_notifier_block __read_mostly = {
	.notifier_call = amt_device_event,
};

#ifdef AMT_TEST_ENABLED
#include <linux/delay.h>

/*
 * Regression test for the 2026-05-21 staging-wedge AB-BA pattern.
 *
 * Pattern: amt_dev_stop holds rtnl_lock, calls cancel_work_sync on a worker
 * that's mid-setsockopt waiting on rtnl_lock. Recursive deadlock.
 *
 * Commit 4's design avoids this by deferring cancel_work_sync to
 * amt_dev_destructor (post-rtnl). amt_dev_stop only flips a flag and
 * drains pending — never blocks on the worker.
 *
 * This test asserts that invariant: a teardown_stop call returns
 * within a bounded time even when a worker is "busy" (we don't have
 * a real rtnl-held worker to test against, so we approximate by
 * checking teardown_stop doesn't call cancel_work_sync).
 *
 * Run by loading amt.ko with the module compiled with -DAMT_TEST_ENABLED.
 * The test runs at module init and logs PASS/FAILURE.
 */
static void __init amt_upstream_self_test(void)
{
	struct amt_dev *amt;
	ktime_t t0, elapsed;
	u64 elapsed_ms;
	int i;

	pr_info("amt: running self-test (AMT_TEST_ENABLED)\n");

	amt = kzalloc(sizeof(*amt), GFP_KERNEL);
	if (!amt) {
		pr_err("amt: self-test kzalloc failed\n");
		return;
	}

	/* Minimal init mirroring amt_dev_init's upstream block. */
	spin_lock_init(&amt->upstream_lock);
	spin_lock_init(&amt->upstream_pending_lock);
	INIT_LIST_HEAD(&amt->upstream_pending);
	INIT_WORK(&amt->upstream_work, amt_upstream_worker);
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&amt->upstream[i]);
#if IS_ENABLED(CONFIG_IPV6)
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&amt->upstream_v6[i]);
#endif
	atomic_set(&amt->upstream_setsockopt_slow_count, 0);

	/* Simulate "device is up" — track and worker will try to act, but
	 * with no stream_dev they'll bail with -ESHUTDOWN/-ENODEV. That's
	 * fine for this regression test; the assertion is about timing
	 * (teardown_stop must not block), not emit success.
	 */
	WRITE_ONCE(amt->upstream_active, true);

	/* Enqueue a fake pending entry. Worker dispatch will fail fast (no
	 * stream_dev) but that's OK — we're measuring teardown_stop latency,
	 * not emit correctness.
	 */
	{
		struct amt_upstream_pending *p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (p) {
			p->family = AF_INET;
			p->group_v4 = htonl(0xe8630001);
			p->source_v4 = htonl(0x0a000001);
			p->op = AMT_UPSTREAM_JOIN;
			spin_lock_bh(&amt->upstream_pending_lock);
			list_add_tail(&p->link, &amt->upstream_pending);
			spin_unlock_bh(&amt->upstream_pending_lock);
		}
	}

	/* Time the teardown. Must complete fast — no cancel_work_sync, no
	 * blocking, no recursive lock. The whole point of Commit 4's design.
	 */
	t0 = ktime_get();
	amt_upstream_teardown_stop(amt);
	elapsed = ktime_sub(ktime_get(), t0);
	elapsed_ms = ktime_to_ms(elapsed);

	if (elapsed_ms > 50) {
		pr_err("amt: SELF-TEST FAILURE: teardown_stop took %llu ms (limit 50ms) — "
		       "did someone re-introduce cancel_work_sync into amt_dev_stop?\n",
		       elapsed_ms);
	} else {
		pr_info("amt: self-test PASS: teardown_stop returned in %llu ms\n",
			elapsed_ms);
	}

	/* Now mimic destructor: cancel the worker and free state. */
	cancel_work_sync(&amt->upstream_work);
	kfree(amt);
}

/*
 * Regression test for the 2026-05-25 amt_dev_destructor panic:
 * sysfs_remove_group(&dev->dev.kobj, ...) on a netdev whose device_del()
 * had already nulled kobj->sd → NULL deref in kernfs_find_and_get_ns.
 *
 * The prior self-test allocated a bare amt_dev via kzalloc and never went
 * through alloc_netdev, so it could not catch destructor bugs that depend
 * on net_device-embedded device-model state. This test fixes that gap: it
 * allocates a real net_device via alloc_netdev (which initializes dev->dev
 * but does NOT register it, leaving kobj->sd == NULL — exactly the state
 * priv_destructor sees AFTER device_del() during unregister_netdevice).
 *
 * If amt_dev_destructor calls any kobj-dependent API (sysfs_remove_group,
 * device_remove_groups, kobject_*), this test OOPSes at module load and
 * surfaces the regression before any user-facing damage.
 *
 * Pair with: amt_type::groups for sysfs lifetime; see amt_type comment.
 */
static void __init amt_lifecycle_self_test(void)
{
	struct net_device *test_dev;
	struct amt_dev *amt;
	int i;

	pr_info("amt: running lifecycle self-test (destructor safety)\n");

	test_dev = alloc_netdev(sizeof(*amt), "amtst%d",
				NET_NAME_UNKNOWN, amt_link_setup);
	if (!test_dev) {
		pr_err("amt: lifecycle self-test alloc_netdev failed\n");
		return;
	}

	amt = netdev_priv(test_dev);

	/* Mirror amt_dev_init's upstream block — the destructor walks
	 * these tables and waits on this work, so they must be initialized
	 * to match the post-ndo_init state. Everything else stays zeroed,
	 * matching a never-opened device (the scenario that hit the panic).
	 */
	spin_lock_init(&amt->upstream_lock);
	spin_lock_init(&amt->upstream_pending_lock);
	INIT_LIST_HEAD(&amt->upstream_pending);
	INIT_WORK(&amt->upstream_work, amt_upstream_worker);
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&amt->upstream[i]);
#if IS_ENABLED(CONFIG_IPV6)
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&amt->upstream_v6[i]);
#endif

	/* CRITICAL: do NOT register_netdevice(). We want kobj->sd == NULL,
	 * matching the state after device_del() during real
	 * unregister_netdevice. The prior bug (sysfs_remove_group in
	 * amt_dev_destructor) panics on exactly this state.
	 */
	amt_dev_destructor(test_dev);

	free_netdev(test_dev);

	pr_info("amt: lifecycle self-test PASS: destructor safe on alloc_netdev-only state\n");
}

static void __init amt_selftest_free_pending(struct amt_dev *amt)
{
	struct amt_upstream_pending *p, *tmp;
	LIST_HEAD(local);

	amt_upstream_drain_pending(amt, &local);
	list_for_each_entry_safe(p, tmp, &local, link) {
		list_del(&p->link);
		kfree(p);
	}
}

static bool __init amt_ex_transition_run_case(struct amt_dev *amt, bool to_ex)
{
	struct {
		struct igmpv3_grec grec;
		__be32 srcs[1];
	} report;
	struct amt_tunnel_list tunnel = {0};
	struct amt_group_node *gnode;
	struct amt_source_node *snode;
	struct amt_upstream_pending *p, *tmp;
	union amt_addr src = {0};
	LIST_HEAD(local);
	const char *name;
	__be32 group;
	__be32 drop_src;
	__be32 keep_src;
	u32 hash;
	int leave_before;
	int leave_pending = 0;
	int pending_total = 0;
	bool source_removed;
	bool pass = true;
	int i;

	name = to_ex ? "TO_EX" : "IS_EX";
	group = htonl(0xe8630001);	/* 232.99.0.1 */
	drop_src = htonl(0x0a000001);	/* A-B: 10.0.0.1 */
	keep_src = htonl(0x0a000002);	/* B-only: 10.0.0.2 */

	gnode = kzalloc(sizeof(*gnode) +
			(sizeof(struct hlist_head) * amt->hash_buckets),
			GFP_KERNEL);
	if (!gnode) {
		pr_err("amt: ex-transition %s self-test gnode alloc failed\n",
		       name);
		return false;
	}

	src.ip4 = drop_src;
	snode = amt_alloc_snode(gnode, &src);
	if (!snode) {
		pr_err("amt: ex-transition %s self-test snode alloc failed\n",
		       name);
		kfree(gnode);
		return false;
	}

	/* Synthetic INCLUDE-mode group with one FWD/OLD A-B source. The
	 * report contains a different B source, so drop_src is in A-B.
	 */
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&amt->upstream[i]);
	for (i = 0; i < amt->hash_buckets; i++)
		INIT_HLIST_HEAD(&gnode->sources[i]);

	spin_lock_init(&tunnel.lock);
	tunnel.amt = amt;
	tunnel.nr_sources = 1;
	gnode->amt = amt;
	gnode->v6 = false;
	gnode->filter_mode = MCAST_INCLUDE;
	gnode->tunnel_list = &tunnel;
	gnode->group_addr.ip4 = group;
	gnode->nr_sources = 1;
	INIT_DELAYED_WORK(&gnode->group_timer, amt_group_work);

	snode->status = AMT_SOURCE_STATUS_FWD;
	snode->flags = AMT_SOURCE_OLD;
	hash = amt_source_hash(&tunnel, &snode->source_addr);
	hlist_add_head_rcu(&snode->node, &gnode->sources[hash]);

	memset(&report, 0, sizeof(report));
	report.grec.grec_nsrcs = htons(1);
	report.grec.grec_mca = group;
	report.grec.grec_src[0] = keep_src;

	/* Seed the host-stack mirror without queueing a JOIN. The case under
	 * test is the handler's pre-cleanup LEAVE.
	 */
	if (!amt_upstream_refcount(amt, group, drop_src, AMT_UPSTREAM_JOIN)) {
		pr_err("amt: SELF-TEST FAILURE: %s could not seed upstream refcount\n",
		       name);
		pass = false;
	}
	leave_before = atomic_read(&amt_upstream_test_leave_emits);
	WRITE_ONCE(amt_upstream_test_suppress_queue, true);

	if (to_ex)
		amt_mcast_to_ex_handler(amt, &tunnel, gnode, &report.grec,
					&igmpv3_zero_grec, false);
	else
		amt_mcast_is_ex_handler(amt, &tunnel, gnode, &report.grec,
					&igmpv3_zero_grec, false);

	if (gnode->filter_mode != MCAST_EXCLUDE) {
		pr_err("amt: SELF-TEST FAILURE: %s did not flip filter_mode to EXCLUDE\n",
		       name);
		pass = false;
	}

	if (gnode->nr_sources != 1 || tunnel.nr_sources != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s removed A-B before cleanup (group=%u tunnel=%u)\n",
		       name, gnode->nr_sources, tunnel.nr_sources);
		pass = false;
	}

	spin_lock_bh(&amt->upstream_lock);
	if (amt_upstream_find(amt, group, drop_src) != NULL) {
		pr_err("amt: SELF-TEST FAILURE: %s did not drain A-B refcount before filter_mode flip\n",
		       name);
		pass = false;
	}
	spin_unlock_bh(&amt->upstream_lock);

	amt_upstream_drain_pending(amt, &local);
	list_for_each_entry_safe(p, tmp, &local, link) {
		pending_total++;
		if (p->family == AF_INET && p->op == AMT_UPSTREAM_LEAVE &&
		    p->group_v4 == group && p->source_v4 == drop_src)
			leave_pending++;
		list_del(&p->link);
		kfree(p);
	}

	if (pending_total != 1 || leave_pending != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s queued %d pending ops, %d matching A-B LEAVEs (want exactly 1)\n",
		       name, pending_total, leave_pending);
		pass = false;
	}

	if (atomic_read(&amt_upstream_test_leave_emits) - leave_before != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s leave emit counter delta was %d (want 1)\n",
		       name, atomic_read(&amt_upstream_test_leave_emits) - leave_before);
		pass = false;
	}

	amt_cleanup_srcs(amt, &tunnel, gnode);

	if (gnode->nr_sources != 0 || tunnel.nr_sources != 0) {
		pr_err("amt: SELF-TEST FAILURE: %s cleanup did not remove A-B source (group=%u tunnel=%u)\n",
		       name, gnode->nr_sources, tunnel.nr_sources);
		pass = false;
	}

	if (atomic_read(&amt_upstream_test_leave_emits) - leave_before != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s cleanup queued an extra upstream LEAVE\n",
		       name);
		pass = false;
	}

	source_removed = gnode->nr_sources == 0;
	if (!source_removed) {
		hlist_del_init_rcu(&snode->node);
		kfree(snode);
	}
	if (cancel_delayed_work_sync(&gnode->group_timer))
		dev_put(amt->dev);
	kfree(gnode);
	amt_selftest_free_pending(amt);

	return pass;
}

#if IS_ENABLED(CONFIG_IPV6)
/* v6 sibling of amt_ex_transition_run_case. Mirrors the v4 case
 * structurally; the only differences are address-family-specific:
 *   - gnode->v6 = true
 *   - report uses struct mld2_grec + struct in6_addr sources
 *   - seed/find/match go through amt_upstream_refcount_v6 /
 *     amt_upstream_find_v6 against amt->upstream_v6[]
 *   - handler dispatch passes mldv2_zero_grec and v6=true
 *   - pending entry assertion checks AF_INET6 + ipv6_addr_equal
 * Validates that the v6 upstream-track path mirrors v4 for the same
 * INCLUDE->EXCLUDE leak scenario covered in PR #57 / commit 49316ce.
 */
static bool __init amt_ex_transition_run_case_v6(struct amt_dev *amt, bool to_ex)
{
	struct {
		struct mld2_grec grec;
		struct in6_addr srcs[1];
	} report;
	struct amt_tunnel_list tunnel = {0};
	struct amt_group_node *gnode;
	struct amt_source_node *snode;
	struct amt_upstream_pending *p, *tmp;
	union amt_addr src = {0};
	LIST_HEAD(local);
	const char *name;
	struct in6_addr group;
	struct in6_addr drop_src;
	struct in6_addr keep_src;
	u32 hash;
	int leave_before;
	int leave_pending = 0;
	int pending_total = 0;
	bool source_removed;
	bool pass = true;
	int i;

	name = to_ex ? "TO_EX_v6" : "IS_EX_v6";

	/* SSM v6 group ff3e::1 (global-scope source-specific multicast,
	 * RFC 4607 FF3x::/32). The scope nibble `e` is global; this test
	 * does not rely on scope semantics — it just needs a valid SSM
	 * group that amt_upstream_track will accept.
	 */
	memset(&group, 0, sizeof(group));
	group.s6_addr[0] = 0xff;
	group.s6_addr[1] = 0x3e;
	group.s6_addr[15] = 0x01;
	/* A-B drop_src = 2001:db8::1; B-only keep_src = 2001:db8::2. */
	memset(&drop_src, 0, sizeof(drop_src));
	drop_src.s6_addr[0] = 0x20;
	drop_src.s6_addr[1] = 0x01;
	drop_src.s6_addr[2] = 0x0d;
	drop_src.s6_addr[3] = 0xb8;
	drop_src.s6_addr[15] = 0x01;
	memset(&keep_src, 0, sizeof(keep_src));
	keep_src.s6_addr[0] = 0x20;
	keep_src.s6_addr[1] = 0x01;
	keep_src.s6_addr[2] = 0x0d;
	keep_src.s6_addr[3] = 0xb8;
	keep_src.s6_addr[15] = 0x02;

	gnode = kzalloc(sizeof(*gnode) +
			(sizeof(struct hlist_head) * amt->hash_buckets),
			GFP_KERNEL);
	if (!gnode) {
		pr_err("amt: ex-transition %s self-test gnode alloc failed\n",
		       name);
		return false;
	}

	src.ip6 = drop_src;
	snode = amt_alloc_snode(gnode, &src);
	if (!snode) {
		pr_err("amt: ex-transition %s self-test snode alloc failed\n",
		       name);
		kfree(gnode);
		return false;
	}

	/* Re-init both upstream tables between cases so each case sees a
	 * clean slate, matching the v4 run_case pattern.
	 */
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&amt->upstream[i]);
		INIT_HLIST_HEAD(&amt->upstream_v6[i]);
	}
	for (i = 0; i < amt->hash_buckets; i++)
		INIT_HLIST_HEAD(&gnode->sources[i]);

	spin_lock_init(&tunnel.lock);
	tunnel.amt = amt;
	tunnel.nr_sources = 1;
	gnode->amt = amt;
	gnode->v6 = true;
	gnode->filter_mode = MCAST_INCLUDE;
	gnode->tunnel_list = &tunnel;
	gnode->group_addr.ip6 = group;
	gnode->nr_sources = 1;
	INIT_DELAYED_WORK(&gnode->group_timer, amt_group_work);

	snode->status = AMT_SOURCE_STATUS_FWD;
	snode->flags = AMT_SOURCE_OLD;
	hash = amt_source_hash(&tunnel, &snode->source_addr);
	hlist_add_head_rcu(&snode->node, &gnode->sources[hash]);

	memset(&report, 0, sizeof(report));
	report.grec.grec_nsrcs = htons(1);
	report.grec.grec_mca = group;
	report.grec.grec_src[0] = keep_src;

	/* Test scope: this exercises ONLY the handler's pre-cleanup A-B
	 * LEAVE invariant. The real MLDv2 report path calls amt_add_srcs()
	 * before amt_mcast_*_ex_handler() to populate B/(B-A) source state;
	 * we deliberately skip that so the assertions can isolate the
	 * pre-flip refcount drain. Matches the v4 amt_ex_transition_run_case
	 * test structure.
	 *
	 * Seed the host-stack mirror without queueing a JOIN. The case under
	 * test is the handler's pre-cleanup LEAVE.
	 */
	if (!amt_upstream_refcount_v6(amt, &group, &drop_src, AMT_UPSTREAM_JOIN)) {
		pr_err("amt: SELF-TEST FAILURE: %s could not seed upstream refcount\n",
		       name);
		pass = false;
	}
	leave_before = atomic_read(&amt_upstream_test_leave_emits);
	WRITE_ONCE(amt_upstream_test_suppress_queue, true);

	if (to_ex)
		amt_mcast_to_ex_handler(amt, &tunnel, gnode, &report.grec,
					&mldv2_zero_grec, true);
	else
		amt_mcast_is_ex_handler(amt, &tunnel, gnode, &report.grec,
					&mldv2_zero_grec, true);

	if (gnode->filter_mode != MCAST_EXCLUDE) {
		pr_err("amt: SELF-TEST FAILURE: %s did not flip filter_mode to EXCLUDE\n",
		       name);
		pass = false;
	}

	if (gnode->nr_sources != 1 || tunnel.nr_sources != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s removed A-B before cleanup (group=%u tunnel=%u)\n",
		       name, gnode->nr_sources, tunnel.nr_sources);
		pass = false;
	}

	spin_lock_bh(&amt->upstream_lock);
	if (amt_upstream_find_v6(amt, &group, &drop_src) != NULL) {
		pr_err("amt: SELF-TEST FAILURE: %s did not drain A-B refcount before filter_mode flip\n",
		       name);
		pass = false;
	}
	spin_unlock_bh(&amt->upstream_lock);

	amt_upstream_drain_pending(amt, &local);
	list_for_each_entry_safe(p, tmp, &local, link) {
		pending_total++;
		if (p->family == AF_INET6 && p->op == AMT_UPSTREAM_LEAVE &&
		    ipv6_addr_equal(&p->group_v6, &group) &&
		    ipv6_addr_equal(&p->source_v6, &drop_src))
			leave_pending++;
		list_del(&p->link);
		kfree(p);
	}

	if (pending_total != 1 || leave_pending != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s queued %d pending ops, %d matching A-B LEAVEs (want exactly 1)\n",
		       name, pending_total, leave_pending);
		pass = false;
	}

	if (atomic_read(&amt_upstream_test_leave_emits) - leave_before != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s leave emit counter delta was %d (want 1)\n",
		       name, atomic_read(&amt_upstream_test_leave_emits) - leave_before);
		pass = false;
	}

	amt_cleanup_srcs(amt, &tunnel, gnode);

	if (gnode->nr_sources != 0 || tunnel.nr_sources != 0) {
		pr_err("amt: SELF-TEST FAILURE: %s cleanup did not remove A-B source (group=%u tunnel=%u)\n",
		       name, gnode->nr_sources, tunnel.nr_sources);
		pass = false;
	}

	if (atomic_read(&amt_upstream_test_leave_emits) - leave_before != 1) {
		pr_err("amt: SELF-TEST FAILURE: %s cleanup queued an extra upstream LEAVE\n",
		       name);
		pass = false;
	}

	source_removed = gnode->nr_sources == 0;
	if (!source_removed) {
		hlist_del_init_rcu(&snode->node);
		kfree(snode);
	}
	if (cancel_delayed_work_sync(&gnode->group_timer))
		dev_put(amt->dev);
	kfree(gnode);
	amt_selftest_free_pending(amt);

	return pass;
}
#endif /* CONFIG_IPV6 */

/*
 * Regression test for the INCLUDE->EXCLUDE filter_mode flip leak fixed
 * alongside this commit. Pre-fix, the IS_EX and TO_EX handlers flipped
 * filter_mode before source cleanup, so any (S, G) source in A-B (old
 * INCLUDE list but not the new EXCLUDE record) was destroyed after
 * amt_upstream_track's INCLUDE guard became false. The upstream
 * host-stack JOIN refcount stayed pinned forever.
 *
 * Drive both transition handlers and assert the A-B LEAVE is queued
 * exactly once before cleanup removes the old source.
 */
static void __init amt_ex_transition_self_test(void)
{
	struct net_device *test_dev;
	struct amt_dev *amt;
	bool pass;
	int i;

	pr_info("amt: running EX-transition self-test (IS_EX/TO_EX handlers)\n");

	test_dev = alloc_netdev(sizeof(*amt), "amtex%d",
				NET_NAME_UNKNOWN, amt_link_setup);
	if (!test_dev) {
		pr_err("amt: ex-transition alloc_netdev failed\n");
		return;
	}
	amt = netdev_priv(test_dev);
	amt->dev = test_dev;

	spin_lock_init(&amt->upstream_lock);
	spin_lock_init(&amt->upstream_pending_lock);
	INIT_LIST_HEAD(&amt->upstream_pending);
	INIT_WORK(&amt->upstream_work, amt_upstream_worker);
	for (i = 0; i < AMT_UPSTREAM_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&amt->upstream[i]);
#if IS_ENABLED(CONFIG_IPV6)
		INIT_HLIST_HEAD(&amt->upstream_v6[i]);
#endif
	}
	amt->hash_buckets = 8;
	amt->qrv = 2;
	amt->qi = 125;
	amt->qri = 10;
	atomic_set(&amt->upstream_setsockopt_slow_count, 0);
	atomic_set(&amt_upstream_test_leave_emits, 0);
	WRITE_ONCE(amt->upstream_active, true);

	pass = amt_ex_transition_run_case(amt, false);
	pass = amt_ex_transition_run_case(amt, true) && pass;
#if IS_ENABLED(CONFIG_IPV6)
	pass = amt_ex_transition_run_case_v6(amt, false) && pass;
	pass = amt_ex_transition_run_case_v6(amt, true) && pass;
#endif

	WRITE_ONCE(amt_upstream_test_suppress_queue, false);
	cancel_work_sync(&amt->upstream_work);
	amt_selftest_free_pending(amt);
	__amt_source_gc_work();

	if (pass)
#if IS_ENABLED(CONFIG_IPV6)
		pr_info("amt: ex-transition self-test PASS: IS_EX, TO_EX, IS_EX_v6, TO_EX_v6 each queue exactly one A-B LEAVE before cleanup\n");
#else
		pr_info("amt: ex-transition self-test PASS: IS_EX and TO_EX queue exactly one A-B LEAVE before cleanup\n");
#endif

	free_netdev(test_dev);
}
#endif /* AMT_TEST_ENABLED */

static int __init amt_init(void)
{
	int err;

	err = register_netdevice_notifier(&amt_notifier_block);
	if (err < 0)
		goto err;

	err = rtnl_link_register(&amt_link_ops);
	if (err < 0)
		goto unregister_notifier;

	amt_wq = alloc_workqueue("amt", WQ_UNBOUND, 0);
	if (!amt_wq) {
		err = -ENOMEM;
		goto rtnl_unregister;
	}

	spin_lock_init(&source_gc_lock);
	spin_lock_bh(&source_gc_lock);
	INIT_DELAYED_WORK(&source_gc_wq, amt_source_gc_work);
	mod_delayed_work(amt_wq, &source_gc_wq,
			 msecs_to_jiffies(AMT_GC_INTERVAL));
	spin_unlock_bh(&source_gc_lock);

#ifdef AMT_TEST_ENABLED
	amt_upstream_self_test();
	amt_lifecycle_self_test();
	amt_ex_transition_self_test();
#endif

	return 0;

rtnl_unregister:
	rtnl_link_unregister(&amt_link_ops);
unregister_notifier:
	unregister_netdevice_notifier(&amt_notifier_block);
err:
	pr_err("error loading AMT module loaded\n");
	return err;
}
late_initcall(amt_init);

static void __exit amt_fini(void)
{
	rtnl_link_unregister(&amt_link_ops);
	unregister_netdevice_notifier(&amt_notifier_block);
	cancel_delayed_work_sync(&source_gc_wq);
	__amt_source_gc_work();
	destroy_workqueue(amt_wq);
}
module_exit(amt_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for Automatic Multicast Tunneling (AMT)");
MODULE_AUTHOR("Taehee Yoo <ap420073@gmail.com>");
MODULE_ALIAS_RTNL_LINK("amt");
