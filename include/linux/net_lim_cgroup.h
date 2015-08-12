#ifndef _NET_LIM_CGROUP_H
#define _NET_LIM_CGROUP_H

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/rwlock_types.h>

struct net_lim_range_item {
	unsigned int start, end;
	struct list_head list;
};

struct net_lim_addr_item {
	u32 addr;
	struct list_head list;
};

struct net_lim_cgroup {
	struct cgroup_subsys_state css;

	/* inet_bind() available ports range */
	struct list_head port_ranges;

	/* inet_bind() available address range */
	struct list_head addrs;
};

struct net_lim_cgroup *css_net_lim(struct cgroup_subsys_state *css);
int net_lim_port_allowed(struct task_struct *tsk, unsigned int port);
int net_lim_addr_allowed(struct task_struct *tsk, u32 addr);
void net_lim_get_local_port_range(struct task_struct *tsk, int *low, int *high);
u32 net_lim_get_default_address(struct task_struct *tsk);

#endif
