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

#define NET_LIM_ALLOW 0
#define NET_LIM_DENY 1

#define NET_LIM_PORTS_ALLOW 0
#define NET_LIM_PORTS_DENY 1
#define NET_LIM_ADDRS_ALLOW 2
#define NET_LIM_ADDRS_DENY 3

enum net_lim_behavior {
	NET_LIM_DEFAULT_NONE,
	NET_LIM_DEFAULT_ALLOW,
	NET_LIM_DEFAULT_DENY,
};

struct net_lim_range_item {
	u32 start, end;
	struct list_head list;
	struct rcu_head rcu;
};

struct net_lim_cgroup {
	struct cgroup_subsys_state	css;

	/* inet_bind() available ports range */
	struct list_head port_ranges;
	enum net_lim_behavior port_behavior;

	/* inet_bind() available address range */
	struct list_head addr_ranges;
	enum net_lim_behavior addr_behavior;

	/* ephemeral ports range */
	int local_port_range[2];

	/* default bind address used when try to bind on INADDR_ANY */
	u32 default_address;
};

struct net_lim_cgroup *css_net_lim(struct cgroup_subsys_state *css);
int net_lim_check_port(struct task_struct *tsk, unsigned int port);
int net_lim_check_addr(struct task_struct *tsk, u32 addr);
void net_lim_get_local_port_range(struct task_struct *tsk,
	   						int *low, int *high);
u32 net_lim_get_default_address(struct task_struct *tsk);
#endif
