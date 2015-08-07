#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/net_lim_cgroup.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

enum range_type {
	PORT_RANGE,
	ADDR_RANGE
};

static DEFINE_MUTEX(net_lim_cgroup_mutex);
static DEFINE_RWLOCK(net_lim_croup_rwlock);

struct net_lim_cgroup *css_net_lim(struct cgroup_subsys_state *css)
{
	return container_of(css, struct net_lim_cgroup, css);
}

static void net_lim_range_clean(struct list_head *list_ranges)
{
	struct net_lim_range_item *ex, *tmp;

	list_for_each_entry_safe(ex, tmp, list_ranges, list) {
		list_del_rcu(&ex->list);
		kfree_rcu(ex, rcu);
	}
}

static int net_lim_range_add(struct net_lim_range_item *range,
                             struct list_head *list_ranges,
                             enum range_type type)
{
	struct net_lim_range_item *excopy, *walk = NULL;
	struct list_head *new_list = NULL;
	int insert_before = 0;

	lockdep_assert_held(&net_lim_cgroup_mutex);

	excopy = kmemdup(range, sizeof(*range), GFP_KERNEL);
	if (!excopy)
		return -ENOMEM;

	new_list = list_ranges;
	list_for_each_entry(walk, list_ranges, list) {
		new_list = &walk->list;
		if ((( type = PORT_RANGE ) && (walk->start > excopy->start)) ||
		                (( type = ADDR_RANGE ) &&
		                 (htonl(walk->start) > htonl(excopy->start)))) {
			insert_before = 1;
			break;
		}
		if (walk->start == excopy->start) {
			kfree(excopy);
			return -EINVAL;
		}
	}

	if (insert_before) {
		list_add_tail_rcu(&excopy->list, new_list);
	} else {
		list_add_rcu(&excopy->list, new_list);
	}
	return 0;
}

static void set_port_allow_behavoir(struct net_lim_cgroup *net_lim)
{
	struct net_lim_range_item range;

	range.start = 0;
	range.end = 65535;
	net_lim_range_clean(&net_lim->port_ranges);
	net_lim_range_add(&range, &net_lim->port_ranges, PORT_RANGE);
	net_lim->port_behavior = NET_LIM_DEFAULT_ALLOW;
}

static void set_addr_allow_behavoir(struct net_lim_cgroup *net_lim)
{
	struct net_lim_range_item range;

	range.start = htonl(INADDR_ANY);
	range.end = htonl(INADDR_ANY);
	net_lim_range_clean(&net_lim->addr_ranges);
	net_lim_range_add(&range, &net_lim->addr_ranges, ADDR_RANGE);
	net_lim->addr_behavior = NET_LIM_DEFAULT_ALLOW;
}

/*
 * Allocate new net_lim cgroup.
 */
static struct cgroup_subsys_state *
net_lim_css_alloc(struct cgroup_subsys_state *parent)
{
	struct net_lim_cgroup *net_lim;

	net_lim = kzalloc(sizeof(struct net_lim_cgroup), GFP_KERNEL);
	if (!net_lim)
		return ERR_PTR(-ENOMEM);

	// TODO: copy parents settings (?)
	/* initialize ports ranges. */
	INIT_LIST_HEAD(&net_lim->port_ranges);
	set_port_allow_behavoir(net_lim);

	/* initialize addrs ranges. */
	INIT_LIST_HEAD(&net_lim->addr_ranges);
	set_addr_allow_behavoir(net_lim);

	/* initialize local_port_range. Proxying sysctl values by default. */
	net_lim->local_port_range[0] = -1;
	net_lim->local_port_range[1] = -1;

	/* initialize default bind address as INADDR_ANY */
	net_lim->default_address = htonl(INADDR_ANY);

	return &net_lim->css;
}

static void net_lim_ranges_clean(struct net_lim_cgroup *net_lim)
{
	net_lim_range_clean(&net_lim->port_ranges);
	net_lim_range_clean(&net_lim->addr_ranges);
}

static void net_lim_css_free(struct cgroup_subsys_state *css)
{
	struct net_lim_cgroup *net_lim = css_net_lim(css);

	net_lim_ranges_clean(net_lim);
	kfree(net_lim);
}

/*
 * Validate and extract port range string.
 */
int extract_port_range(char *str, u32 *start, u32 *end)
{
	char *tmp = str;

	if (strlen(str) > 11)
		return 1;

	if (strchr(tmp, '-') == NULL) {
		if (kstrtoint(str, 0, (int *)start))
			return 1;
		*end = *start;
	} else {
		tmp = strsep(&str, "-");

		if ((*tmp == '\0') ||
		                (str == NULL) ||
		                (*str == '\0'))
			return 1;

		if (kstrtoint(tmp, 0, (int *)start))
			return 1;
		if (kstrtoint(str, 0, (int *)end))
			return 1;
	}

	if ((*end < *start) ||
	                (*start < 0) ||
	                (*start > 65535) ||
	                (*end < 0) ||
	                (*end > 65535))
		return 1;

	return 0;
}

/*
* Validate and extract address string.
*/
int extract_addr_range(char *str, u32 *start, u32 *end)
{
	if (strlen(str) > 15)
		return 1;

	if (!in4_pton(str, -1, (u8 *)start, -1, NULL)) {
		return 1;
	}

	*end = 0;

	return 0;
}

/*
 * Called under net_lim_cgroup_mutex.
 * Check existed range intersection with new one.
 */
static int net_lim_range_check_intersect(struct net_lim_range_item *range,
                struct list_head *list_ranges)
{
	struct net_lim_range_item *walk;

	lockdep_assert_held(&net_lim_cgroup_mutex);

	list_for_each_entry(walk, list_ranges, list) {
		if (((walk->start <= range->start)
		                && (range->start <= walk->end))
		                || ((walk->start <= range->end)
		                    && (range->end <= walk->end)))
			return 1;
	}

	return 0;
}

/*
 * Called under net_lim_cgroup_mutex.
 * Remove range item from list.
 */
static int net_lim_range_rm(struct net_lim_range_item *range,
                            struct list_head *list_ranges)
{
	struct net_lim_range_item *walk, *tmp;
	int del_count = 0;

	lockdep_assert_held(&net_lim_cgroup_mutex);

	list_for_each_entry_safe(walk, tmp, list_ranges, list) {
		if ((walk->start == range->start) &&
		                (walk->end == range->end)) {
			list_del_rcu(&walk->list);
			kfree_rcu(walk, rcu);
			del_count++;
		}
	}
	return del_count;
}

/*
 * Update network limits for `ports` and `addrs`.
 */
static int net_lim_cgroup_update_limits(struct net_lim_cgroup *net_lim,
                                        int filetype, char *buffer)
{
	int ret, rc = 0;
	struct net_lim_range_item ex;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (*buffer == '\0')
		return -EINVAL;

	memset(&ex, 0, sizeof(ex));

	if (css_has_online_children(&net_lim->css))
		return -EINVAL;

	switch (filetype) {
	case NET_LIM_PORTS_ALLOW:
		if ((strlen(buffer) == 1) && (*buffer == 'a')) {
			set_port_allow_behavoir(net_lim);
			break;
		} else {
			/* Call extract_port_range() here for param check. */
			if (extract_port_range(buffer, &ex.start, &ex.end))
				return -EINVAL;
			/* We already in ALLOW behavior - skip other actions. */
			if (net_lim->port_behavior == NET_LIM_DEFAULT_ALLOW)
				break;
			if (net_lim_range_check_intersect(&ex,
			                                  &net_lim->port_ranges))
				return -EINVAL;
			net_lim->port_behavior = NET_LIM_DEFAULT_NONE;
			rc = net_lim_range_add(&ex, &net_lim->port_ranges,
			                       PORT_RANGE);
		}

		break;

	case NET_LIM_PORTS_DENY:
		if ((strlen(buffer) == 1) && (*buffer == 'a')) {
			net_lim_range_clean(&net_lim->port_ranges);
			net_lim->port_behavior = NET_LIM_DEFAULT_DENY;
		} else {
			/* Call extract_port_range() here for param check. */
			if (extract_port_range(buffer, &ex.start, &ex.end))
				return -EINVAL;

			/* We already in DENY behavior - skip other actions. */
			if (net_lim->port_behavior == NET_LIM_DEFAULT_DENY)
				break;

			ret = net_lim_range_rm(&ex, &net_lim->port_ranges);
			/* Reset behavior to NONE if changed something. */
			if (ret)
				net_lim->port_behavior = NET_LIM_DEFAULT_NONE;
		}
		break;

	case NET_LIM_ADDRS_ALLOW:
		if ((strlen(buffer) == 1) && (*buffer == 'a')) {
			set_addr_allow_behavoir(net_lim);
			break;
		} else {
			/* Call extract_addr_range() here for param check. */
			if (extract_addr_range(buffer, &ex.start, &ex.end))
				return -EINVAL;
			/* Support 0.0.0.0 as alias for allow-default. */
			if (ex.start == htonl(INADDR_ANY)) {
				set_addr_allow_behavoir(net_lim);
				break;
			}
			/* We already in ALLOW behavior - skip other actions. */
			if (net_lim->addr_behavior == NET_LIM_DEFAULT_ALLOW)
				break;

			net_lim->addr_behavior = NET_LIM_DEFAULT_NONE;
			rc = net_lim_range_add(&ex, &net_lim->addr_ranges,
			                       ADDR_RANGE);
		}
		break;

	case NET_LIM_ADDRS_DENY:
		if ((strlen(buffer) == 1) && (*buffer == 'a')) {
			net_lim_range_clean(&net_lim->addr_ranges);
			net_lim->addr_behavior = NET_LIM_DEFAULT_DENY;
		} else {
			/* Call extract_addr_range() here for param check. */
			if (extract_addr_range(buffer, &ex.start, &ex.end))
				return -EINVAL;
			/* Support 0.0.0.0 as alias for deny-default. */
			if (ex.start == htonl(INADDR_ANY)) {
				net_lim_range_clean(&net_lim->addr_ranges);
				net_lim->addr_behavior = NET_LIM_DEFAULT_DENY;
				break;
			}
			/* We already in DENY behavior - skip other actions. */
			if (net_lim->addr_behavior == NET_LIM_DEFAULT_DENY)
				break;
			ret = net_lim_range_rm(&ex, &net_lim->addr_ranges);
			/* Reset behavior to NONE if changed something. */
			if (ret)
				net_lim->addr_behavior = NET_LIM_DEFAULT_NONE;
		}
		break;
	default:
		rc = -EINVAL;
	}
	return rc;
}

static ssize_t net_lim_cgroup_limits_write(struct kernfs_open_file *of,
                char *buf, size_t nbytes, loff_t off)
{
	int retval;

	mutex_lock(&net_lim_cgroup_mutex);
	retval = net_lim_cgroup_update_limits(css_net_lim(of_css(of)),
	                                      of_cft(of)->private, strstrip(buf));
	mutex_unlock(&net_lim_cgroup_mutex);
	return retval ? : nbytes;
}

static int net_lim_cgroup_ports_seq_show(struct seq_file *seq, void *v)
{
	struct net_lim_range_item *range;
	struct cgroup_subsys_state *css = seq_css(seq);
	struct net_lim_cgroup *net_lim = css_net_lim(css);

	rcu_read_lock();
	list_for_each_entry_rcu(range, &net_lim->port_ranges, list) {
		if (range->start == range->end) {
			seq_printf(seq, "%d\n", range->start);
		} else {
			seq_printf(seq, "%d-%d\n", range->start, range->end);
		}
		// first = 0;
	}
	rcu_read_unlock();

	return 0;
}

static int net_lim_cgroup_addrs_seq_show(struct seq_file *seq, void *v)
{
	struct net_lim_range_item *range;
	struct cgroup_subsys_state *css = seq_css(seq);
	struct net_lim_cgroup *net_lim = css_net_lim(css);

	rcu_read_lock();
	list_for_each_entry_rcu(range, &net_lim->addr_ranges, list) {
		seq_printf(seq, "%d.%d.%d.%d\n", NIPQUAD(range->start));
	}
	rcu_read_unlock();
	return 0;
}

static ssize_t net_lim_cgroup_local_port_range_write(struct kernfs_open_file *of,
                                     char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct net_lim_cgroup *net_lim = css_net_lim(css);
	int ports[2];
	char *sbuf = strstrip(buf);

	/* Check should we use sysctl values instead of cgroups. See doc for
	details. */
	if ((*sbuf == '-') && (*(sbuf+1) == '1') && (*(sbuf+2) == '\0')) {
		ports[0] = ports[1] = -1;
	} else {
		if (extract_port_range(sbuf, &ports[0], &ports[1]))
			return -EINVAL;
	}

	write_lock(&net_lim_croup_rwlock);
	net_lim->local_port_range[0] = ports[0];
	net_lim->local_port_range[1] = ports[1];
	write_unlock(&net_lim_croup_rwlock);
	return nbytes;
}

/*
* Show current local_port_range value.
*/
static int net_lim_cgroup_local_port_range_seq_show(struct seq_file *seq,
                                                    			void *v)
{
	struct cgroup_subsys_state *css = seq_css(seq);
	struct net_lim_cgroup *net_lim = css_net_lim(css);

	read_lock(&net_lim_croup_rwlock);
	if (net_lim->local_port_range[0] == -1) {
		seq_printf(seq, "-1\n");
	} else {
		seq_printf(seq, "%d-%d\n", net_lim->local_port_range[0],
		           net_lim->local_port_range[1]);
	}
	read_unlock(&net_lim_croup_rwlock);

	return 0;
}
/*
 * Default address to substitute in case INADDR_ANY
 */
static ssize_t net_lim_cgroup_default_address_write(struct kernfs_open_file *of,
                                     	char *buf, size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct net_lim_cgroup *net_lim = css_net_lim(css);
	char *sbuf = strstrip(buf);
	u32 addr;

	if (!in4_pton(sbuf, -1, (u8 *)&addr, -1, NULL)) {
		return -EINVAL;
	}

	write_lock(&net_lim_croup_rwlock);
	net_lim->default_address = addr;
	write_unlock(&net_lim_croup_rwlock);
	return nbytes;
}

/*
* Show current default_address value.
*/
static int net_lim_cgroup_default_address_seq_show(struct seq_file *seq,
                                                    			void *v)
{
	struct cgroup_subsys_state *css = seq_css(seq);
	struct net_lim_cgroup *net_lim = css_net_lim(css);

	read_lock(&net_lim_croup_rwlock);
	seq_printf(seq, "%d.%d.%d.%d\n", NIPQUAD(net_lim->default_address));
	read_unlock(&net_lim_croup_rwlock);

	return 0;
}

static struct cftype net_lim_files[] = {
	{
		.name = "ipv4.ports.allow",
		.write = net_lim_cgroup_limits_write,
		.private = NET_LIM_PORTS_ALLOW,
	},
	{
		.name = "ipv4.ports.deny",
		.write = net_lim_cgroup_limits_write,
		.private = NET_LIM_PORTS_DENY,
	},
	{
		.name = "ipv4.ports.list",
		.seq_show = net_lim_cgroup_ports_seq_show,
	},
	{
		.name = "ipv4.addrs.allow",
		.write = net_lim_cgroup_limits_write,
		.private = NET_LIM_ADDRS_ALLOW,
	},
	{
		.name = "ipv4.addrs.deny",
		.write = net_lim_cgroup_limits_write,
		.private = NET_LIM_ADDRS_DENY,
	},
	{
		.name = "ipv4.addrs.list",
		.seq_show = net_lim_cgroup_addrs_seq_show,
	},
	{
		.name = "ipv4.ip_local_port_range",
		.write = net_lim_cgroup_local_port_range_write,
		.seq_show = net_lim_cgroup_local_port_range_seq_show,
	},
	{
		.name = "ipv4.default_address",
		.write = net_lim_cgroup_default_address_write,
		.seq_show = net_lim_cgroup_default_address_seq_show,
	},
	{ }	/* terminate */
};

struct cgroup_subsys net_lim_cgrp_subsys = {
	.css_alloc	= net_lim_css_alloc,
	.css_free	= net_lim_css_free,
	.legacy_cftypes	= net_lim_files,
	.dfl_cftypes	= net_lim_files,
};

int net_lim_check_port(struct task_struct *tsk, unsigned int port)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);
	struct net_lim_range_item *walk;

	rcu_read_lock();
	list_for_each_entry(walk, &net_lim->port_ranges, list) {
 		if ((walk->start <= port) && (port <= walk->end))
 		        return 1;
	}
	rcu_read_unlock();
	return 0;
}

int net_lim_check_addr(struct task_struct *tsk, u32 addr)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);
	struct net_lim_range_item *walk;

	rcu_read_lock();
	list_for_each_entry(walk, &net_lim->addr_ranges, list) {
 		if ((walk->start == htonl(INADDR_ANY)) || (walk->start == addr))
 		        return 1;
	}
	rcu_read_unlock();
	return 0;
}

void net_lim_get_local_port_range(struct task_struct *tsk,
	   						int *low, int *high)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);

	read_lock(&net_lim_croup_rwlock);
	*low = net_lim->local_port_range[0];
	*high = net_lim->local_port_range[1];
	read_unlock(&net_lim_croup_rwlock);
}

u32 net_lim_get_default_address(struct task_struct *tsk)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);
	u32 addr;

	rcu_read_lock();
	addr = net_lim->default_address;
	rcu_read_unlock();
	return addr;
}
