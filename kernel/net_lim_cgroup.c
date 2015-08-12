#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/net_lim_cgroup.h>
#include <linux/string.h>

#define RANGE_MAX_LEN 12
#define IP_ADDRESS_MAX_LEN 16
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static DEFINE_RWLOCK(net_lim_croup_rwlock);

struct net_lim_cgroup *css_net_lim(struct cgroup_subsys_state *css)
{
	return container_of(css, struct net_lim_cgroup, css);
}

/*
 * Clean list @list_ranges and deallocate all items.
 */
static void net_lim_range_clean(struct list_head *list_ranges)
{
	struct net_lim_range_item *walk, *tmp;

	list_for_each_entry_safe(walk, tmp, list_ranges, list) {
		list_del(&walk->list);
		kfree(walk);
	}
}

/*
 * Clean list @list_addrs and deallocate all items.
 */
static void net_lim_addrs_clean(struct list_head *list_addrs)
{
	struct net_lim_addr_item *walk, *tmp;

	list_for_each_entry_safe(walk, tmp, list_addrs, list) {
		list_del(&walk->list);
		kfree(walk);
	}
}

/*
 * Allocate new net_lim subsystem node.
 */
static struct cgroup_subsys_state *
net_lim_css_alloc(struct cgroup_subsys_state *parent)
{
	struct net_lim_cgroup *net_lim;

	net_lim = kzalloc(sizeof(struct net_lim_cgroup), GFP_KERNEL);
	if (!net_lim)
		return ERR_PTR(-ENOMEM);

	/* initialize ports ranges. */
	INIT_LIST_HEAD(&net_lim->port_ranges);

	/* initialize addrs ranges. */
	INIT_LIST_HEAD(&net_lim->addrs);

	return &net_lim->css;
}

/*
 * Deallocate memory of items in net_lim lists.
 */
static void net_lim_ranges_clean(struct net_lim_cgroup *net_lim)
{
	net_lim_range_clean(&net_lim->port_ranges);
	net_lim_addrs_clean(&net_lim->addrs);
}

/*
 * Free net_lim node.
 */
static void net_lim_css_free(struct cgroup_subsys_state *css)
{
	struct net_lim_cgroup *net_lim = css_net_lim(css);

	net_lim_ranges_clean(net_lim);
	kfree(net_lim);
}

/*
 * Validate and extract port range string.
 */
static int extract_port_range(char *str, unsigned int *start, unsigned int *end)
{
	char *tmp = str;

	if (strlen(str) > RANGE_MAX_LEN-1)
		return -ERANGE;

	if (strchr(tmp, '-') == NULL) {
		if (kstrtoint(str, 0, (int *)start))
			return -EINVAL;
		*end = *start;
	} else {
		tmp = strsep(&str, "-");

		if ((*tmp == '\0') ||
		                (str == NULL) ||
		                (*str == '\0'))
			return -EINVAL;

		if (kstrtoint(tmp, 0, (int *)start))
			return -EINVAL;
		if (kstrtoint(str, 0, (int *)end))
			return -EINVAL;
	}

	if ((*end < *start) ||
	                (*start < 1) ||
	                (*start > 65535) ||
	                (*end < 1) ||
	                (*end > 65535))
		return -ERANGE;

	return 0;
}

/*
* Validate and extract ip address from string.
*/
int extract_address(char *str, u32 *addr)
{
	if (strlen(str) > IP_ADDRESS_MAX_LEN)
		return -EINVAL;

	if (!in4_pton(str, -1, (u8 *)addr, -1, NULL)) {
		return -EINVAL;
	}

	return 0;
}

/*
* Aloccate memory and add low-high range to list.
*/
static int list_add_range(struct list_head *list_ranges, unsigned int low,
                          				unsigned int high)
{
	struct net_lim_range_item *range;

	range = kmalloc(sizeof(*range), GFP_KERNEL);
	if (!range)
		return -ENOMEM;

	range->start = low;
	range->end = high;
	list_add_tail(&range->list, list_ranges);
	return 0;
}

/*
* Aloccate memory and add address to list.
*/
static int list_add_address(struct list_head *list_addrs, u32 addr)
{
	struct net_lim_addr_item *addr_item;

	addr_item = kmalloc(sizeof(*addr_item), GFP_KERNEL);
	if (!addr_item)
		return -ENOMEM;

	addr_item->addr = addr;
	list_add_tail(&addr_item->list, list_addrs);
	return 0;
}

/*
* Parse string of ports and ranges.
*/
static int parse_ports_list(char *buf, struct list_head *list_ranges)
{
	char str[RANGE_MAX_LEN];
	char *s, *tmp;
	u32 low, high;
	int ret = 0;

	tmp = s = buf;
	while(*s++ != '\0') {
		if ((*s == ',') || (*s == '\0')) {
			if (s-tmp > RANGE_MAX_LEN)
				return -ERANGE;
			memset(&str[0], '\0', RANGE_MAX_LEN);
			strncpy(&str[0], tmp, s-tmp);

			/* Extract port or region. */
			if ((ret = extract_port_range(str, &low, &high)))
				return ret;

			if ((ret = list_add_range(list_ranges, low, high)))
				return ret;

			tmp = s + 1;
		}
	}

	return ret;
}

/*
* Parse string of addrs.
*/
static int parse_addrs_list(char *buf, struct list_head *list_addrs)
{
	char str[IP_ADDRESS_MAX_LEN];
	char *s, *tmp;
	u32 addr;
	int ret = 0;

	tmp = s = buf;
	while(*s++ != '\0') {
		if ((*s == ',') || (*s == '\0')) {
			if (s-tmp > IP_ADDRESS_MAX_LEN)
				return -EINVAL;
			memset(&str[0], '\0', IP_ADDRESS_MAX_LEN);
			strncpy(&str[0], tmp, s-tmp);

			/* Extract ip address from @str. */
			if ((ret = extract_address(str, &addr)))
				return ret;

			if ((ret = list_add_address(list_addrs, addr)))
				return ret;

			tmp = s + 1;
		}
	}
	return ret;
}

/*
* Write list of allowed ports.
*/
static ssize_t net_lim_cgroup_ports_write(struct kernfs_open_file *of,
                                     	char *buf, size_t nbytes, loff_t off)
{
	int retval = 0;
	char *buffer = strstrip(buf);
	struct net_lim_cgroup *net_lim = css_net_lim(of_css(of));
	LIST_HEAD(list_ranges);

	if (css_has_online_children(&net_lim->css))
		return -EINVAL;

	/* Don't apply cgroup port values. */
	if (*buffer == '\0') {
		net_lim_range_clean(&net_lim->port_ranges);
		return nbytes;
	}

	if ((retval = parse_ports_list(buffer, &list_ranges))) {
		net_lim_range_clean(&list_ranges);
		return retval;
	}

	/* Here we have valid list of port ranges. Clear existed list and
	* replace with new one. */
	write_lock(&net_lim_croup_rwlock);
	net_lim_range_clean(&net_lim->port_ranges);
	list_splice(&list_ranges, &net_lim->port_ranges);
	write_unlock(&net_lim_croup_rwlock);
	return nbytes;
}

/*
* Show list of allowed ports.
*/
static int net_lim_cgroup_ports_seq_show(struct seq_file *seq, void *v)
{
	struct net_lim_range_item *walk;
	struct cgroup_subsys_state *css = seq_css(seq);
	struct net_lim_cgroup *net_lim = css_net_lim(css);
	int comma = 0;

	read_lock(&net_lim_croup_rwlock);
	list_for_each_entry(walk, &net_lim->port_ranges, list) {
		if (comma++)
			seq_printf(seq, ",");
		if (walk->start == walk->end) {
			seq_printf(seq, "%d", walk->start);
		} else {
			seq_printf(seq, "%d-%d", walk->start, walk->end);
		}
	}
	read_unlock(&net_lim_croup_rwlock);
	if (comma)
		seq_printf(seq, "\n");
	return 0;
}

/*
* Show current local_port_range value.
*/
static int net_lim_cgroup_local_port_range_seq_show(struct seq_file *seq,
                                                    			void *v)
{
	struct net_lim_cgroup *net_lim = css_net_lim(seq_css(seq));
	struct net_lim_range_item *range;

	read_lock(&net_lim_croup_rwlock);
	if (list_empty(&net_lim->port_ranges))
		goto _unlock;

	range = list_last_entry(&net_lim->port_ranges,
	                        struct net_lim_range_item, list);

	seq_printf(seq, "%d-%d\n", range->start, range->end);

_unlock:
	read_unlock(&net_lim_croup_rwlock);
	return 0;
}

/*
* Write list of allowed addrs.
*/
static ssize_t net_lim_cgroup_addrs_write(struct kernfs_open_file *of,
                                     	char *buf, size_t nbytes, loff_t off)
{
	int retval = 0;
	char *buffer = strstrip(buf);
	struct net_lim_cgroup *net_lim = css_net_lim(of_css(of));
	LIST_HEAD(list_addrs);

	if (css_has_online_children(&net_lim->css))
		return -EINVAL;

	/* Don't apply cgroup values to limit bind() addresses. */
	if (*buffer == '\0') {
		net_lim_addrs_clean(&net_lim->addrs);
		// net_lim_list_clean(&net_lim->addrs, walk, tmp);
		return nbytes;
	}

	if ((retval = parse_addrs_list(buffer, &list_addrs))) {
		net_lim_addrs_clean(&list_addrs);
		return retval;
	}

	/* Here we have valid list of addrs. Clear existed list and
	* replace with new one. */
	write_lock(&net_lim_croup_rwlock);
	net_lim_addrs_clean(&net_lim->addrs);
	list_splice(&list_addrs, &net_lim->addrs);
	write_unlock(&net_lim_croup_rwlock);
	return nbytes;
}

/*
* Show list of allowed addrs.
*/
static int net_lim_cgroup_addrs_seq_show(struct seq_file *seq, void *v)
{
	struct net_lim_addr_item *walk;
	struct net_lim_cgroup *net_lim = css_net_lim(seq_css(seq));
	int wrote = 0;

	read_lock(&net_lim_croup_rwlock);
	list_for_each_entry(walk, &net_lim->addrs, list) {
		if (wrote++)
			seq_printf(seq, ",");
		seq_printf(seq, "%d.%d.%d.%d", NIPQUAD(walk->addr));
	}
	if (wrote)
		seq_printf(seq, "\n");
	read_unlock(&net_lim_croup_rwlock);
	return 0;
}

/*
* Show current default_address value.
*/
static int net_lim_cgroup_default_address_seq_show(struct seq_file *seq,
                                                    			void *v)
{
	struct net_lim_cgroup *net_lim = css_net_lim(seq_css(seq));
	struct net_lim_addr_item *addr_item = NULL;

	read_lock(&net_lim_croup_rwlock);
	if (list_empty(&net_lim->addrs))
		goto _unlock;

	addr_item = list_first_entry(&net_lim->addrs, struct net_lim_addr_item, list);
	seq_printf(seq, "%d.%d.%d.%d\n", NIPQUAD(addr_item->addr));

_unlock:
	read_unlock(&net_lim_croup_rwlock);
	return 0;
}


static struct cftype net_lim_files[] = {
	{
		.name = "ipv4.ports",
		.write = net_lim_cgroup_ports_write,
		.seq_show = net_lim_cgroup_ports_seq_show,
	},
	{
		.name = "ipv4.ip_local_port_range",
		.seq_show = net_lim_cgroup_local_port_range_seq_show,
	},
	{
		.name = "ipv4.addrs",
		.write = net_lim_cgroup_addrs_write,
		.seq_show = net_lim_cgroup_addrs_seq_show,
	},
	{
		.name = "ipv4.default_address",
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

int net_lim_port_allowed(struct task_struct *tsk, unsigned int port)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);
	struct net_lim_range_item *walk;
	int found = 0;

	read_lock(&net_lim_croup_rwlock);
	/* Don't apply cgroup rules if list is empty. */
	if (list_empty(&net_lim->port_ranges)) {
		found++;
		goto _unlock;
	}
	/* Check in list of ranges for allowed port. */
	list_for_each_entry(walk, &net_lim->port_ranges, list) {
 		if ((walk->start <= port) && (port <= walk->end)) {
 		        found++;
 		        goto _unlock;
 		}
	}
_unlock:
	read_unlock(&net_lim_croup_rwlock);
	return found;
}

int net_lim_addr_allowed(struct task_struct *tsk, u32 addr)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);
	struct net_lim_addr_item *walk;
	int found = 0;

	read_lock(&net_lim_croup_rwlock);
	/* Don't apply cgroup rules if list is empty. */
	if (list_empty(&net_lim->addrs)) {
		found++;
		goto _unlock;
	}
	/* Check in list of addrs for allowed addr. */
	list_for_each_entry(walk, &net_lim->addrs, list) {
 		if (walk->addr == addr) {
 			found++;
 		        goto _unlock;
 		}
	}
_unlock:
	read_unlock(&net_lim_croup_rwlock);
	return found;
}

void net_lim_get_local_port_range(struct task_struct *tsk, int *low, int *high)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);
	struct net_lim_range_item *range;

	read_lock(&net_lim_croup_rwlock);
	if (list_empty(&net_lim->port_ranges))
		goto _unlock;

	/* Use net_lim range values if list of allowed ports is not empty. */
	range = list_last_entry(&net_lim->port_ranges,
	                        struct net_lim_range_item, list);

	*low = range->start;
	*high = range->end;

_unlock:
	read_unlock(&net_lim_croup_rwlock);
}

u32 net_lim_get_default_address(struct task_struct *tsk)
{
	struct net_lim_cgroup *net_lim =
			css_net_lim(tsk->cgroups->subsys[net_lim_cgrp_id]);
	u32 addr;
	struct net_lim_addr_item *addr_item;


	read_lock(&net_lim_croup_rwlock);
	if (list_empty(&net_lim->addrs)) {
		addr = 0;
		goto _unlock;
	}

	/* Use net_lim range values if list of allowed ports is not empty. */
	addr_item = list_first_entry(&net_lim->addrs, struct net_lim_addr_item,
	                             					list);
	addr = addr_item->addr;
_unlock:
	read_unlock(&net_lim_croup_rwlock);
	return addr;
}
