#include "ktcp-common.h"
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#define TCP_PORT    8888
typedef void (*sk_ready_ft)(struct sock*, int);
/*-------ipt data and ops>-------*/
static struct list_head ipt;
static ktcp_user_ft ipt_poll_handler;
static inline int ktcp_destroy_socket(struct socket*);
static rwlock_t	ipt_lock;

static inline ipt_entry* ipt_add_entry(struct socket *sk, net_addr_t ip)
{
	ipt_entry *entry;
	write_lock(&ipt_lock);
	entry = kzalloc(sizeof(ipt_entry), GFP_ATOMIC);
	entry->socket = sk;
	entry->ip = ip;
	list_add_tail(&entry->list, &ipt);
	write_unlock(&ipt_lock);
	return entry;
}

static inline int ipt_del_entry(ipt_entry *entry)
{
	int ret; 
	write_lock(&ipt_lock);
	ret = ktcp_destroy_socket(entry->socket);
	if (ret)
		pr_emerg("%s:%d:error in release sock\n", __func__, __LINE__);
	list_del(&entry->list);
	kfree(entry);
	write_unlock(&ipt_lock);
	return ret;
}

static inline void ipt_print_ip(void)
{
	ipt_entry *entry;
	read_lock(&ipt_lock);
	list_for_each_entry(entry, &ipt, list) {
		pr_info("%pI4\n", &entry->ip);
	}
	read_unlock(&ipt_lock);
}
static inline ipt_entry* ipt_ip_entry(net_addr_t ip)
{
	ipt_entry *entry;
	read_lock(&ipt_lock);
	list_for_each_entry(entry, &ipt, list) {
		if (entry->ip == ip) {
			read_unlock(&ipt_lock);
			return entry;
		}
	}
	read_unlock(&ipt_lock);
	return NULL;
}

static inline ipt_entry* ipt_sk_entry(struct socket *sk)
{
	ipt_entry *entry;
	read_lock(&ipt_lock);
	list_for_each_entry(entry, &ipt, list) {
		if (entry->socket == sk) {
			read_unlock(&ipt_lock);
			return entry;
		}
	}
	read_unlock(&ipt_lock);
	return NULL;
}

static int	ipt_sk_ready_check(void)
{
	ipt_entry *entry;
	read_lock(&ipt_lock);
	list_for_each_entry(entry, &ipt, list) {
		if (!skb_queue_empty(&entry->socket->sk->sk_receive_queue)) {
			read_unlock(&ipt_lock);
			return 1;
		}
	}
	read_unlock(&ipt_lock);
	return 0;
}

static void ipt_poll(void)
{
	ipt_entry *entry;
	read_lock(&ipt_lock);
	list_for_each_entry(entry, &ipt, list) {
		if (skb_queue_empty(&entry->socket->sk->sk_receive_queue)) {
			continue;
		}
		ipt_poll_handler(entry->socket, entry->ip);
	}
	read_unlock(&ipt_lock);
}

static inline void ipt_init(ktcp_user_ft handler)
{
	INIT_LIST_HEAD(&ipt);
	rwlock_init(&ipt_lock);
	ipt_poll_handler = handler;
}

static inline void ipt_exit(void)
{
	ipt_entry *entry, *safe;
	write_lock(&ipt_lock);
	list_for_each_entry_safe(entry, safe, &ipt, list) {
		ktcp_destroy_socket(entry->socket);
		list_del(&entry->list);
		kfree(entry);
	}
	write_unlock(&ipt_lock);
}

/*-------ipt data and ops<-------*/

/*-------ktcp common data and ops>-------*/

static sk_ready_ft origSk = NULL;
static struct task_struct *ktcp_server_lwp = NULL;
static struct task_struct *ktcp_poll_lwp = NULL;

static void ktcp_req_ready(struct sock *sk, int bytes)
{
	origSk(sk, bytes);
	wake_up_process(ktcp_server_lwp);
}
static void ktcp_data_ready(struct sock *sk, int bytes)
{
	origSk(sk, bytes);
	wake_up_process(ktcp_poll_lwp);
}

static inline int ktcp_create_socket(struct socket **sk, sk_ready_ft ready)
{
    int ret =  sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, sk);
	if (origSk == NULL)
		origSk = (*sk)->sk->sk_data_ready;
	if (ready)
		(*sk)->sk->sk_data_ready = ready;
	return ret;
}

static inline int ktcp_destroy_socket(struct socket *sk)
{
	int ret = sk->ops->release(sk);
	sock_release(sk);
	return ret;
}

static inline struct sockaddr* ktcp_sockaddr(struct sockaddr_in *addr,
		net_addr_t ip)
{
	addr->sin_family = AF_INET;
	addr->sin_port = htons(TCP_PORT);
	addr->sin_addr.s_addr = ip;

	return (struct sockaddr*)addr;
}

static inline void ktcp_msghdr(struct msghdr *msg, struct iovec *iov,
		size_t iovlen)
{
	msg->msg_name = NULL;
	msg->msg_namelen = 0;
	msg->msg_iov = iov;
	msg->msg_iovlen = iovlen;
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_flags = 0;
}

struct socket* ktcp_ipt_sk(net_addr_t ip)
{
	return ipt_ip_entry(ip)->socket;
}

net_addr_t ktcp_ipt_ip(struct socket *sk)
{
	return ipt_sk_entry(sk)->ip;
}

net_addr_t ktcp_ip(const char *nic)
{
    struct in_ifaddr *ifa = NULL;
    struct net_device *dev;
    net_addr_t ret = 0;

    dev = __dev_get_by_name(&init_net, nic);
    if (!dev) {
        BUG_ON(!dev);
        goto done;
    }

    for (ifa = ((struct in_device *) dev->ip_ptr)->ifa_list; ifa;
            ifa = ifa->ifa_next) {
        if (strcmp(nic, ifa->ifa_label) == 0) {
            ret = ifa->ifa_local;
            break;
        }
	}
done:
    return ret;
}

int ktcp_recv(struct socket *sk, void *buffer, int length)
{
	struct msghdr msg;
	struct iovec iov;
	int bytes;

#ifndef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
#endif

	iov.iov_base = buffer;
	iov.iov_len = length;

	ktcp_msghdr(&msg, &iov, 1);

#ifndef KSOCKET_ADDR_SAFE
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	bytes = sock_recvmsg(sk, &msg, length, MSG_WAITALL);
#ifndef KSOCKET_ADDR_SAFE
	set_fs(old_fs);
#endif
	return bytes;
}

int ktcp_iov_send(struct socket *sk, struct iovec *iov,
		size_t iovlen, size_t length)
{
    struct msghdr msg;
	int len;

#ifndef KSOCKET_ADDR_SAFE
	mm_segment_t old_fs;
#endif

	ktcp_msghdr(&msg, iov, iovlen);

#ifndef KSOCKET_ADDR_SAFE
	old_fs = get_fs();
	set_fs(KERNEL_DS);
#endif
	len = sock_sendmsg(sk, &msg, length);
#ifndef KSOCKET_ADDR_SAFE
	set_fs(old_fs);
#endif

	return len;
}

int ktcp_send(struct socket *sk, void *buffer, size_t length)
{
	struct iovec iov;

	iov.iov_base = buffer;
	iov.iov_len = length;

	return ktcp_iov_send(sk, &iov, 1, length);
}

int ktcp_connect(net_addr_t ip, ipt_entry** entry)
{
	int ret = 0;
	struct sockaddr_in addr;
	struct socket *sk;
	*entry = NULL;
	if (ipt_ip_entry(ip))
		return ret;
	if ((ret = ktcp_create_socket(&sk, ktcp_data_ready)))
		return ret;

	ret = sk->ops->connect(sk, ktcp_sockaddr(&addr, ip),
			sizeof(struct sockaddr_in), 0);
	if (ret) {
		sock_release(sk);
		return ret;
	}
	pr_emerg("connect to %pI4\n", &ip);
	if (entry)
		*entry = ipt_add_entry(sk, ip);
	return ret;
}

int ktcp_close(net_addr_t ip)
{
	return ipt_del_entry(ipt_ip_entry(ip));
}

static int ktcp_bind(struct socket *sk)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(TCP_PORT),
		.sin_addr.s_addr = INADDR_ANY
	};
	return sk->ops->bind(sk, (struct sockaddr*)&addr,
			sizeof(struct sockaddr_in));
}

static int ktcp_listen(struct socket *sk, int backlog)
{
	if ((unsigned)backlog > SOMAXCONN)
		backlog = SOMAXCONN;
	return sk->ops->listen(sk, backlog);
}

static int ktcp_accept(struct socket *sk, ipt_entry** entry)
{
	struct sockaddr_in addr;
	struct socket *new_sk = NULL;
	int ret = 0;
	int addr_len = 0;
	*entry = NULL;

	ret = ktcp_create_socket(&new_sk, ktcp_data_ready);

	if ((ret))
		return ret;
	ret = sk->ops->accept(sk, new_sk, 0);

	if (ret < 0) {
		sock_release(new_sk);
		return ret;
	}

	pr_emerg("accpet conn from %pI4\n", &addr.sin_addr.s_addr);
	
	new_sk->ops->getname(new_sk, (struct sockaddr*)&addr, &addr_len, 1);

	if (ipt_ip_entry(addr.sin_addr.s_addr)) {
		ktcp_destroy_socket(new_sk);
		return ret;
	}

	*entry = ipt_add_entry(new_sk, addr.sin_addr.s_addr);

	return ret;
}

static int ktcp_poll(void* dummie)
{
	wait_queue_head_t wq;
	init_waitqueue_head(&wq);

	while (!kthread_should_stop()) {
		wait_event_interruptible(wq, ipt_sk_ready_check()||
				kthread_should_stop());
		ipt_poll();
	}
	return 0;
}

static int ktcp_server(void *dummie)
{
	wait_queue_head_t wq;
	struct inet_connection_sock *isock;
	struct socket *listen_socket;

	init_waitqueue_head(&wq);

	ktcp_create_socket(&listen_socket, ktcp_req_ready);

	isock = inet_csk(listen_socket->sk);

	listen_socket->sk->sk_reuse = 1;

	ktcp_bind(listen_socket);

	ktcp_listen(listen_socket, 64);

	while (!kthread_should_stop()) {
		ipt_entry *entry;
		wait_event_interruptible(wq, 
				(!reqsk_queue_empty(&isock->icsk_accept_queue))||
				kthread_should_stop());

		if (kthread_should_stop())
			break;
		
		ktcp_accept(listen_socket, &entry);
	}

	ktcp_destroy_socket(listen_socket);

	return 0;
}

int ktcp_init(ktcp_user_ft handler)
{
	ipt_init(handler);
	ktcp_poll_lwp = kthread_run(ktcp_poll, NULL, "ktcp_poll");
	ktcp_server_lwp = kthread_run(ktcp_server, NULL, "ktcp_server");
	return 0;
}

int ktcp_exit()
{
	kthread_stop(ktcp_poll_lwp);
	kthread_stop(ktcp_server_lwp);
	ipt_exit();
	return 0;
}
/*------------------module only--------------------*/
/*-----------------sysfs>--------------------------*/
static struct kobject *control = NULL;

static char ip_string[100] = {0};
static net_addr_t ip_peer;
static atomic_t client_on = ATOMIC_INIT(0);
static int	client_sends = 0;

static u8	*trash = NULL;

int client_connect(void *dummie)
{
	ktcp_connect(ip_peer, NULL);
	ipt_print_ip();
	return 0;
}

int client_thread(void *dummie)
{
	int i = 0;
	struct socket *sk = ktcp_ipt_sk(ip_peer);
	if (sk == NULL) {
		atomic_set(&client_on, 0);
		return 0;
	}
	for (; i < client_sends; ++i) {
		ktcp_send(sk, trash, PAGE_SIZE);
	}

	atomic_set(&client_on, 0);
	return 0;
}

ssize_t show_client_status(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t count = sprintf(buf,"%d\n", atomic_read(&client_on));
	return count;
}

ssize_t start_client_thread(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	int i;
	if (atomic_read(&client_on) != 0)
		return count;
	sscanf(buf, "%d\n", &i);
	if (i <= 0)
		return count;
	client_sends = i;
	atomic_set(&client_on, 1);
	kthread_run(client_thread, NULL, "client_thread");
	return count;
}

ssize_t ip_peer_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t count = snprintf(buf, 50, "%pI4\n", &ip_peer);
	return count;
}
ssize_t ip_peer_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	sscanf(buf, "%s\n", ip_string);
	ip_peer = in_aton(ip_string);
	kthread_run(client_connect, NULL, "client_con");
	return count;
}

static struct kobj_attribute attr_ip_peer = __ATTR(ip_peer, 0666, ip_peer_show, ip_peer_store);
static struct kobj_attribute attr_client = __ATTR(client, 0666, show_client_status, start_client_thread);

static struct attribute *attrs[] = {
	&attr_ip_peer.attr,
	&attr_client.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};
/*-----------------<sysfs--------------------------*/

void dummie_handler(struct socket *sk, net_addr_t ip)
{
	ktcp_recv(sk, trash, PAGE_SIZE);
}

int init_module(void)
{
	int ret;
	ktcp_init(dummie_handler);
	trash = kmalloc(PAGE_SIZE, GFP_KERNEL);
	control = kobject_create_and_add("ktcp_control", &(((struct module*)(THIS_MODULE))->mkobj.kobj));
	if (control)
		ret = sysfs_create_group(control, &attr_group);

	return 0;
}

void cleanup_module()
{
	if (control)
		kobject_del(control);
	ktcp_exit();
}

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Timothy Yo <yyou4@binghamton.edu>");
MODULE_DESCRIPTION("Sector hash Block Device");
