#include "ktcp-common.h"
#include <linux/inet.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#define TCP_PORT    8888

typedef void (*sk_ready_ft)(struct sock*, int);

typedef struct ipt_entry {
	struct list_head list;
    net_addr_t ip;
    struct socket *socket;
} ipt_entry;

/*-------ipt data and ops>-------*/
static struct list_head ipt;

static ktcp_user_ft ipt_poll_handler;

static inline int ktcp_destroy_socket(struct socket*);

static rwlock_t	ipt_lock;

static int __ipt_add_entry(void *entry)
{
	write_lock(&ipt_lock);
	list_add_tail(&(((ipt_entry*)entry)->list), &ipt);
	write_unlock(&ipt_lock);
	return 0;
}

static inline ipt_entry* ipt_add_entry(struct socket *sk, net_addr_t ip)
{
	ipt_entry *entry;
	entry = kzalloc(sizeof(ipt_entry), GFP_ATOMIC);
	if (entry) {
		entry->socket = sk;
		entry->ip = ip;
		kthread_run(__ipt_add_entry, entry, "ipt_add");
	}
	return entry;
}

static int __ipt_del_entry(void *entry)
{
	int ret;
	write_lock(&ipt_lock);
	ret = ktcp_destroy_socket(((ipt_entry*)entry)->socket);
	if (ret)
		pr_emerg("%s:%d:error in release sock\n", __func__, __LINE__);
	list_del(&(((ipt_entry*)entry)->list));
	kfree(entry);
	write_unlock(&ipt_lock);
	return 0;
}
static inline void ipt_del_entry(ipt_entry *entry)
{
	if (entry) {
		kthread_run(__ipt_del_entry, entry, "ipt_del");
	}
}

static inline int ipt_print_ip(void)
{
	ipt_entry *entry;
	int cnt = 0;
	read_lock(&ipt_lock);
	list_for_each_entry(entry, &ipt, list) {
		cnt++;
		pr_info("%pI4\n", &entry->ip);
	}
	read_unlock(&ipt_lock);

	return cnt;
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
		pr_emerg("%s:remove ipt entry for %pI4\n", __func__, &entry->ip);
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

static inline int ktcp_create_socket(struct socket **sk)
{
    int ret =  sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, sk);
	if (origSk == NULL)
		origSk = (*sk)->sk->sk_data_ready;
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

int ktcp_connect(net_addr_t ip)
{
	int ret = 0;
	struct sockaddr_in addr;
	struct socket *sk;
	if (ipt_ip_entry(ip))
		return ret;
	if ((ret = ktcp_create_socket(&sk)))
		return ret;

	ret = sk->ops->connect(sk, ktcp_sockaddr(&addr, ip),
			sizeof(struct sockaddr_in), 0);
	sk->sk->sk_data_ready = ktcp_data_ready;
	if (ret) {
		sock_release(sk);
		pr_emerg("%s:%d:fail to connect to %pI4\n", __func__, __LINE__, &ip);
		return ret;
	}

	ipt_add_entry(sk, ip);

	pr_emerg("connect to %pI4\n", &ip);

	return ret;
}

void ktcp_close(net_addr_t ip)
{
	pr_emerg("%s:%d closing socket for ip %pI4\n", __func__, __LINE__, &ip);
	ipt_del_entry(ipt_ip_entry(ip));
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

	ret = ktcp_create_socket(&new_sk);

	if ((ret))
		return ret;
	ret = sk->ops->accept(sk, new_sk, 0);

	new_sk->sk->sk_data_ready = ktcp_data_ready;

	if (ret < 0) {
		sock_release(new_sk);
		return ret;
	}

	new_sk->ops->getname(new_sk, (struct sockaddr*)&addr, &addr_len, 1);

	pr_emerg("accpet conn from %pI4\n", &addr.sin_addr.s_addr);

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

	ktcp_create_socket(&listen_socket);

	isock = inet_csk(listen_socket->sk);

	listen_socket->sk->sk_reuse = 1;

	ktcp_bind(listen_socket);

	ktcp_listen(listen_socket, 64);

	listen_socket->sk->sk_data_ready = ktcp_req_ready;

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
static u8	*trash = NULL;
static atomic_t clients = ATOMIC_INIT(0);
static atomic_t iterations = ATOMIC_INIT(1000000);

net_addr_t ip_aton(const char *buf)
{
	char ip_string[20] = {0};
	sscanf(buf, "%s\n", ip_string);
	return in_aton(ip_string);
}

int client_thread(void *ipp)
{
	struct socket *sk;
	int i, cnt;
	net_addr_t ip; 

	atomic_inc(&clients);

	ip = *(net_addr_t*)ipp;
	kfree(ipp);

	cnt = atomic_read(&iterations);
	sk = ktcp_ipt_sk(ip);

	if (sk == NULL) {
		atomic_dec(&clients);
		return 0;
	}

	pr_info("%s:%d start sending to %pI4: itr %d\n", __func__, __LINE__, &ip, cnt);

	for (i = 0; i < cnt; ++i) {
		ktcp_send(sk, trash, PAGE_SIZE);
	}
	pr_emerg("%s:%d finish sending task\n", __func__, __LINE__);

	atomic_dec(&clients);
	return 0;
}
/*-----------------sysfs>--------------------------*/
static struct kobject *control = NULL;

ssize_t iterations_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t count = sprintf(buf, "%d\n", atomic_read(&iterations));
	return count;
}

ssize_t iterations_set(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	int itr = 0;
	sscanf(buf, "%d\n", &itr);
	atomic_set(&iterations, itr);
	return count;
}

ssize_t clients_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t count = sprintf(buf, "%d\n", atomic_read(&clients));
	return count;
}

ssize_t clients_add(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	net_addr_t *ip = kzalloc(sizeof(net_addr_t), GFP_ATOMIC);
	*ip = ip_aton(buf);

	if (NULL == kthread_run(client_thread, (void*)ip, "ktcp_client"))
		kfree(ip);
	return count;
}

ssize_t ip_table_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t count = sprintf(buf, "%d\n", ipt_print_ip());
	return count;
}
ssize_t ip_table_add(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	net_addr_t ip = ip_aton(buf);
	ktcp_connect(ip);
	return count;
}

static struct kobj_attribute attr_ip_table= __ATTR(ip_table, 0666, ip_table_show, ip_table_add);
static struct kobj_attribute attr_clients= __ATTR(clients, 0666, clients_show, clients_add);
static struct kobj_attribute attr_iterations= __ATTR(iterations, 0666, iterations_show, iterations_set);

static struct attribute *attrs[] = {
	&attr_ip_table.attr,
	&attr_clients.attr,
	&attr_iterations.attr,
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};
/*-----------------<sysfs--------------------------*/

void dummie_handler(struct socket *sk, net_addr_t ip)
{
	int bytes;
	bytes = ktcp_recv(sk, trash, PAGE_SIZE);
}

int init_module(void)
{
	int ret;

	ktcp_init(dummie_handler);

	trash = kmalloc(PAGE_SIZE, GFP_KERNEL);
#if 0
	control = kobject_create_and_add("ktcp_control", &(((struct module*)(THIS_MODULE))->mkobj.kobj));
#endif
	control = kobject_create_and_add("ktcp_control", NULL);

	if (control)
		ret = sysfs_create_group(control, &attr_group);

	return 0;
}

void cleanup_module()
{
	if (control)
		kobject_del(control);
	kfree(trash);
	ktcp_exit();
}

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Timothy Yo <yyou4@binghamton.edu>");
MODULE_DESCRIPTION("Sector hash Block Device");
