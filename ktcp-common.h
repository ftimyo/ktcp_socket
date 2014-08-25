#ifndef TCP_COMMON
#define TCP_COMMON
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <net/tcp.h>
#include <linux/inetdevice.h>

typedef __be32 net_addr_t;

typedef struct ipt_entry {
	struct list_head list;
    net_addr_t ip;
    struct socket *socket;
} ipt_entry;

typedef void (*ktcp_user_ft)(struct socket*, net_addr_t);


struct socket* ktcp_ipt_sk(net_addr_t ip);

net_addr_t ktcp_ipt_ip(struct socket *sk);

net_addr_t ktcp_ip(const char *nic);

int ktcp_recv(struct socket *sk, void *buffer, int length);

int ktcp_iov_send(struct socket *sk, struct iovec *iov,
		size_t iovlen, size_t length);

int ktcp_send(struct socket *sk, void *buffer, size_t length);

int ktcp_connect(net_addr_t ip, ipt_entry** entry);

int ktcp_close(net_addr_t ip);

int ktcp_init(ktcp_user_ft handler);

int ktcp_exit(void);

#endif
