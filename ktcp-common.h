#ifndef TCP_COMMON
#define TCP_COMMON
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <net/tcp.h>
#include <linux/inetdevice.h>

typedef __be32 net_addr_t;

typedef struct ktcp_request {
	void *bio;
	void *page;
	int  bytes;	/*bytes left*/
} ktcp_request;



typedef void (*ktcp_user_ft)(struct socket*, net_addr_t, ktcp_request*);


struct socket* ktcp_ipt_sk(net_addr_t ip);

net_addr_t ktcp_ipt_ip(struct socket *sk);

/*get ip address of the NIC*/
net_addr_t ktcp_ip(const char *nic);

/*ktcp_recv: if return val is 0, while lenght is not 0,
 * peer must close the connection.
 * Therefore we should close the connection too*/
int ktcp_recv(struct socket *sk, void *buffer, int length, int flag);

int ktcp_iov_send(struct socket *sk, struct iovec *iov,
		size_t iovlen, size_t length);

int ktcp_send(struct socket *sk, void *buffer, size_t length);

int ktcp_connect(net_addr_t ip);

void ktcp_close(net_addr_t ip);

int ktcp_init(ktcp_user_ft handler, ktcp_user_ft pending_handler);

int ktcp_exit(void);

#endif

