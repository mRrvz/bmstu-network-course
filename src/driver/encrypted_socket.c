#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <linux/if_arp.h>
#include <net/raw.h>

#include "encrypted_socket.h"

static inline struct encrypted_sock *encrypted_sk(struct sock *sk)
{
	return (struct encrypted_sock *)sk;
}

static int encrypted_sock_release(struct socket *socket)
{
	struct sock *sk = socket->sk;

	lock_sock(sk);
	sock_orphan(sk);
	skb_queue_purge(&sk->sk_receive_queue);
	release_sock(sk);

	sock_put(sk);

	return 0;
}

static int encrypted_sock_bind(struct socket *socket, struct sockaddr *addr, int addr_len)
{
	struct sock *sk = socket->sk;
	(void)sk;

	return inet_bind(socket, addr, addr_len);
}

static int encrypted_sock_getname(struct socket *socket, struct sockaddr *addr, int perr)
{
	struct sock *sk = socket->sk;
	(void)sk;

	return 0;
}

static int encrypted_sock_recvmsg(struct socket *socket, struct msghdr *msg, size_t len, int flags)
{
	struct sock *sk = socket->sk;

	if (sk->sk_state == ENC_SOCK_CLOSED)
		return 0;

	return sock_common_recvmsg(socket, msg, len, flags);
}

static int encrypted_sock_sendmsg(struct socket *socket, struct msghdr *msg, size_t len)
{
	struct sock *sk = socket->sk;

	return sk->sk_prot->sendmsg(sk, msg, len);
}

static int encrypted_sock_setsockopt(struct socket *socket, int level, int optname,
				     sockptr_t optval, unsigned int len)
{
	struct sock *sk = socket->sk;

    return sk->sk_prot->setsockopt(sk, level, optname, optval, len);
}

static int encrypted_sock_getsockopt(struct socket *socket, int level, int optname,
				     char __user *optval, int __user *optlen)
{
	return 0;
}

static int encrypted_connect(struct socket *socket, struct sockaddr *vaddr,
				      int sockaddr_len, int flags)
{
	struct sock *sk = socket->sk;

    return sk->sk_prot->connect(sk, vaddr, sockaddr_len);
}

static const struct proto_ops encrypted_sock_ops = {
	.family = PF_ENC,
	.owner = THIS_MODULE,
	.release = encrypted_sock_release,
	.ioctl = sock_no_ioctl,
	.bind = encrypted_sock_bind,
	.getname = encrypted_sock_getname,
	.sendmsg = encrypted_sock_sendmsg,
	.recvmsg = encrypted_sock_recvmsg,
	.poll = datagram_poll,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = encrypted_sock_setsockopt,
	.getsockopt = encrypted_sock_getsockopt,
	.connect = encrypted_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.mmap = sock_no_mmap,
};

static int encrypted_sock_create(struct net *net, struct socket *sock, int proto, int kern)
{
	struct sock *sk;

    /*
	if (proto != 0) {
		pr_err("Invalid protocol %d\n", proto); 
		return -EPROTONOSUPPORT;
	}
    */
	
	if (sock->type != SOCK_RAW) {
		pr_err("Encrypted sockets currently supports only SOCK_RAW type\n");
		return -ESOCKTNOSUPPORT;
	}

	sk = sk_alloc(net, AF_ENC, GFP_KERNEL, &raw_prot, kern);
	if (!sk) {
		pr_err("Failed to allocate socket\n");
		return -ENOMEM;
	}

	sock_init_data(sock, sk);

	sock->ops = &encrypted_sock_ops;
	sock->state = SS_UNCONNECTED;
	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = proto;
	sk->sk_state = ENC_SOCK_OPEN;

	return 0;
};

static const struct net_proto_family encrypted_sock_family_ops = {
	.owner = THIS_MODULE,
	.family = PF_ENC,
	.create = encrypted_sock_create,
};

static int encrypted_socket_init(void)
{
	int err;
	err = sock_register(&encrypted_sock_family_ops);
	if (err)
		pr_err("Failed to register encrypted socket (%d)\n", err);

	return err;
}

static void encrypted_socket_exit(void)
{
	sock_unregister(PF_ENC);
}

module_init(encrypted_socket_init);
module_exit(encrypted_socket_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Romanov");
