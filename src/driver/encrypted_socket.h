#ifndef __ENCRYPTED_SOCKET_H__
#define __ENCRYPTED_SOCKET_H__

enum {
	ENC_SOCK_OPEN = 1,
	ENC_SOCK_BOUND,
	ENC_SOCK_CLOSED,
};

struct encrypted_sock {
	struct sock sk;
};

#endif
