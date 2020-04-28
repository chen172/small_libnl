#if 1
//netlink-private/types.h中的定义
struct nl_sock
{
	struct sockaddr_nl	s_local;
	struct sockaddr_nl	s_peer;
	int			s_fd;
	int			s_proto;
	unsigned int		s_seq_next;
	unsigned int		s_seq_expect;
	int			s_flags;
	struct nl_cb *		s_cb;
	size_t			s_bufsize;
};

struct nl_cb
{
	nl_recvmsg_msg_cb_t	cb_set[NL_CB_TYPE_MAX+1];
	void *			cb_args[NL_CB_TYPE_MAX+1];

	nl_recvmsg_err_cb_t	cb_err;
	void *			cb_err_arg;

	/** May be used to replace nl_recvmsgs with your own implementation
	 * in all internal calls to nl_recvmsgs. */
	int			(*cb_recvmsgs_ow)(struct nl_sock *,
						  struct nl_cb *);

	/** Overwrite internal calls to nl_recv, must return the number of
	 * octets read and allocate a buffer for the received data. */
	int			(*cb_recv_ow)(struct nl_sock *,
					      struct sockaddr_nl *,
					      unsigned char **,
					      struct ucred **);

	/** Overwrites internal calls to nl_send, must send the netlink
	 * message. */
	int			(*cb_send_ow)(struct nl_sock *,
					      struct nl_msg *);

	int			cb_refcnt;
	/** indicates the callback that is currently active */
	enum nl_cb_type		cb_active;
};
#endif
//定义在netlink-private/netlink.h
static inline int nl_cb_call(struct nl_cb *cb, int type, struct nl_msg *msg)
{
	int ret;

	//给cb赋值
	cb->cb_active = type;
	//调用cb结构中的函数
	ret = cb->cb_set[type](msg, cb->cb_args[type]);
	cb->cb_active = __NL_CB_TYPE_MAX;
	return ret;
}
//定义在nl.c中的宏
#define NL_CB_CALL(cb, type, msg) \
do { \
	int err = nl_cb_call(cb, type, msg); \
	switch (err) { \
	case NL_OK: \
		err = 0; \
		break; \
	case NL_SKIP: \
		printf("go to skip\n"); \
	case NL_STOP: \
		printf("go to stop\n"); \
	default: \
		printf("go to out\n"); \
	} \
} while (0)

#if 1
//构建libnl需要的宏
#define NL_MSG_PEEK		(1<<3)
int nl_recv1(struct nl_sock *sk, struct sockaddr_nl *nla,
	    unsigned char **buf, struct ucred **creds)
{
	ssize_t n;
	int flags = 0;
	static int page_size = 0;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = (void *) nla,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	if (sk->s_flags & NL_MSG_PEEK)
		flags |= MSG_PEEK | MSG_TRUNC;
	
	//得到内存的页大小
	if (page_size == 0)
		page_size = getpagesize() * 4;
	iov.iov_len = sk->s_bufsize ? : page_size;
	iov.iov_base = malloc(iov.iov_len);

	
	
	n = recvmsg(sk->s_fd, &msg, flags);
	
	if (n == -1) {
		printf("recvmsg errro happened\n");
		return n;
	}
	if (n == 0) {
		printf("recvmsg zeros bytes\n");
		return n;
	}
	*buf = iov.iov_base;
	return n;
}
	
int nl_recvmsgs1(struct nl_sock *sk, struct nl_cb *cb)
{
	unsigned char *buf = NULL;
	struct nlmsghdr *hdr;
	int n;
	struct sockaddr_nl nla = {0};
	struct nl_msg *msg = NULL;
	//这个结构是什么？
	struct ucred *creds = NULL;
	n = nl_recv1(sk, &nla, &buf, &creds);
	hdr = (struct nlmsghdr *) buf;
	//printf("nl_recv1 recv %d bytes\n", n);
	while (nlmsg_ok(hdr, n)) {
		

		nlmsg_free(msg);
		msg = nlmsg_convert(hdr);
		if (!msg) {
			printf("msg error\n");
		}

		nlmsg_set_proto(msg, sk->s_proto);
		nlmsg_set_src(msg, &nla);

		/* Raw callback is the first, it gives the most control
		 * to the user and he can do his very own parsing. */
		if (cb->cb_set[NL_CB_MSG_IN])
			NL_CB_CALL(cb, NL_CB_MSG_IN, msg);

	}
	return 0;
}
#endif
