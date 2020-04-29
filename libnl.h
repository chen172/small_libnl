#if 1

#define DEBUG 0
//netlink-private/types.h中的定义

#define NL_NO_AUTO_ACK		(1<<4)
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
	err = nl_cb_call(cb, type, msg); \
	switch (err) { \
	case NL_OK: \
		err = 0; \
		break; \
	case NL_SKIP: \
		goto skip; \
	case NL_STOP: \
		goto stop; \
	default: \
		goto out; \
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
	int n, err = 0, multipart = 0, interrupted = 0, nrecv = 0;
	struct sockaddr_nl nla = {0};
	struct nl_msg *msg = NULL;
	//这个结构是什么？
	struct ucred *creds = NULL;

continue_reading:
	n = nl_recv1(sk, &nla, &buf, &creds);
	hdr = (struct nlmsghdr *) buf;
	
	while (nlmsg_ok(hdr, n)) {
		

		nlmsg_free(msg);
		//把消息放在libnl中的nl_msg结构体中
		msg = nlmsg_convert(hdr);
		if (!msg) {
			printf("msg error\n");
		}

		nlmsg_set_proto(msg, sk->s_proto);
		nlmsg_set_src(msg, &nla);
	
		/* messages terminates a multipart message, this is
		 * usually the end of a message and therefore we slip
		 * out of the loop by default. the user may overrule
		 * this action by skipping this packet. */
		//多个消息在这里被终结	
		if (hdr->nlmsg_type == NLMSG_DONE) {
			#if DEBUG
			printf("1111message terminates a multipart messag, going to call NL_CB_FINISH\n");
			#endif
			multipart = 0;
			/** Last message in a series of multi part messages received */
			//接收到了最后的消息
			//回调函数的行为
			//跳到skip,设置handle_cmd中的变量err为0,结束handle_cmd
			if (cb->cb_set[NL_CB_FINISH])
				NL_CB_CALL(cb, NL_CB_FINISH, msg);
		}
		/* Message to be ignored, the default action is to
		 * skip this message if no callback is specified. The
		 * user may overrule this action by returning
		 * NL_PROCEED. */
		//被忽略的消息，handle_cmd没有设置相关的回调函数
		else if (hdr->nlmsg_type == NLMSG_NOOP) {
			#if DEBUG
			printf("2222Message to be ignored, go to skip\n");
			#endif
			//没有设置这个回调函数,跳到skip
			if (cb->cb_set[NL_CB_SKIPPED])
				NL_CB_CALL(cb, NL_CB_SKIPPED, msg);
			else
				goto skip;
		}
		 /* Message carries a nlmsgerr */
		//错误的消息
		else if (hdr->nlmsg_type == NLMSG_ERROR) {
			#if DEBUG
			printf("3333wrong message, going to call NL_CB_ACK\n");
			#endif
			struct nlmsgerr *e = nlmsg_data(hdr);
			/** Message is an acknowledge */
			//消息是acknowledge
			//回调函数的行为是
			//退出这个接收消息并处理的函数，设置handle_cmd中的变量err为0,结束handle_cmd
			if (cb->cb_set[NL_CB_ACK])
				NL_CB_CALL(cb, NL_CB_ACK, msg);
		} //最后是有效的消息
		else {
			/* Valid message (not checking for MULTIPART bit to
			 * get along with broken kernels. NL_SKIP has no
			 * effect on this.  */
			/** Message is valid */
			//消息是有效的
			//回调函数处理完消息后，会返回，去执行接下来的代码
			#if DEBUG
			printf("4444Valid message, going to call NL_CB_VALID\n");
			#endif
			if (cb->cb_set[NL_CB_VALID])
				NL_CB_CALL(cb, NL_CB_VALID, msg);
		}
skip:
		err = 0;
		hdr = nlmsg_next(hdr, &n);
	}
	
	nlmsg_free(msg);
	free(buf);
	free(creds);
	buf = NULL;
	msg = NULL;
	creds = NULL;

	if (multipart) {
		/* Multipart message not yet complete, continue reading */
		goto continue_reading;
	}
stop:
	err = 0;
out:
	nlmsg_free(msg);
	free(buf);
	free(creds);

	if (interrupted)
		err = -NLE_DUMP_INTR;

	if (!err)
		err = nrecv;

	return err;
}
#endif
