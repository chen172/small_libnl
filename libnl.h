#if 1

//define in netlink-private/types.h
#if 0
struct nl_msg
{
	int			nm_protocol;
	int			nm_flags;
	struct sockaddr_nl	nm_src;
	struct sockaddr_nl	nm_dst;
	struct ucred		nm_creds;
	struct nlmsghdr *	nm_nlh;
	size_t			nm_size;
	int			nm_refcnt;
};
#endif

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
//implementation of nl_recvmsgs
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

//defined in msg.c
/********************************************************/
#if 0

static size_t default_msg_size;

static void __init init_msg_size(void)
{
	default_msg_size = getpagesize();
}

static struct nl_msg *__nlmsg_alloc(size_t len)
{
	struct nl_msg *nm;

	if (len < sizeof(struct nlmsghdr))
		len = sizeof(struct nlmsghdr);

	nm = calloc(1, sizeof(*nm));
	if (!nm)
		goto errout;

	nm->nm_refcnt = 1;

	nm->nm_nlh = calloc(1, len);
	if (!nm->nm_nlh)
		goto errout;

	nm->nm_protocol = -1;
	nm->nm_size = len;
	nm->nm_nlh->nlmsg_len = nlmsg_total_size(0);

	NL_DBG(2, "msg %p: Allocated new message, maxlen=%zu\n", nm, len);

	return nm;
errout:
	free(nm);
	return NULL;
}

/**
 * Allocate a new netlink message with the default maximum payload size.
 *
 * Allocates a new netlink message without any further payload. The
 * maximum payload size defaults to PAGESIZE or as otherwise specified
 * with nlmsg_set_default_size().
 *
 * @return Newly allocated netlink message or NULL.
 */
struct nl_msg *nlmsg_alloc(void)
{
	return __nlmsg_alloc(default_msg_size);
}
#endif


/*******************************************************/

// implementation of libnl nl_send_auto_complete

// don't need this function
int nl_sendmsg1(struct nl_sock *sk, struct nl_msg *msg, struct msghdr *hdr)
{
	struct nl_cb *cb;
	int ret;

	if (sk->s_fd < 0)
		return -NLE_BAD_SOCK;

	nlmsg_set_src(msg, &sk->s_local);

	cb = sk->s_cb;
	if (cb->cb_set[NL_CB_MSG_OUT])
		if ((ret = nl_cb_call(cb, NL_CB_MSG_OUT, msg)) != NL_OK)
			return ret;

	ret = sendmsg(sk->s_fd, hdr, 0);
	if (ret < 0)
		return -nl_syserr2nlerr(errno);

	//NL_DBG(4, "sent %d bytes\n", ret);
	return ret;
}

//This function is to construct msghdr, for sendmsg, address is from nl_sock, msg_iov is from iovec
int nl_send_iovec1(struct nl_sock *sk, struct nl_msg *msg, struct iovec *iov, unsigned iovlen)
{
	struct sockaddr_nl *dst;
	//struct ucred *creds;
	//The main thing do
	struct msghdr hdr = {
		.msg_name = (void *) &sk->s_peer,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = iov,
		.msg_iovlen = iovlen,
	};

	/* Overwrite destination if specified in the message itself, defaults
	 * to the peer address of the socket.
	 */
	//The netlink address is passed from nl_sock, not nl_msg
	dst = nlmsg_get_dst(msg);
	if (dst->nl_family == AF_NETLINK) {
		printf("dst's nl_family field is AF_NETLINK\n");
		hdr.msg_name = dst;
	} else {
		printf("dst's not nl_family field is AF_NETLINK\n");
	}

	#if 0
	/* Add credentials if present. */
	creds = nlmsg_get_creds(msg);
	if (creds != NULL) {
		char buf[CMSG_SPACE(sizeof(struct ucred))];
		struct cmsghdr *cmsg;

		hdr.msg_control = buf;
		hdr.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&hdr);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CREDENTIALS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
		memcpy(CMSG_DATA(cmsg), creds, sizeof(struct ucred));
	}
	#endif

	int ret;
	ret = sendmsg(sk->s_fd, &hdr, 0);
	if (ret < 0)
		return -nl_syserr2nlerr(errno);

	//NL_DBG(4, "sent %d bytes\n", ret);
	return ret;
	//return nl_sendmsg1(sk, msg, &hdr);
}

//This function is to construct struct iovec, iovec is from nl_msg, for struct msghdr
int nl_send1(struct nl_sock *sk, struct nl_msg *msg)
{
	struct nl_cb *cb = sk->s_cb;

	if (cb->cb_send_ow)
		return cb->cb_send_ow(sk, msg);
	else {
		struct iovec iov = {
			.iov_base = (void *) nlmsg_hdr(msg), //message address
			.iov_len = nlmsg_hdr(msg)->nlmsg_len,
		};

		return nl_send_iovec1(sk, msg, &iov, 1);
	}
}
/**
 * Finalize and transmit Netlink message
 * @arg sk		Netlink socket (required)
 * @arg msg		Netlink message (required)
 *
 * Finalizes the message by passing it to `nl_complete_msg()` and transmits it
 * by passing it to `nl_send()`.
 *
 * @callback This function triggers the `NL_CB_MSG_OUT` callback.
 *
 * @see nl_complete_msg()
 * @see nl_send()
 *
 * @return Number of bytes sent or a negative error code.
 */

//1.complete netlink message
//2.send the message
int nl_send_auto1(struct nl_sock *sk, struct nl_msg *msg)
{
	nl_complete_msg(sk, msg);

	return nl_send1(sk, msg);
}

//@deprecated Please use nl_send_auto()
int nl_send_auto_complete1(struct nl_sock *sk, struct nl_msg *msg)
{
	return nl_send_auto1(sk, msg);
}

//define in genl.c
/***************************************************************************/
//implementation of genlmsg_put
#if 0
/**
 * Add Generic Netlink headers to Netlink message
 * @arg msg		Netlink message object
 * @arg port		Netlink port or NL_AUTO_PORT
 * @arg seq		Sequence number of message or NL_AUTO_SEQ
 * @arg family		Numeric family identifier
 * @arg hdrlen		Length of user header
 * @arg flags		Additional Netlink message flags (optional)
 * @arg cmd		Numeric command identifier
 * @arg version		Interface version
 *
 * Calls nlmsg_put() on the specified message object to reserve space for
 * the Netlink header, the Generic Netlink header, and a user header of
 * specified length. Fills out the header fields with the specified
 * parameters.
 *
 * @par Example:
 * @code
 * struct nl_msg *msg;
 * struct my_hdr *user_hdr;
 *
 * if (!(msg = nlmsg_alloc()))
 * 	// ERROR
 *
 * user_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family_id,
 *                        sizeof(struct my_hdr), 0, MY_CMD_FOO, 0);
 * if (!user_hdr)
 * 	// ERROR
 * @endcode
 *
 * @see nlmsg_put()
 *
 * Returns Pointer to user header or NULL if an error occurred.
 */
void *genlmsg_put1(struct nl_msg *msg, uint32_t port, uint32_t seq, int family,
		  int hdrlen, int flags, uint8_t cmd, uint8_t version)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr hdr = {
		.cmd = cmd,
		.version = version,
	};

	nlh = nlmsg_put(msg, port, seq, family, GENL_HDRLEN + hdrlen, flags);
	if (nlh == NULL)
		return NULL;

	memcpy(nlmsg_data(nlh), &hdr, sizeof(hdr));
	//NL_DBG(2, "msg %p: Added generic netlink header cmd=%d version=%d\n",
	 //      msg, cmd, version);

	return nlmsg_data(nlh) + GENL_HDRLEN;
}

//define in msg.c
/**
 * Add a netlink message header to a netlink message
 * @arg n		netlink message
 * @arg pid		netlink process id or NL_AUTO_PID
 * @arg seq		sequence number of message or NL_AUTO_SEQ
 * @arg type		message type
 * @arg payload		length of message payload
 * @arg flags		message flags
 *
 * Adds or overwrites the netlink message header in an existing message
 * object. If \a payload is greater-than zero additional room will be
 * reserved, f.e. for family specific headers. It can be accesed via
 * nlmsg_data().
 *
 * @return A pointer to the netlink message header or NULL.
 */
struct nlmsghdr *nlmsg_put1(struct nl_msg *n, uint32_t pid, uint32_t seq,
			   int type, int payload, int flags)
{
	struct nlmsghdr *nlh;

	if (n->nm_nlh->nlmsg_len < NLMSG_HDRLEN)
		//BUG();

	nlh = (struct nlmsghdr *) n->nm_nlh;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_pid = pid;
	nlh->nlmsg_seq = seq;

	//NL_DBG(2, "msg %p: Added netlink header type=%d, flags=%d, pid=%d, "
		//  "seq=%d\n", n, type, flags, pid, seq);

	if (payload > 0 &&
	    nlmsg_reserve(n, payload, NLMSG_ALIGNTO) == NULL)
		return NULL;

	return nlh;
}
#endif
#endif
