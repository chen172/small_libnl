#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/netlink.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <linux/nl80211.h>

//有的操作系统没有定义这些宏，所以需要在这里定义
/* support for extack if compilation headers are too old */
#ifndef NETLINK_EXT_ACK
#define NETLINK_EXT_ACK 11
enum nlmsgerr_attrs {
	NLMSGERR_ATTR_UNUSED,
	NLMSGERR_ATTR_MSG,
	NLMSGERR_ATTR_OFFS,
	NLMSGERR_ATTR_COOKIE,

	__NLMSGERR_ATTR_MAX,
	NLMSGERR_ATTR_MAX = __NLMSGERR_ATTR_MAX - 1
};
#endif
#ifndef NLM_F_CAPPED
#define NLM_F_CAPPED 0x100
#endif
#ifndef NLM_F_ACK_TLVS
#define NLM_F_ACK_TLVS 0x200
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

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
	printf("nl_recv1 recv %d bytes\n", n);
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
struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
	CIB_WDEV,
};

enum id_input {
	II_NONE,
	II_NETDEV,
	II_PHY_NAME,
	II_PHY_IDX,
	II_WDEV,
};

struct cmd {
	char *name;
	char *args;
	char *help;
	enum nl80211_commands cmd;
	int nl_msg_flags;
	int hidden;
	enum command_identify_by idby;
	/*
	 * The handler should return a negative error code,
	 * zero on success, 1 if the arguments were wrong.
	 * Return 2 iff you provide the error message yourself.
	 */
	int (*handler)(struct nl80211_state *state,
		       struct nl_msg *msg,
		       int argc, char **argv,
		       enum id_input id);
	struct cmd *(*selector)(int argc, char **argv);
	struct cmd *parent;
};

// some callback function
static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)err - 1;
	int len = nlh->nlmsg_len;
	struct nlattr *attrs;
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	int *ret = arg;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);

	*ret = err->error;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	if (len <= ack_len)
		return NL_STOP;

	attrs = (void *)((unsigned char *)nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG]) {
		len = strnlen((char *)nla_data(tb[NLMSGERR_ATTR_MSG]),
			      nla_len(tb[NLMSGERR_ATTR_MSG]));
		fprintf(stderr, "kernel reports: %*s\n", len,
			(char *)nla_data(tb[NLMSGERR_ATTR_MSG]));
	}

	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

// this callback is a litlle special
static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

int valid_handler(struct nl_msg *msg, void *arg)
{
	if (registered_handler)
		return registered_handler(msg, registered_handler_data);

	return NL_OK;
}

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}
	

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	err = 1;
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK,
		   NETLINK_EXT_ACK, &err, sizeof(err));

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	//printf("id is %d\n", state->nl80211_id);
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}


static int handle_info(struct nl80211_state *state,
		       struct nl_msg *msg,
		       int argc, char **argv,
		       enum id_input id);

struct cmd cmds[2];


static int __handle_cmd(struct nl80211_state *state, enum id_input idby,
			int argc, char **argv, const struct cmd **cmdout)
{
	
	struct cmd *cmd, *match = NULL, *sectcmd;
	//cmd = malloc(sizeof(struct cmd));
	struct nl_cb *cb;
	struct nl_cb *s_cb;
	struct nl_msg *msg;
	int err, i;

	if (argc <= 1 && idby != II_NONE)
		return 1;
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}
	
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	
	// construct cmd
	s_cb = nl_cb_alloc(NL_CB_DEFAULT);
	
	if (!cb || !s_cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		err = 2;
		goto out;
	}
	
	
	//printf("name is %s\n", *argv);
	for (i = 0; i < 2; i++)
		if (strcmp(cmds[i].name, *argv) == 0)
			cmd = &cmds[i];
	
	//在这里构造了消息,狗造了两次
	genlmsg_put(msg, 0, 0, state->nl80211_id, 0,
		    cmd->nl_msg_flags, cmd->cmd, 0);
	
	
	//主要是设置回调函数
	err = cmd->handler(state, msg, argc, argv, idby);
	if (err)
		goto out;

	nl_socket_set_cb(state->nl_sock, s_cb);
	
	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	//在这里fd是没问题的，但在nl80211_init有问题
	printf("The fd is %d\n", state->nl_sock->s_fd);
	while (err > 0)
		nl_recvmsgs1(state->nl_sock, cb);

 out:
	nl_cb_put(cb);
	nl_cb_put(s_cb);
	nlmsg_free(msg);
	return err;
	return 0;
}

static int print_phy_handler(struct nl_msg *msg, void *arg)
{
	return 0;
}

static int print_feature_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	bool print = (unsigned long)arg;
#define maybe_printf(...) do { if (print) printf(__VA_ARGS__); } while (0)

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]) {
		uint32_t feat = nla_get_u32(tb_msg[NL80211_ATTR_PROTOCOL_FEATURES]);

		maybe_printf("nl80211 features: 0x%x\n", feat);
		if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP) {
			maybe_printf("\t* split wiphy dump\n");
			//nl80211_has_split_wiphy = true;
		}
	}

	return NL_SKIP;
}
static int handle_info(struct nl80211_state *state,
		       struct nl_msg *msg,
		       int argc, char **argv,
		       enum id_input id)
{
	char *feat_args[] = { "features", "-q" };
	int err;

	err = __handle_cmd(state, II_NONE, 2, feat_args, NULL);
	register_handler(print_phy_handler, NULL);
	return 0;
}

static int handle_features(struct nl80211_state *state, struct nl_msg *msg,
			   int argc, char **argv, enum id_input id)
{
	unsigned long print = argc == 0 || strcmp(argv[0], "-q");
	//在这里注册解析消息用的handler,
	register_handler(print_feature_handler, (void *)print);
	return 0;
}
int main(int argc, char **argv)
{
	struct nl80211_state nlstate;
	int err;
	const struct cmd *cmd = NULL;
	enum id_input idby;

	//初始化所有的命令
	cmds[0].name = "phy";
	cmds[0].args = NULL;
	cmds[0].cmd = NL80211_CMD_GET_WIPHY;
	cmds[0].nl_msg_flags = NLM_F_DUMP;
	cmds[0].idby = CIB_NONE;
	cmds[0].handler = handle_info;
	cmds[0].help = NULL;

	cmds[1].name = "features";
	cmds[1].args = "";
	cmds[1].cmd = NL80211_CMD_GET_PROTOCOL_FEATURES;
	cmds[1].nl_msg_flags = 0;
	cmds[1].idby = CIB_NONE;
	cmds[1].handler = handle_features;
	cmds[1].help = "";
	
	
	argv++;
	err = nl80211_init(&nlstate);
	
	idby = II_NONE;
	
	err = __handle_cmd(&nlstate, idby, argc, argv, &cmd);
	return 0;
}
