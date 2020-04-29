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
//#include <linux/nl80211.h>
#include "nl80211.h"
#include "ieee80211.h"
#include "phy.h"


//libnl中recvmsgs的实现
#include "libnl.h"


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

//iw中的命令数据结构，根据这个命令，可以构造发送的消息结构体，这个结构体可以定义一个函数
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

/***********************************************************************************/



//和套接字相关的回调函数
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

//多个消息结束时，会调用这个回调函数来处理
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

//这样可以让每个命令需要的valid_handler不一样，让函数作为一个变量
static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

//因为对每个命令,valid_handler函数都是不一样的
//这个回调函数是用来处理有用的消息的
int valid_handler(struct nl_msg *msg, void *arg)
{
	if (registered_handler)
		return registered_handler(msg, registered_handler_data);

	return NL_OK;
}



//TO DO
//构建命令的时候要在这里加入cmd结构体中的函数
/***********************************************************************************/
//phy命令结构体定义的函数
static bool nl80211_has_split_wiphy = false;
static int __handle_cmd(struct nl80211_state *state, enum id_input idby,
			int argc, char **argv, const struct cmd **cmdout);

static int handle_info(struct nl80211_state *state,
		       struct nl_msg *msg,
		       int argc, char **argv,
		       enum id_input id)
{
	
	char *feat_args[] = { "features", "-q" };
	int err;

	err = __handle_cmd(state, II_NONE, 2, feat_args, NULL);
	if (!err && nl80211_has_split_wiphy) {
		nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP);
		nlmsg_hdr(msg)->nlmsg_flags |= NLM_F_DUMP;
	}
	
	register_handler(print_phy_handler, NULL);

	return 0;
}

#include "features.h"
//feature cmd function
static int handle_features(struct nl80211_state *state, struct nl_msg *msg,
			   int argc, char **argv, enum id_input id)
{
	unsigned long print = argc == 0 || strcmp(argv[0], "-q");
	register_handler(print_feature_handler, (void *)print);
	return 0;
}
/***********************************************************************************/




//main函数中的函数
/***********************************************************************************/
#define N 2
struct cmd cmds[N];
//初始化所有的命令，可以在这里添加命令
void init_cmds(void)
{
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

}

//初始化nl80211,得到nl80211的id,和nl80211通信
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

//处理命令行参数
static int __handle_cmd(struct nl80211_state *state, enum id_input idby,
			int argc, char **argv, const struct cmd **cmdout)
{
	
	struct cmd *cmd, *match = NULL, *sectcmd;
	struct nl_cb *cb;
	struct nl_msg *msg;
	const char *section;
	int err, i;

	if (argc <= 1 && idby != II_NONE)
		return 1;
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}
	
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		err = 2;
		goto out;
	}
	
	section = *argv;
	
	argv++;
	//找到匹配的命令
	for (i = 0; i < N; i++)
		if (strcmp(cmds[i].name, section) == 0)
			cmd = &cmds[i];
	
	//构造消息体
	genlmsg_put(msg, 0, 0, state->nl80211_id, 0,
		    cmd->nl_msg_flags, cmd->cmd, 0);
	
	
	//通过cmd结构体中的函数来设置和套接字相关的回调函数，主要是设置和这个命令相关的valid_handler
	err = cmd->handler(state, msg, argc, argv, idby);
	if (err)
		goto out;

	
	//发送消息
	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0)
		goto out;

	
	err = 1;
	//在这里添加回调函数，对所有的命令来说，error_handler，finish_handler，ack_handler都是一样的。
	//但是valid_handler这个回调函数是不一样的，所以会在前面通过cmd->handler来设置对应命令的这个回调函数
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	
	//接收消息，然后处理消息
	while (err > 0)
		nl_recvmsgs1(state->nl_sock, cb);

 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}
/***********************************************************************************/


int main(int argc, char **argv)
{
	struct nl80211_state nlstate;
	int err;
	const struct cmd *cmd = NULL;
	enum id_input idby;

	//初始化所有的命令
	init_cmds();
	
	argv++;
	err = nl80211_init(&nlstate);
	
	idby = II_NONE;
	
	err = __handle_cmd(&nlstate, idby, argc, argv, &cmd);
	return 0;
}
