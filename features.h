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
			nl80211_has_split_wiphy = true;
		}
	}

	return NL_SKIP;
}
