static void print_flag(const char *name, int *open)
{
	if (!*open)
		printf(" (");
	else
		printf(", ");
	printf("%s", name);
	*open = 1;
}

//定义在iw的iw.h中
#define BIT(x) (1ULL<<(x))
//定义在iw的util.c中
void print_ht_capability(__u16 cap)
{
#define PRINT_HT_CAP(_cond, _str) \
	do { \
		if (_cond) \
			printf("\t\t\t" _str "\n"); \
	} while (0)

	printf("\t\tCapabilities: 0x%02x\n", cap);

	PRINT_HT_CAP((cap & BIT(0)), "RX LDPC");
	PRINT_HT_CAP((cap & BIT(1)), "HT20/HT40");
	PRINT_HT_CAP(!(cap & BIT(1)), "HT20");

	PRINT_HT_CAP(((cap >> 2) & 0x3) == 0, "Static SM Power Save");
	PRINT_HT_CAP(((cap >> 2) & 0x3) == 1, "Dynamic SM Power Save");
	PRINT_HT_CAP(((cap >> 2) & 0x3) == 3, "SM Power Save disabled");

	PRINT_HT_CAP((cap & BIT(4)), "RX Greenfield");
	PRINT_HT_CAP((cap & BIT(5)), "RX HT20 SGI");
	PRINT_HT_CAP((cap & BIT(6)), "RX HT40 SGI");
	PRINT_HT_CAP((cap & BIT(7)), "TX STBC");

	PRINT_HT_CAP(((cap >> 8) & 0x3) == 0, "No RX STBC");
	PRINT_HT_CAP(((cap >> 8) & 0x3) == 1, "RX STBC 1-stream");
	PRINT_HT_CAP(((cap >> 8) & 0x3) == 2, "RX STBC 2-streams");
	PRINT_HT_CAP(((cap >> 8) & 0x3) == 3, "RX STBC 3-streams");

	PRINT_HT_CAP((cap & BIT(10)), "HT Delayed Block Ack");

	PRINT_HT_CAP(!(cap & BIT(11)), "Max AMSDU length: 3839 bytes");
	PRINT_HT_CAP((cap & BIT(11)), "Max AMSDU length: 7935 bytes");

	/*
	 * For beacons and probe response this would mean the BSS
	 * does or does not allow the usage of DSSS/CCK HT40.
	 * Otherwise it means the STA does or does not use
	 * DSSS/CCK HT40.
	 */
	PRINT_HT_CAP((cap & BIT(12)), "DSSS/CCK HT40");
	PRINT_HT_CAP(!(cap & BIT(12)), "No DSSS/CCK HT40");

	/* BIT(13) is reserved */

	PRINT_HT_CAP((cap & BIT(14)), "40 MHz Intolerant");

	PRINT_HT_CAP((cap & BIT(15)), "L-SIG TXOP protection");
#undef PRINT_HT_CAP
}

/*
 * There are only 4 possible values, we just use a case instead of computing it,
 * but technically this can also be computed through the formula:
 *
 * Max AMPDU length = (2 ^ (13 + exponent)) - 1 bytes
 */
static __u32 compute_ampdu_length(__u8 exponent)
{
	switch (exponent) {
	case 0: return 8191;  /* (2 ^(13 + 0)) -1 */
	case 1: return 16383; /* (2 ^(13 + 1)) -1 */
	case 2: return 32767; /* (2 ^(13 + 2)) -1 */
	case 3: return 65535; /* (2 ^(13 + 3)) -1 */
	default: return 0;
	}
}

void print_ampdu_length(__u8 exponent)
{
	__u32 max_ampdu_length;

	max_ampdu_length = compute_ampdu_length(exponent);

	if (max_ampdu_length) {
		printf("\t\tMaximum RX AMPDU length %d bytes (exponent: 0x0%02x)\n",
		       max_ampdu_length, exponent);
	} else {
		printf("\t\tMaximum RX AMPDU length: unrecognized bytes "
		       "(exponent: %d)\n", exponent);
	}
}

static const char *print_ampdu_space(__u8 space)
{
	switch (space) {
	case 0: return "No restriction";
	case 1: return "1/4 usec";
	case 2: return "1/2 usec";
	case 3: return "1 usec";
	case 4: return "2 usec";
	case 5: return "4 usec";
	case 6: return "8 usec";
	case 7: return "16 usec";
	default:
		return "BUG (spacing more than 3 bits!)";
	}
}
void print_ampdu_spacing(__u8 spacing)
{
	printf("\t\tMinimum RX AMPDU time spacing: %s (0x%02x)\n",
	       print_ampdu_space(spacing), spacing);
}


static void print_mcs_index(const __u8 *mcs)
{
	int mcs_bit, prev_bit = -2, prev_cont = 0;

	for (mcs_bit = 0; mcs_bit <= 76; mcs_bit++) {
		unsigned int mcs_octet = mcs_bit/8;
		unsigned int MCS_RATE_BIT = 1 << mcs_bit % 8;
		bool mcs_rate_idx_set;

		mcs_rate_idx_set = !!(mcs[mcs_octet] & MCS_RATE_BIT);

		if (!mcs_rate_idx_set)
			continue;

		if (prev_bit != mcs_bit - 1) {
			if (prev_bit != -2)
				printf("%d, ", prev_bit);
			else
				printf(" ");
			printf("%d", mcs_bit);
			prev_cont = 0;
		} else if (!prev_cont) {
			printf("-");
			prev_cont = 1;
		}

		prev_bit = mcs_bit;
	}

	if (prev_cont)
		printf("%d", prev_bit);
	printf("\n");
}

void print_ht_mcs(const __u8 *mcs)
{
	/* As defined in 7.3.2.57.4 Supported MCS Set field */
	unsigned int tx_max_num_spatial_streams, max_rx_supp_data_rate;
	bool tx_mcs_set_defined, tx_mcs_set_equal, tx_unequal_modulation;

	max_rx_supp_data_rate = (mcs[10] | ((mcs[11] & 0x3) << 8));
	tx_mcs_set_defined = !!(mcs[12] & (1 << 0));
	tx_mcs_set_equal = !(mcs[12] & (1 << 1));
	tx_max_num_spatial_streams = ((mcs[12] >> 2) & 3) + 1;
	tx_unequal_modulation = !!(mcs[12] & (1 << 4));

	if (max_rx_supp_data_rate)
		printf("\t\tHT Max RX data rate: %d Mbps\n", max_rx_supp_data_rate);
	/* XXX: else see 9.6.0e.5.3 how to get this I think */

	if (tx_mcs_set_defined) {
		if (tx_mcs_set_equal) {
			printf("\t\tHT TX/RX MCS rate indexes supported:");
			print_mcs_index(mcs);
		} else {
			printf("\t\tHT RX MCS rate indexes supported:");
			print_mcs_index(mcs);

			if (tx_unequal_modulation)
				printf("\t\tTX unequal modulation supported\n");
			else
				printf("\t\tTX unequal modulation not supported\n");

			printf("\t\tHT TX Max spatial streams: %d\n",
				tx_max_num_spatial_streams);

			printf("\t\tHT TX MCS rate indexes supported may differ\n");
		}
	} else {
		printf("\t\tHT RX MCS rate indexes supported:");
		print_mcs_index(mcs);
		printf("\t\tHT TX MCS rate indexes are undefined\n");
	}
}

void print_vht_info(__u32 capa, const __u8 *mcs)
{
	__u16 tmp;
	int i;

	printf("\t\tVHT Capabilities (0x%.8x):\n", capa);

#define PRINT_VHT_CAPA(_bit, _str) \
	do { \
		if (capa & BIT(_bit)) \
			printf("\t\t\t" _str "\n"); \
	} while (0)

	printf("\t\t\tMax MPDU length: ");
	switch (capa & 3) {
	case 0: printf("3895\n"); break;
	case 1: printf("7991\n"); break;
	case 2: printf("11454\n"); break;
	case 3: printf("(reserved)\n");
	}
	printf("\t\t\tSupported Channel Width: ");
	switch ((capa >> 2) & 3) {
	case 0: printf("neither 160 nor 80+80\n"); break;
	case 1: printf("160 MHz\n"); break;
	case 2: printf("160 MHz, 80+80 MHz\n"); break;
	case 3: printf("(reserved)\n");
	}
	PRINT_VHT_CAPA(4, "RX LDPC");
	PRINT_VHT_CAPA(5, "short GI (80 MHz)");
	PRINT_VHT_CAPA(6, "short GI (160/80+80 MHz)");
	PRINT_VHT_CAPA(7, "TX STBC");
	/* RX STBC */
	PRINT_VHT_CAPA(11, "SU Beamformer");
	PRINT_VHT_CAPA(12, "SU Beamformee");
	/* compressed steering */
	/* # of sounding dimensions */
	PRINT_VHT_CAPA(19, "MU Beamformer");
	PRINT_VHT_CAPA(20, "MU Beamformee");
	PRINT_VHT_CAPA(21, "VHT TXOP PS");
	PRINT_VHT_CAPA(22, "+HTC-VHT");
	/* max A-MPDU */
	/* VHT link adaptation */
	PRINT_VHT_CAPA(28, "RX antenna pattern consistency");
	PRINT_VHT_CAPA(29, "TX antenna pattern consistency");

	printf("\t\tVHT RX MCS set:\n");
	tmp = mcs[0] | (mcs[1] << 8);
	for (i = 1; i <= 8; i++) {
		printf("\t\t\t%d streams: ", i);
		switch ((tmp >> ((i-1)*2) ) & 3) {
		case 0: printf("MCS 0-7\n"); break;
		case 1: printf("MCS 0-8\n"); break;
		case 2: printf("MCS 0-9\n"); break;
		case 3: printf("not supported\n"); break;
		}
	}
	tmp = mcs[2] | (mcs[3] << 8);
	printf("\t\tVHT RX highest supported: %d Mbps\n", tmp & 0x1fff);

	printf("\t\tVHT TX MCS set:\n");
	tmp = mcs[4] | (mcs[5] << 8);
	for (i = 1; i <= 8; i++) {
		printf("\t\t\t%d streams: ", i);
		switch ((tmp >> ((i-1)*2) ) & 3) {
		case 0: printf("MCS 0-7\n"); break;
		case 1: printf("MCS 0-8\n"); break;
		case 2: printf("MCS 0-9\n"); break;
		case 3: printf("not supported\n"); break;
		}
	}
	tmp = mcs[6] | (mcs[7] << 8);
	printf("\t\tVHT TX highest supported: %d Mbps\n", tmp & 0x1fff);
}

void print_he_info(struct nlattr *nl_iftype)
{
	struct nlattr *tb[NL80211_BAND_IFTYPE_ATTR_MAX + 1];
	struct nlattr *tb_flags[NL80211_IFTYPE_MAX + 1];
	char *iftypes[NUM_NL80211_IFTYPES] = {
		"Unspec", "Adhoc", "Station", "AP", "AP/VLAN", "WDS", "Monitor",
		"Mesh", "P2P/Client", "P2P/Go", "P2P/Device", "OCB", "NAN",
	};
	__u16 mac_cap[3] = { 0 };
	__u16 phy_cap[6] = { 0 };
	__u16 mcs_set[6] = { 0 };
	__u8 ppet[25] = { 0 };
	size_t len;
	int i;

	#define PRINT_HE_CAP(_var, _idx, _bit, _str) \
	do { \
		if (_var[_idx] & BIT(_bit)) \
			printf("\t\t\t\t" _str "\n"); \
	} while (0)

	#define PRINT_HE_CAP_MASK(_var, _idx, _shift, _mask, _str) \
	do { \
		if ((_var[_idx] >> _shift) & _mask) \
			printf("\t\t\t\t" _str ": %d\n", (_var[_idx] >> _shift) & _mask); \
	} while (0)

	#define PRINT_HE_MAC_CAP(...) PRINT_HE_CAP(mac_cap, __VA_ARGS__)
	#define PRINT_HE_MAC_CAP_MASK(...) PRINT_HE_CAP_MASK(mac_cap, __VA_ARGS__)
	#define PRINT_HE_PHY_CAP(...) PRINT_HE_CAP(phy_cap, __VA_ARGS__)
	#define PRINT_HE_PHY_CAP0(_idx, _bit, ...) PRINT_HE_CAP(phy_cap, _idx, _bit + 8, __VA_ARGS__)
	#define PRINT_HE_PHY_CAP_MASK(...) PRINT_HE_CAP_MASK(phy_cap, __VA_ARGS__)

	nla_parse(tb, NL80211_BAND_IFTYPE_ATTR_MAX,
		  nla_data(nl_iftype), nla_len(nl_iftype), NULL);

	if (!tb[NL80211_BAND_IFTYPE_ATTR_IFTYPES])
		return;

	if (nla_parse_nested(tb_flags, NL80211_IFTYPE_MAX,
			     tb[NL80211_BAND_IFTYPE_ATTR_IFTYPES], NULL))
		return;

	printf("\t\tHE Iftypes:");
	for (i = 0; i < NUM_NL80211_IFTYPES; i++)
		if (nla_get_flag(tb_flags[i]) && iftypes[i])
			printf(" %s", iftypes[i]);
	printf("\n");

	if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]) {
		len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]);
		if (len > sizeof(mac_cap))
			len = sizeof(mac_cap);
		memcpy(mac_cap,
		       nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC]),
		       len);
	}
	printf("\t\t\tHE MAC Capabilities (0x");
	for (i = 0; i < 3; i++)
		printf("%04x", mac_cap[i]);
	printf("):\n");

	PRINT_HE_MAC_CAP(0, 0, "+HTC HE Supported");
	PRINT_HE_MAC_CAP(0, 1, "TWT Requester");
	PRINT_HE_MAC_CAP(0, 2, "TWT Responder");
	PRINT_HE_MAC_CAP_MASK(0, 3, 0x3, "Dynamic BA Fragementation Level");
	PRINT_HE_MAC_CAP_MASK(0, 5, 0x7, "Maximum number of MSDUS Fragments");
	PRINT_HE_MAC_CAP_MASK(0, 8, 0x3, "Minimum Payload size of 128 bytes");
	PRINT_HE_MAC_CAP_MASK(0, 10, 0x3, "Trigger Frame MAC Padding Duration");
	PRINT_HE_MAC_CAP_MASK(0, 12, 0x7, "Multi-TID Aggregation Support");

	PRINT_HE_MAC_CAP(1, 1, "All Ack");
	PRINT_HE_MAC_CAP(1, 2, "TRS");
	PRINT_HE_MAC_CAP(1, 3, "BSR");
	PRINT_HE_MAC_CAP(1, 4, "Broadcast TWT");
	PRINT_HE_MAC_CAP(1, 5, "32-bit BA Bitmap");
	PRINT_HE_MAC_CAP(1, 6, "MU Cascading");
	PRINT_HE_MAC_CAP(1, 7, "Ack-Enabled Aggregation");
	PRINT_HE_MAC_CAP(1, 9, "OM Control");
	PRINT_HE_MAC_CAP(1, 10, "OFDMA RA");
	PRINT_HE_MAC_CAP_MASK(1, 11, 0x3, "Maximum A-MPDU Length Exponent");
	PRINT_HE_MAC_CAP(1, 13, "A-MSDU Fragmentation");
	PRINT_HE_MAC_CAP(1, 14, "Flexible TWT Scheduling");
	PRINT_HE_MAC_CAP(1, 15, "RX Control Frame to MultiBSS");

	PRINT_HE_MAC_CAP(2, 0, "BSRP BQRP A-MPDU Aggregation");
	PRINT_HE_MAC_CAP(2, 1, "QTP");
	PRINT_HE_MAC_CAP(2, 2, "BQR");
	PRINT_HE_MAC_CAP(2, 3, "SRP Responder Role");
	PRINT_HE_MAC_CAP(2, 4, "NDP Feedback Report");
	PRINT_HE_MAC_CAP(2, 5, "OPS");
	PRINT_HE_MAC_CAP(2, 6, "A-MSDU in A-MPDU");
	PRINT_HE_MAC_CAP_MASK(2, 7, 7, "Multi-TID Aggregation TX");
	PRINT_HE_MAC_CAP(2, 10, "HE Subchannel Selective Transmission");
	PRINT_HE_MAC_CAP(2, 11, "UL 2x996-Tone RU");
	PRINT_HE_MAC_CAP(2, 12, "OM Control UL MU Data Disable RX");

	if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]) {
		len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]);

		if (len > sizeof(phy_cap) - 1)
			len = sizeof(phy_cap) - 1;
		memcpy(&((__u8 *)phy_cap)[1],
		       nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY]),
		       len);
	}
	printf("\t\t\tHE PHY Capabilities: (0x");
	for (i = 0; i < 11; i++)
		printf("%02x", ((__u8 *)phy_cap)[i + 1]);
	printf("):\n");

	PRINT_HE_PHY_CAP0(0, 1, "HE40/2.4GHz");
	PRINT_HE_PHY_CAP0(0, 2, "HE40/HE80/5GHz");
	PRINT_HE_PHY_CAP0(0, 3, "HE160/5GHz");
	PRINT_HE_PHY_CAP0(0, 4, "HE160/HE80+80/5GHz");
	PRINT_HE_PHY_CAP0(0, 5, "242 tone RUs/2.4GHz");
	PRINT_HE_PHY_CAP0(0, 6, "242 tone RUs/5GHz");

	PRINT_HE_PHY_CAP_MASK(1, 0, 0xf, "Punctured Preamble RX");
	PRINT_HE_PHY_CAP_MASK(1, 4, 0x1, "Device Class");
	PRINT_HE_PHY_CAP(1, 5, "LDPC Coding in Payload");
	PRINT_HE_PHY_CAP(1, 6, "HE SU PPDU with 1x HE-LTF and 0.8us GI");
	PRINT_HE_PHY_CAP_MASK(1, 7, 0x3, "Midamble Rx Max NSTS");
	PRINT_HE_PHY_CAP(1, 9, "NDP with 4x HE-LTF and 3.2us GI");
	PRINT_HE_PHY_CAP(1, 10, "STBC Tx <= 80MHz");
	PRINT_HE_PHY_CAP(1, 11, "STBC Rx <= 80MHz");
	PRINT_HE_PHY_CAP(1, 12, "Doppler Tx");
	PRINT_HE_PHY_CAP(1, 13, "Doppler Rx");
	PRINT_HE_PHY_CAP(1, 14, "Full Bandwidth UL MU-MIMO");
	PRINT_HE_PHY_CAP(1, 15, "Partial Bandwidth UL MU-MIMO");

	PRINT_HE_PHY_CAP_MASK(2, 0, 0x3, "DCM Max Constellation");
	PRINT_HE_PHY_CAP_MASK(2, 2, 0x1, "DCM Max NSS Tx");
	PRINT_HE_PHY_CAP_MASK(2, 3, 0x3, "DCM Max Constellation Rx");
	PRINT_HE_PHY_CAP_MASK(2, 5, 0x1, "DCM Max NSS Rx");
	PRINT_HE_PHY_CAP(2, 6, "Rx HE MU PPDU from Non-AP STA");
	PRINT_HE_PHY_CAP(2, 7, "SU Beamformer");
	PRINT_HE_PHY_CAP(2, 8, "SU Beamformee");
	PRINT_HE_PHY_CAP(2, 9, "MU Beamformer");
	PRINT_HE_PHY_CAP_MASK(2, 10, 0x7, "Beamformee STS <= 80Mhz");
	PRINT_HE_PHY_CAP_MASK(2, 13, 0x7, "Beamformee STS > 80Mhz");

	PRINT_HE_PHY_CAP_MASK(3, 0, 0x7, "Sounding Dimensions <= 80Mhz");
	PRINT_HE_PHY_CAP_MASK(3, 3, 0x7, "Sounding Dimensions > 80Mhz");
	PRINT_HE_PHY_CAP(3, 6, "Ng = 16 SU Feedback");
	PRINT_HE_PHY_CAP(3, 7, "Ng = 16 MU Feedback");
	PRINT_HE_PHY_CAP(3, 8, "Codebook Size SU Feedback");
	PRINT_HE_PHY_CAP(3, 9, "Codebook Size MU Feedback");
	PRINT_HE_PHY_CAP(3, 10, "Triggered SU Beamforming Feedback");
	PRINT_HE_PHY_CAP(3, 11, "Triggered MU Beamforming Feedback");
	PRINT_HE_PHY_CAP(3, 12, "Triggered CQI Feedback");
	PRINT_HE_PHY_CAP(3, 13, "Partial Bandwidth Extended Range");
	PRINT_HE_PHY_CAP(3, 14, "Partial Bandwidth DL MU-MIMO");
	PRINT_HE_PHY_CAP(3, 15, "PPE Threshold Present");

	PRINT_HE_PHY_CAP(4, 0, "SRP-based SR");
	PRINT_HE_PHY_CAP(4, 1, "Power Boost Factor ar");
	PRINT_HE_PHY_CAP(4, 2, "HE SU PPDU & HE PPDU 4x HE-LTF 0.8us GI");
	PRINT_HE_PHY_CAP_MASK(4, 3, 0x7, "Max NC");
	PRINT_HE_PHY_CAP(4, 6, "STBC Tx > 80MHz");
	PRINT_HE_PHY_CAP(4, 7, "STBC Rx > 80MHz");
	PRINT_HE_PHY_CAP(4, 8, "HE ER SU PPDU 4x HE-LTF 0.8us GI");
	PRINT_HE_PHY_CAP(4, 9, "20MHz in 40MHz HE PPDU 2.4GHz");
	PRINT_HE_PHY_CAP(4, 10, "20MHz in 160/80+80MHz HE PPDU");
	PRINT_HE_PHY_CAP(4, 11, "80MHz in 160/80+80MHz HE PPDU");
	PRINT_HE_PHY_CAP(4, 12, "HE ER SU PPDU 1x HE-LTF 0.8us GI");
	PRINT_HE_PHY_CAP(4, 13, "Midamble Rx 2x & 1x HE-LTF");
	PRINT_HE_PHY_CAP_MASK(4, 14, 0x3, "DCM Max BW");

	PRINT_HE_PHY_CAP(5, 0, "Longer Than 16HE SIG-B OFDM Symbols");
	PRINT_HE_PHY_CAP(5, 1, "Non-Triggered CQI Feedback");
	PRINT_HE_PHY_CAP(5, 2, "TX 1024-QAM");
	PRINT_HE_PHY_CAP(5, 3, "RX 1024-QAM");
	PRINT_HE_PHY_CAP(5, 4, "RX Full BW SU Using HE MU PPDU with Compression SIGB");
	PRINT_HE_PHY_CAP(5, 5, "RX Full BW SU Using HE MU PPDU with Non-Compression SIGB");

	if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]) {
		len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]);
		if (len > sizeof(mcs_set))
			len = sizeof(mcs_set);
		memcpy(mcs_set,
		       nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET]),
		       len);
	}

	for (i = 0; i < 3; i++) {
		__u8 phy_cap_support[] = { BIT(1) | BIT(2), BIT(3), BIT(4) };
		char *bw[] = { "<= 80", "160", "80+80" };
		int j;

		if ((phy_cap[0] & (phy_cap_support[i] << 8)) == 0)
			continue;

		for (j = 0; j < 2; j++) {
			int k;
			printf("\t\t\tHE %s MCS and NSS set %s MHz\n", j ? "TX" : "RX", bw[i]);
			for (k = 0; k < 8; k++) {
				__u16 mcs = mcs_set[(i * 2) + j];
				mcs >>= k * 2;
				mcs &= 0x3;
				printf("\t\t\t\t\t %d streams: ", k + 1);
				if (mcs == 3)
					printf("not supported\n");
				else
					printf("MCS 0-%d\n", 7 + (mcs * 2));
			}

		}
	}

	len = 0;
	if (tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]) {
		len = nla_len(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]);
		if (len > sizeof(ppet))
			len = sizeof(ppet);
		memcpy(ppet,
		       nla_data(tb[NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE]),
		       len);
	}

	if (len && (phy_cap[3] & BIT(15))) {
		size_t i;

		printf("\t\t\tPPE Threshold ");
		for (i = 0; i < len; i++)
			if (ppet[i])
				printf("0x%02x ", ppet[i]);
		printf("\n");
	}
}

int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

//和套接字相关的回调函数，用来解析phy命令相关的消息
static int print_phy_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IR] = { .type = NLA_FLAG },
		[__NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
	};

	struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
	static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
		[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
	};

	struct nlattr *nl_band;
	struct nlattr *nl_freq;
	struct nlattr *nl_rate;
	struct nlattr *nl_mode;
	struct nlattr *nl_cmd;
	struct nlattr *nl_if, *nl_ftype;
	int rem_band, rem_freq, rem_rate, rem_mode, rem_cmd, rem_ftype, rem_if;
	int open;
	/*
	 * static variables only work here, other applications need to use the
	 * callback pointer and store them there so they can be multithreaded
	 * and/or have multiple netlink sockets, etc.
	 */
	static int64_t phy_id = -1;
	static int last_band = -1;
	static bool band_had_freq = false;
	bool print_name = true;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY]) {
		if (nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]) == phy_id)
			print_name = false;
		else
			last_band = -1;
		phy_id = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);
	}
	if (print_name && tb_msg[NL80211_ATTR_WIPHY_NAME])
		printf("Wiphy %s\n", nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]));

	/* needed for split dump */
	if (tb_msg[NL80211_ATTR_WIPHY_BANDS]) {
		nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {
			if (last_band != nl_band->nla_type) {
				printf("\tBand %d:\n", nl_band->nla_type + 1);
				band_had_freq = false;
			}
			last_band = nl_band->nla_type;

			nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band),
				  nla_len(nl_band), NULL);

			if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
				__u16 cap = nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
				print_ht_capability(cap);
			}
			if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]) {
				__u8 exponent = nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]);
				print_ampdu_length(exponent);
			}
			if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]) {
				__u8 spacing = nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]);
				print_ampdu_spacing(spacing);
			}
			if (tb_band[NL80211_BAND_ATTR_HT_MCS_SET] &&
			    nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) == 16)
				print_ht_mcs(nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]));
			if (tb_band[NL80211_BAND_ATTR_VHT_CAPA] &&
			    tb_band[NL80211_BAND_ATTR_VHT_MCS_SET])
				print_vht_info(nla_get_u32(tb_band[NL80211_BAND_ATTR_VHT_CAPA]),
					       nla_data(tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]));
			if (tb_band[NL80211_BAND_ATTR_IFTYPE_DATA]) {
				struct nlattr *nl_iftype;
				int rem_band;

				nla_for_each_nested(nl_iftype, tb_band[NL80211_BAND_ATTR_IFTYPE_DATA], rem_band)
					print_he_info(nl_iftype);
			}
			if (tb_band[NL80211_BAND_ATTR_FREQS]) {
				if (!band_had_freq) {
					printf("\t\tFrequencies:\n");
					band_had_freq = true;
				}
				nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
					uint32_t freq;
					nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq),
						  nla_len(nl_freq), freq_policy);
					if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
						continue;
					freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);
					printf("\t\t\t* %d MHz [%d]", freq, ieee80211_frequency_to_channel(freq));

					if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] &&
					    !tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
						printf(" (%.1f dBm)", 0.01 * nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]));

					open = 0;
					if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED]) {
						print_flag("disabled", &open);
						goto next;
					}

					/* If both flags are set assume an new kernel */
					if (tb_freq[NL80211_FREQUENCY_ATTR_NO_IR] && tb_freq[__NL80211_FREQUENCY_ATTR_NO_IBSS]) {
						print_flag("no IR", &open);
					} else if (tb_freq[NL80211_FREQUENCY_ATTR_PASSIVE_SCAN]) {
						print_flag("passive scan", &open);
					} else if (tb_freq[__NL80211_FREQUENCY_ATTR_NO_IBSS]){
						print_flag("no ibss", &open);
					}

					if (tb_freq[NL80211_FREQUENCY_ATTR_RADAR])
						print_flag("radar detection", &open);
next:
					if (open)
						printf(")");
					printf("\n");
				}
			}

			if (tb_band[NL80211_BAND_ATTR_RATES]) {
			printf("\t\tBitrates (non-HT):\n");
			nla_for_each_nested(nl_rate, tb_band[NL80211_BAND_ATTR_RATES], rem_rate) {
				nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate),
					  nla_len(nl_rate), rate_policy);
				if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
					continue;
				printf("\t\t\t* %2.1f Mbps", 0.1 * nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]));
				open = 0;
				if (tb_rate[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE])
					print_flag("short preamble supported", &open);
				if (open)
					printf(")");
				printf("\n");
			}
			}
		}
	}
	return 0;
}
