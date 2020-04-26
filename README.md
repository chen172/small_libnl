# linux-netlink
分析如何通过netlink套接字接口调用内核模块。
通过分析genl_ctrl_probe_by_name可以知道如何使用libnl来
通过Generic netlink访问内核。


TO DO:
1.从Linux kernel下完整的fork下netlink.h
2.解决simple_iw的bug，主要问题是命令的构建。
