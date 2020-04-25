# linux-netlink
分析如何通过netlink套接字接口调用内核模块。


TO DO:
1.从Linux kernel下完整的fork下netlink.h
2.根据ctrl.c的分析，要构造头部和payload。
3.根据genl.c和msg.c分析Generic netlink头部的构造。
4.根据attr.c分析消息payload属性的构造。
