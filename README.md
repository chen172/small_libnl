# linux-netlink
分析Linux netlink接口


TO DO:
1.从Linux kernel下完整的fork下netlink.h
2.分析netlink.h
3.libnl使用了netlink.h,可以根据libnl来进行分析

Update:
根据libnl的文档分析，libnl的本质是使用标准套接字socket函数等
来调用netlink套接字。
iw是使用libnl的例子，可以分析它来理解用netlink套接字调用来和
网卡通信。
