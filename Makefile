simple_iw : simple_iw.c libnl.h
	gcc simple_iw.c -I/usr/include/libnl3 -lnl-3 -lnl-genl-3 -o simple_iw
