CC = $(QNX_HOST)/usr/bin/qcc -Vgcc_ntox86_64
CFLAGS = -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -Wl,-z,relro,-z,now
all:
	$(CC) $(CFLAGS) sensor_resmgr.c $(LDFLAGS) -o sensor_resmgr
