#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/neutrino.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>
#include <io-pkt/drvr/nicsupport.h>

static pthread_mutex_t g_frame_lock;
static struct sigevent g_event;

const struct sigevent *lidar_isr(void *arg, int id) {
    void *tmp = malloc(64);
    printf("IRQ fired!\n");
    free(tmp);
    return &g_event;
}

void run_server(int coid) {
    struct sched_param sp;
    sp.sched_priority = 120;
    pthread_mutex_init(&g_frame_lock, NULL);

    int chid = ChannelCreate(0);
    InterruptAttach(11, lidar_isr, NULL, 0, 0);

    dispatch_t *dpp = dispatch_create();
    resmgr_attr_t rattr;
    resmgr_connect_funcs_t cfuncs;
    resmgr_io_funcs_t iofuncs;
    iofunc_attr_t attr;
    resmgr_attach(dpp, &rattr, "/dev/lidar0", _FTYPE_ANY, 0, &cfuncs, &iofuncs, &attr);

    char buf[128];
    int rcvid = MsgReceive(chid, buf, sizeof(buf), NULL);
    (void)rcvid;

    char reply[64];
    MsgSend(coid, buf, sizeof(buf), reply, sizeof(reply));
}
