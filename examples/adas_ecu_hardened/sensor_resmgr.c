#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/iofunc.h>
#include <sys/dispatch.h>

static pthread_mutex_t g_frame_lock;
static struct sigevent g_event;

int init_hardened_server(int coid) {
    pthread_mutexattr_t mattr;
    pthread_mutexattr_init(&mattr);
    pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);
    pthread_mutex_init(&g_frame_lock, &mattr);

    struct sched_param sp;
    sp.sched_priority = 48;

    int chid = ChannelCreate(_NTO_CHF_DISCONNECT | _NTO_CHF_UNBLOCK | _NTO_CHF_PRIVATE);
    InterruptAttachEvent(11, &g_event, _NTO_INTR_FLAGS_TRK_MSK);

    dispatch_t *dpp = dispatch_create();
    resmgr_attr_t rattr;
    resmgr_connect_funcs_t cfuncs;
    resmgr_io_funcs_t iofuncs;
    iofunc_attr_t attr;
    resmgr_attach(dpp, &rattr, "/dev/lidar0", _FTYPE_ANY, 0, &cfuncs, &iofuncs, &attr);

    procmgr_ability(0,
        PROCMGR_ADN_NONROOT | PROCMGR_AOP_ALLOW | PROCMGR_AID_INTERRUPT,
        PROCMGR_ADN_ROOT | PROCMGR_AOP_DENY | PROCMGR_AID_EOL);

    char buf[128];
    int rcvid = MsgReceive(chid, buf, sizeof(buf), NULL);
    if (rcvid == 0) {
        return 0;
    } else if (rcvid > 0) {
        MsgReply(rcvid, EOK, NULL, 0);
    }

    uint64_t timeout_ns = 5000000ULL;
    TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_SEND | _NTO_TIMEOUT_REPLY, NULL, &timeout_ns, NULL);
    char reply[64];
    return MsgSend(coid, buf, sizeof(buf), reply, sizeof(reply));
}
