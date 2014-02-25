/*
 * Copyright 2014 GRNET S.A. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *   1. Redistributions of source code must retain the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and
 * documentation are those of the authors and should not be
 * interpreted as representing official policies, either expressed
 * or implied, of GRNET S.A.
 */

#include "block/block_int.h"
#include "qemu/error-report.h"
#include "qemu/sockets.h"
#include "qemu/uri.h"
#include "qemu/thread.h"

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <xseg/xseg.h>
#include <xseg/protocol.h>

#define ARCHIP_FD_READ      0
#define ARCHIP_FD_WRITE     1

#define NUM_XSEG_THREADS    2

struct xseg *xseg;
struct xseg_config cfg;
xport srcport = NoPort;
xport sport = NoPort;
struct xseg_port *port;
xport mportno = NoPort;
xport vportno = NoPort;

struct posixfd_signal_desc {
    char signal_file[sizeof(void *)];
    int fd;
    int flag;
};

#define archipelagolog(fmt, ...) \
    fprintf(stderr, "archipelago\t%-24s" fmt, __func__, ##__VA_ARGS__)

typedef enum {
    ARCHIP_AIO_READ,
    ARCHIP_AIO_WRITE,
    ARCHIP_AIO_VOLINFO,
} ARCHIPAIOCmd;

typedef struct ArchipelagoConf {
    char *volname;
    int mapperd_port;
    int vlmcd_port;
    int64_t size;
} ArchipelagoConf;

typedef struct ArchipelagoAIOCB {
    BlockDriverAIOCB common;
    QEMUBH *bh;
    int64_t ret;
    QEMUIOVector *qiov;
    char *buffer;
    ARCHIPAIOCmd cmd;
    int64_t sector_num;
    int error;
    struct BDRVArchipelagoState *s;
    int cancelled;
    int status;
} ArchipelagoAIOCB;

typedef struct ArchipelagoCB {
    ArchipelagoAIOCB *acb;
    struct BDRVArchipelagoState *s;
    int done;
    int64_t size;
    char *buf;
    int64_t ret;
} ArchipelagoCB;

typedef struct BDRVArchipelagoState {
    int fds[2];
    ArchipelagoConf *gconf;
    uint32_t archipflags;
    int qemu_aio_count;
    int event_reader_pos;
    ArchipelagoCB *event_acb;
} BDRVArchipelagoState;

typedef struct AIORequestData {
    char *volname;
    off_t offset;
    ssize_t size;
    char *buf;
    ArchipelagoCB *aio_cb;
    int ret;
    int write;
} AIORequestData;

typedef struct ArchipelagoThread {
    QemuThread request_th;
    QemuCond request_cond;
    QemuMutex request_mutex;
    int is_signaled;
    int is_running;
} ArchipelagoThread;

static void archipelago_aio_bh_cb(void *opaque);
static int qemu_archipelago_signal_pipe(BDRVArchipelagoState *s,
        ArchipelagoCB *aio_cb);

QemuMutex archip_mutex;
QemuCond archip_cond;
ArchipelagoThread archipelago_th[NUM_XSEG_THREADS];
static int is_signaled = 0;

static void init_local_signal(void)
{
    if(xseg && (sport != srcport)) {
        xseg_init_local_signal(xseg, srcport);
        sport = srcport;
    }
}

static void archipelago_finish_aiocb(ArchipelagoCB *aio_cb, ssize_t c,
        AIORequestData *reqdata)
{
	int ret;
	aio_cb->ret = c;
	ret = qemu_archipelago_signal_pipe(aio_cb->s, aio_cb);
	if(ret < 0) {
		error_report("archipelago_finish_aiocb(): failed writing to acb->s->fds");
		g_free(aio_cb);
        g_free(reqdata);
        /* Lock disk and exit ??*/
	}
    g_free(reqdata);
}

static int wait_reply(struct xseg_request *expected_req)
{
    struct xseg_request *rec;
    xseg_prepare_wait(xseg, srcport);
    struct posixfd_signal_desc *psd = xseg_get_signal_desc(xseg, port);
    while(1) {
        rec = xseg_receive(xseg, srcport, 0);
        if(rec) {
            if(rec != expected_req) {
	            archipelagolog("Unknown received request.\n");
                xseg_put_request(xseg, rec, srcport);
            } else if(!(rec->state & XS_SERVED)) {
                fprintf(stderr, "Failed req.\n");
                return -1;
            } else {
                break;
            }
        }
        xseg_wait_signal(xseg, psd, 10000000UL);
    }
    xseg_cancel_wait(xseg, srcport);
    return 0;
}

static void xseg_request_handler(void *arthd)
{

    struct posixfd_signal_desc *psd = xseg_get_signal_desc(xseg, port);
    ArchipelagoThread *th = (ArchipelagoThread *) arthd;
    while(th->is_running) {
        struct xseg_request *req;
        xseg_prepare_wait(xseg, srcport);
        req = xseg_receive(xseg, srcport, 0);
        if(req){
            AIORequestData *reqdata;
            xseg_get_req_data(xseg, req, (void **)&reqdata);
            if(reqdata->write == ARCHIP_AIO_READ){
                char *data = xseg_get_data(xseg, req);
                memcpy(reqdata->buf, data, req->serviced);
                reqdata->ret = req->serviced;
                xseg_put_request(xseg, req, srcport);
                archipelago_finish_aiocb(reqdata->aio_cb, reqdata->ret, reqdata);
            } else if(reqdata->write == ARCHIP_AIO_WRITE) {
                reqdata->ret = req->serviced;
                xseg_put_request(xseg, req, srcport);
                archipelago_finish_aiocb(reqdata->aio_cb, reqdata->ret, reqdata);
            } else if (reqdata->write == ARCHIP_AIO_VOLINFO) {
                is_signaled = 1;
                qemu_cond_signal(&archip_cond);
            }
        } else {
            xseg_wait_signal(xseg, psd, 10000000UL);
        }
        xseg_cancel_wait(xseg, srcport);
    }
    th->is_signaled = 1;
    qemu_cond_signal(&th->request_cond);
    qemu_thread_exit(NULL);
}

static void qemu_archipelago_gconf_free(ArchipelagoConf *gconf)
{
    g_free(gconf->volname);
    g_free(gconf);
}

static void xseg_find_port(char *pstr, const char *needle, xport *port)
{
    char *a;
    char *dpstr = strdup(pstr);
    a = strtok(dpstr, needle);
    *port = (xport) atoi(a);
    free(dpstr);
}

static int parse_volume_options(ArchipelagoConf *gconf, char *path)
{
    char *tokens[4];
    int i;
    if(!path) {
        return -EINVAL;
    }
    /* Find Volume Name, mapperd and vlmcd ports */
    char *ds = g_strndup(path, strlen(path));
    tokens[0] = strtok(ds, ":");
    tokens[1] = strtok(NULL, "/");
    tokens[2] = strtok(NULL, ":");
    tokens[3] = strtok(NULL, ":");
    if(strcmp(tokens[0], "archipelago") != 0) {
        /* Should not be here. Protocol is already not supported */
        return -EINVAL;
    }

    gconf->volname = g_strndup(tokens[1], strlen(tokens[1]));
    for(i = 0; i < 4; i++) {
        if(tokens[i] != NULL) {
            if(strstr(tokens[i], "mport="))
                xseg_find_port(tokens[i], "mport=", &mportno);
            if(strstr(tokens[i], "vport="))
                xseg_find_port(tokens[i], "vport=", &vportno);
        }
    }

    return 0;
}

static int archipelago_parse_uri(ArchipelagoConf *gconf, const char *filename)
{
    int ret = 0;
    ret = parse_volume_options(gconf, (char *)filename);

    return ret;
}

static int qemu_archipelago_xseg_init(void)
{
    if(xseg_initialize()) {
        archipelagolog("Cannot initialize xseg.\n");
	    goto err_exit;
    }
    xseg = xseg_join((char *)"posix", (char *)"archipelago", (char *)"posixfd", NULL);
    if(!xseg) {
        archipelagolog("Cannot join segment.\n");
	    goto err_exit;
    }
    port = xseg_bind_dynport(xseg);
    srcport = port->portno;
    init_local_signal();
    return 0;
err_exit:
    return -1;
}

static int qemu_archipelago_init(ArchipelagoConf *gconf, const char *filename)
{
    int ret, i;
    /* Set default values */
    vportno = 501;
    mportno = 1001;

    ret = archipelago_parse_uri(gconf, filename);
    if(ret < 0) {
        error_report("Usage: file=archipelago:<volumename>[/mport=<mapperd_port>[:vport=<vlmcd_port>]]");
        errno = -ret;
        goto out;
    }

    ret = qemu_archipelago_xseg_init();
    if(ret < 0) {
        error_report("Cannot initialize xseg. Aborting...\n");
        errno = -ret;
        goto out;
    }
    qemu_cond_init(&archip_cond);
    qemu_mutex_init(&archip_mutex);
    for(i = 0; i < NUM_XSEG_THREADS; i++){
        qemu_cond_init(&archipelago_th[i].request_cond);
        qemu_mutex_init(&archipelago_th[i].request_mutex);
        archipelago_th[i].is_signaled = 0;
        archipelago_th[i].is_running = 1;
        qemu_thread_create(&archipelago_th[i].request_th, (void *) xseg_request_handler,
                (void *)&archipelago_th[i], QEMU_THREAD_DETACHED);
    }
out:
    return ret;
}

static void qemu_archipelago_complete_aio(ArchipelagoCB *aio_cb)
{
    ArchipelagoAIOCB *acb = aio_cb->acb;
    int64_t r;

    r = aio_cb->ret;

    if(acb->cmd != ARCHIP_AIO_READ) {
        if(r < 0) {
            acb->ret = r;
            acb->error = 1;
        } else if(!acb->error) {
            acb->ret = aio_cb->size;
        }
    } else {
        if(r < 0) {
            memset(aio_cb->buf, 0, aio_cb->size);
            acb->ret = r;
            acb->error = 1;
        } else if(r < aio_cb->size) {
            memset(aio_cb->buf +r, 0, aio_cb->size -r);
            if(!acb->error) {
                acb->ret = aio_cb->size;
            }
        } else if(!acb->error) {
            acb->ret = r;
        }
    }
    acb->bh = qemu_bh_new(archipelago_aio_bh_cb, acb);
    qemu_bh_schedule(acb->bh);
    g_free(aio_cb);
}

static void qemu_archipelago_aio_event_reader(void *opaque)
{
    BDRVArchipelagoState *s = opaque;
    ssize_t ret;

    do {
        char *p = (char *)&s->event_acb;

        ret = read(s->fds[ARCHIP_FD_READ], p + s->event_reader_pos,
                sizeof(s->event_acb) - s->event_reader_pos);
        if(ret > 0) {
            s->event_reader_pos += ret;
            if(s->event_reader_pos == sizeof(s->event_acb)) {
                s->event_reader_pos = 0;
                qemu_archipelago_complete_aio(s->event_acb);
                s->qemu_aio_count--;
            }
        }
    } while (ret < 0 && errno == EINTR);
}

static QemuOptsList runtime_opts = {
    .name = "archipelago",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "Specification of the volume image",
        },
        { /* end of list */ }
    },
};

static int qemu_archipelago_open(BlockDriverState *bs, QDict *options,
        int bdrv_flags, Error **errp)
{
    BDRVArchipelagoState *s = bs->opaque;
    int open_flags = O_BINARY;
    int ret = 0;
    s->gconf = g_malloc0(sizeof(ArchipelagoConf));
    QemuOpts *opts;
    Error *local_err = NULL;
    const char *filename;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);
    if(error_is_set(&local_err)) {
        qerror_report_err(local_err);
        error_free(local_err);
        ret = -EINVAL;
        goto out;
    }

    filename= qemu_opt_get(opts, "filename");

    ret = qemu_archipelago_init(s->gconf, filename);
    if(ret < 0) {
        ret = -errno;
        goto out;
    }

    if(bdrv_flags & BDRV_O_RDWR) {
        open_flags |= O_RDWR;
    } else {
        open_flags |= O_RDONLY;
    }

    if((bdrv_flags * BDRV_O_NOCACHE)) {
        open_flags |= O_DIRECT;
    }

    /* Initialized XSEG, join segment and set s->gconf->volname */
    /* Utilize open_flags, if any, with Archipelago */
    s->event_reader_pos = 0;
    ret = qemu_pipe(s->fds);
    if(ret < 0) {
        ret = -errno;
        goto out;
    }

    fcntl(s->fds[ARCHIP_FD_READ], F_SETFL, O_NONBLOCK);
    fcntl(s->fds[ARCHIP_FD_WRITE], F_SETFL, O_NONBLOCK);
    qemu_aio_set_fd_handler(s->fds[ARCHIP_FD_READ],
            qemu_archipelago_aio_event_reader, NULL,
            s);

    qemu_opts_del(opts);
    return 0;

out:
    qemu_opts_del(opts);
    qemu_archipelago_gconf_free(s->gconf);
    return ret;
}

static void qemu_archipelago_close(BlockDriverState *bs)
{
    BDRVArchipelagoState *s = bs->opaque;
    int i;
    close(s->fds[0]);
    close(s->fds[1]);
    qemu_aio_set_fd_handler(s->fds[ARCHIP_FD_READ], NULL, NULL, NULL);
    for(i=0; i < NUM_XSEG_THREADS; i++){
        archipelago_th[i].is_running = 0;
    }
    for(i = 0; i < NUM_XSEG_THREADS; i++){
        qemu_mutex_lock(&archipelago_th[i].request_mutex);
        if(!archipelago_th[i].is_signaled)
    	    qemu_cond_wait(&archipelago_th[i].request_cond, &archipelago_th[i].request_mutex);
        qemu_mutex_unlock(&archipelago_th[i].request_mutex);
        qemu_cond_destroy(&archipelago_th[i].request_cond);
        qemu_mutex_destroy(&archipelago_th[i].request_mutex);
    }
    qemu_cond_destroy(&archip_cond);
    qemu_mutex_destroy(&archip_mutex);
    xseg_leave_dynport(xseg, port);
    xseg_leave(xseg);
}

static int qemu_archipelago_create_volume(ArchipelagoConf *gconf)
{
    int ret;
    int targetlen = strlen(gconf->volname);

    struct xseg_request *req = xseg_get_request(xseg, srcport, mportno, X_ALLOC);
    ret = xseg_prep_request(xseg, req, targetlen, sizeof(struct xseg_request_clone));
    if(ret < 0) {
	    archipelagolog("Cannot prepare xseg request.\n");
	    goto err_exit;
    }
    char *target = xseg_get_target(xseg, req);
    if(!target) {
	    archipelagolog("Cannot get xseg target.\n");
	    goto err_exit;
    }
    strncpy(target, gconf->volname, targetlen);
    struct xseg_request_clone *xclone = (struct xseg_request_clone *) xseg_get_data(xseg, req);
    memset(xclone->target, 0 , XSEG_MAX_TARGETLEN);
    xclone->targetlen = 0;
    xclone->size = gconf->size * BDRV_SECTOR_SIZE;
    req->offset = 0;
    req->size = req->datalen;
    req->op = X_CLONE;

    xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
    if(p == NoPort) {
        archipelagolog("Couldn't submit request.\n");
	    goto err_exit;
    }
    xseg_signal(xseg, p);

    ret = wait_reply(req);
    if(ret < 0) {
	    archipelagolog("wait_reply() error. Aborting...\n");
        goto err_exit;
    }
    xseg_put_request(xseg, req, srcport);
    return ret;
err_exit:
    xseg_put_request(xseg, req, srcport);
    return -1;
}

static int qemu_archipelago_create(const char *filename, QEMUOptionParameter *options, Error **errp)
{
    int ret = 0;
    int64_t total_size = 0;
    ArchipelagoConf *gconf = g_malloc0(sizeof(ArchipelagoConf));

    ret = qemu_archipelago_init(gconf, filename);
    if(ret < 0) {
        ret = -errno;
        goto out;
    }

    while(options && options->name) {
        if(!strcmp(options->name, BLOCK_OPT_SIZE)) {
            total_size = options->value.n / BDRV_SECTOR_SIZE;
        }
        options++;
    }
    /* Create Volume in Archipelago */
    gconf->size = total_size;
    qemu_archipelago_create_volume(gconf);
out:
    qemu_archipelago_gconf_free(gconf);
    return ret;
}

static int qemu_archipelago_truncate(BlockDriverState *bs, int64_t offset)
{
    int ret=0;
    //BDRVArchipelagoState *s = bs->opaque;
    //ret = archipelago_volume_truncate(volname, offset)
    if(ret < 0){
        return -errno;
    }
    return 0;
}

static void qemu_archipelago_aio_cancel(BlockDriverAIOCB *blockacb)
{
    ArchipelagoAIOCB *acb = (ArchipelagoAIOCB *) blockacb;
    acb->cancelled = 1;
    while(acb->status == -EINPROGRESS) {
        qemu_aio_wait();
    }
	qemu_aio_release(acb);
}

static const AIOCBInfo archipelago_aiocb_info = {
    .aiocb_size = sizeof(ArchipelagoAIOCB),
    .cancel = qemu_archipelago_aio_cancel,
};

static int qemu_archipelago_signal_pipe(BDRVArchipelagoState *s, ArchipelagoCB *aio_cb)
{
	int ret = 0;
	while(1) {
		fd_set wfd;
		int fd = s->fds[1];

		ret = write(fd, (void *)&aio_cb, sizeof(aio_cb));
		if(ret > 0) {
			break;
		}
		if(errno == EINTR) {
			continue;
		}
		if(errno != EAGAIN) {
			break;
		}
		FD_ZERO(&wfd);
		FD_SET(fd, &wfd);
		do {
			ret = select(fd + 1, NULL, &wfd, NULL, NULL);
		} while( ret < 0 && errno == EINTR);
	}
	return ret;
}

static void archipelago_aio_bh_cb(void *opaque)
{
    ArchipelagoAIOCB *acb = opaque;
    if(acb->cmd == ARCHIP_AIO_READ) {
        qemu_iovec_from_buf(acb->qiov, 0, acb->buffer, acb->qiov->size);
    }

    qemu_vfree(acb->buffer);
    acb->common.cb(acb->common.opaque, (acb->ret > 0 ? 0 : acb->ret));
    qemu_bh_delete(acb->bh);
    acb->bh = NULL;
    acb->status = 0;

    if(!acb->cancelled) {
        qemu_aio_release(acb);
    }
}

static int archipelago_aio_read(char *volname, char *buf, ssize_t count,
        off_t offset, ArchipelagoCB *aio_cb)
{
    int ret;
    AIORequestData *reqdata = g_malloc(sizeof(AIORequestData));
    int targetlen = strlen(volname);
    struct xseg_request *req = xseg_get_request(xseg, srcport, vportno, X_ALLOC);
    if(!req) {
        archipelagolog("Cannot get xseg request.\n");
	    goto err_exit2;
    }
    ret = xseg_prep_request(xseg, req, targetlen, count);
    if(ret < 0) {
        archipelagolog("Cannot prepare xseg request.\n");
	    goto err_exit;
    }
    char *target = xseg_get_target(xseg, req);
    if(!target) {
        archipelagolog("Cannot get xseg target.\n");
	    goto err_exit;
    }
    strncpy(target, volname, targetlen);
    req->size = count;
    req->offset = offset;
    req->op = X_READ;
    //req->flags |= XF_FLUSH;

    reqdata->volname = volname;
    reqdata->offset = offset;
    reqdata->size = count;
    reqdata->buf = buf;
    reqdata->aio_cb = aio_cb;
    reqdata->write = ARCHIP_AIO_READ;

    xseg_set_req_data(xseg, req, reqdata);
    xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
    if(p == NoPort) {
        archipelagolog("Could not submit xseg request.\n");
	    goto err_exit;
    }
    xseg_signal(xseg, p);
    return 0;
err_exit:
    xseg_put_request(xseg, req, srcport);
    return -1;
err_exit2:
    return -1;
}

static int archipelago_aio_write(char  *volname, char *buf, ssize_t count, off_t offset, ArchipelagoCB *aio_cb)
{
    char *data = NULL;
    int ret;
    AIORequestData *reqdata = g_malloc(sizeof(AIORequestData));
    int targetlen = strlen(volname);
    struct xseg_request *req = xseg_get_request(xseg, srcport, vportno, X_ALLOC);
    if(!req) {
        archipelagolog("Cannot get xseg request.\n");
	    goto err_exit2;
    }
    ret = xseg_prep_request(xseg, req, targetlen, count);
    if( ret < 0) {
        archipelagolog("Cannot prepare xseg request.\n");
	    goto err_exit;
    }
    char *target = xseg_get_target(xseg, req);
    if(!target) {
        archipelagolog("Cannot get xseg target.\n");
	    goto err_exit;
    }
    strncpy(target, volname, targetlen);
    req->size = count;
    req->offset = offset;
    req->op = X_WRITE;
    //req->flags |= XF_FLUSH;

    reqdata->volname = volname;
    reqdata->offset = offset;
    reqdata->size = count;
    reqdata->buf = buf;
    reqdata->aio_cb = aio_cb;
    reqdata->write = ARCHIP_AIO_WRITE;

    xseg_set_req_data(xseg, req, reqdata);

    data = xseg_get_data(xseg, req);
    if(!data) {
        archipelagolog("Cannot get xseg data.\n");
	    goto err_exit;
    }
    memcpy(data, buf, count);

    xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
    if(p == NoPort) {
        archipelagolog("Could not submit xseg request.\n");
	    goto err_exit;
    }
    xseg_signal(xseg, p);
    return 0;
err_exit:
    xseg_put_request(xseg, req, srcport);
    return -1;
err_exit2:
    return -1;
}

static BlockDriverAIOCB *qemu_archipelago_aio_rw(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque, int op)
{
    ArchipelagoAIOCB *acb;
    ArchipelagoCB *aio_cb;
    BDRVArchipelagoState *s = bs->opaque;
    int64_t size, off;
    char *buf;
    int ret;

    acb = qemu_aio_get(&archipelago_aiocb_info, bs, cb, opaque);
    acb->cmd = op;
    acb->qiov = qiov;
    acb->buffer = qemu_blockalign(bs, qiov->size);
    acb->ret = 0;
    acb->error = 0;
    acb->s = s;
    acb->cancelled = 0;
    acb->bh = NULL;
    acb->status = -EINPROGRESS;

    if(op) {
	 qemu_iovec_to_buf(acb->qiov, 0, acb->buffer, qiov->size);
    }

    buf= acb->buffer;
    off = sector_num * BDRV_SECTOR_SIZE;
    size = nb_sectors * BDRV_SECTOR_SIZE;

    s->qemu_aio_count++;

    aio_cb = g_malloc(sizeof(ArchipelagoCB));
    aio_cb->done = 0;
    aio_cb->acb = acb;
    aio_cb->buf = buf;
    aio_cb->s =  acb->s;
    aio_cb->size = size;

    if(op) {
        ret = archipelago_aio_write(s->gconf->volname, buf, size, off, aio_cb);
    }  else {
        ret = archipelago_aio_read(s->gconf->volname, buf, size, off, aio_cb);
    }

    if( ret < 0) {
        goto out;
    }
    return &acb->common;

out:
    error_report("qemu_archipelago_aio_rw(): I/O Error. Aborting...\n");
    s->qemu_aio_count--;
    g_free(aio_cb);
    qemu_aio_release(acb);
    return NULL;
}

static BlockDriverAIOCB *qemu_archipelago_aio_readv(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return qemu_archipelago_aio_rw(bs, sector_num, qiov, nb_sectors, cb,
            opaque, ARCHIP_AIO_READ);
}

static BlockDriverAIOCB *qemu_archipelago_aio_writev(BlockDriverState *bs,
        int64_t sector_num, QEMUIOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque)
{
    return qemu_archipelago_aio_rw(bs, sector_num, qiov, nb_sectors, cb,
            opaque, ARCHIP_AIO_WRITE);
}

static int64_t archipelago_volume_info(char *volname)
{
    int64_t size;
    int ret;
    AIORequestData *reqdata = g_malloc(sizeof(AIORequestData));
    int targetlen = strlen(volname);
    struct xseg_request *req = xseg_get_request(xseg, srcport, mportno, X_ALLOC);
    ret = xseg_prep_request(xseg, req, targetlen, sizeof(struct xseg_reply_info));
    if(ret < 0){
	    archipelagolog("Cannot prepare xseg request.\n");
	    goto err_exit;
    }
    char *target = xseg_get_target(xseg, req);
    if(!target) {
	    archipelagolog("Cannot get xseg target.\n");
	    goto err_exit;
    }
    strncpy(target, volname, targetlen);
    req->size = req->datalen;
    req->offset = 0;
    req->op = X_INFO;

    reqdata->write = ARCHIP_AIO_VOLINFO;
    reqdata->volname = volname;
    xseg_set_req_data(xseg, req, reqdata);

    xport p = xseg_submit(xseg, req, srcport, X_ALLOC);
    if(p == NoPort) {
        archipelagolog("Cannot submit xseg request.\n");
	    goto err_exit;
    }
    xseg_signal(xseg, p);
    qemu_mutex_lock(&archip_mutex);
    if(!is_signaled)
        qemu_cond_wait(&archip_cond, &archip_mutex);
    is_signaled = 0;
    qemu_mutex_unlock(&archip_mutex);

    struct xseg_reply_info *xinfo = (struct xseg_reply_info *) xseg_get_data(xseg, req);
    size = xinfo->size;
    xseg_put_request(xseg, req, srcport);
    return size;
err_exit:
    xseg_put_request(xseg, req, srcport);
    return -1;
}

static int64_t qemu_archipelago_getlength(BlockDriverState *bs)
{
    BDRVArchipelagoState *s = bs->opaque;
    int64_t ret;
    ret = archipelago_volume_info(s->gconf->volname);
    if(ret < 0) {
        return -errno;
    } else {
        return ret;
    }
}

static QEMUOptionParameter qemu_archipelago_create_options[] = {
    {
        .name = BLOCK_OPT_SIZE,
        .type = OPT_SIZE,
        .help = "Virtual disk size"
    },
    {NULL}
};

static int qemu_archipelago_co_flush(BlockDriverState *bs)
{
    return 0;
}

static BlockDriver bdrv_archipelago = {
    .format_name = "archipelago",
    .protocol_name = "archipelago",
    .instance_size = sizeof(BDRVArchipelagoState),
    .bdrv_file_open = qemu_archipelago_open,
    .bdrv_close = qemu_archipelago_close,
    .bdrv_create = qemu_archipelago_create,
    .bdrv_getlength = qemu_archipelago_getlength,
    .bdrv_truncate = qemu_archipelago_truncate,
    .bdrv_aio_readv = qemu_archipelago_aio_readv,
    .bdrv_aio_writev = qemu_archipelago_aio_writev,
    .bdrv_co_flush_to_disk = qemu_archipelago_co_flush,
    .bdrv_has_zero_init = bdrv_has_zero_init_1,
    .create_options = qemu_archipelago_create_options,
};

static void bdrv_archipelago_init(void)
{
    bdrv_register(&bdrv_archipelago);
}

block_init(bdrv_archipelago_init);
