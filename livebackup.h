/*
 * QEMU livebackup
 *
 * Copyright (c) Jagane Sundar
 *
 * Authors:
 *  Jagane Sundar (jagane@sundar.org)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _LIVEBACKUP_H_
#define _LIVEBACKUP_H_

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "block.h"
#include "block_int.h"

/*********************** Begin Protocol Definition ****************************/
typedef struct _backup_request {
    int64_t	opcode;
#define B_NOOP              0
#define B_GET_VDISK_COUNT   1
#define B_DO_SNAP           2
#define B_GET_CLUSTERS		3
#define B_DESTROY_SNAP		4
    int64_t	param1;
#define B_DO_SNAP_INCRBACKUP	0
#define B_DO_SNAP_FULLBACKUP	1
    int64_t	param2;
} backup_request;

typedef struct _get_vdisk_count_result {
    int64_t		status;
} get_vdisk_count_result;

typedef struct _backup_disk_info {
    char        name[PATH_MAX];
    int64_t     max_clusters;
    int64_t     dirty_clusters;
    int64_t     full_backup_mtime;
    int64_t     snapnumber;
} backup_disk_info;

typedef struct _do_snap_result {
    int64_t		status;
#define B_DO_SNAP_RES_SUCCESS                0
#define B_DO_SNAP_RES_ALREADY               -1
#define B_DO_SNAP_RES_NOMEM                 -2
#define B_DO_SNAP_RES_PENDING_WRITES        -3
} do_snap_result;

typedef struct _get_clusters_result {
    int64_t             status;
#define B_GET_CLUSTERS_SUCCESS                 0
#define B_GET_CLUSTERS_NO_MORE_CLUSTERS        1
#define B_GET_CLUSTERS_ERROR_UNKNOWN          -1
#define B_GET_CLUSTERS_ERROR_NO_SNAP_AVAIL    -2
#define B_GET_CLUSTERS_ERROR_INVALID_DISK     -3
#define B_GET_CLUSTERS_ERROR_IOREAD           -4
#define B_GET_CLUSTERS_ERROR_BASE_FILE        -5
    int64_t             offset;
    int64_t             clusters;
} get_clusters_result;
#define BACKUP_MAX_CLUSTERS_IN_1_RESP       4
#define BACKUP_BLOCK_SIZE                    512
#define BACKUP_CLUSTER_SIZE                 4096
#define BACKUP_BLOCKS_PER_CLUSTER           (BACKUP_CLUSTER_SIZE/BACKUP_BLOCK_SIZE)

typedef struct _destroy_snap_result {
    int64_t		status;
#define B_DESTROY_SNAP_SUCCESS               0
#define B_DESTROY_SNAP_ERROR_NO_SNAP        -1
} destroy_snap_result;

/************************* End Protocol Definition ****************************/

static unsigned char mp[8] = { 128, 64, 32, 16, 8, 4, 2, 1};
// static unsigned char mpo[8] = { 127, 191, 223, 239, 247, 251, 253, 254};

static inline void set_cluster_dirty(unsigned char *bitmap, int64_t cluster_num,
                    int64_t *count_ptr)
{
    int64_t off = cluster_num/8;
    int64_t bitoff = cluster_num%8;
    uint8_t ch = *(bitmap + off);
    if ((ch & mp[bitoff]) == 0) {
        *(bitmap + off) = ch | mp[bitoff];
        *count_ptr = (*count_ptr) + 1;
    }
}

static inline void set_blocks_dirty(unsigned char *bitmap,
                    int64_t sector_num, int nb_sectors,
                    int64_t *count_ptr) {
    int64_t first_cluster;
    int64_t last_cluster;
    int64_t i;

    first_cluster = sector_num / BACKUP_BLOCKS_PER_CLUSTER;
    last_cluster = (sector_num + nb_sectors + BACKUP_BLOCKS_PER_CLUSTER -1)
                    / BACKUP_BLOCKS_PER_CLUSTER;
    for (i = first_cluster; i < last_cluster; i++) {
        set_cluster_dirty(bitmap, i, count_ptr);
    }
}

static inline int
is_cluster_dirty(unsigned char *dirty_bitmap, int64_t cluster)
{
    unsigned char ch = *(dirty_bitmap + (cluster/8));
    unsigned char ch1 = ch & mp[cluster%8];
    if (ch1 != 0) {
        return 1;
    } else {
        return 0;
    }
}

static inline int
is_block_dirty(unsigned char *dirty_bitmap, int64_t block)
{
    int64_t cluster = block/BACKUP_BLOCKS_PER_CLUSTER;
    return is_cluster_dirty(dirty_bitmap, cluster);
}

/*
 * return 0 with ret_cluster set to next available dirty cluster
 * return < 0 if there are no more dirty clusters
 */
static inline int
get_next_dirty_cluster_offset(unsigned char *dirty_bitmap,
        int64_t max_clusters_in_dirty_bitmap,
        int64_t curcluster, int maxclusters,
        int64_t *ret_cluster, int *ret_dirty_clusters)
{
    while (curcluster < max_clusters_in_dirty_bitmap) {
        if (is_cluster_dirty(dirty_bitmap, curcluster)) {
            int i;
            for (i = 1; i < maxclusters; i++) {
                if (!is_cluster_dirty(dirty_bitmap, curcluster + i)) {
                    break;
                }
            }
            *ret_cluster = curcluster;
            *ret_dirty_clusters = i;
            return 0;
        }
        curcluster++;
    }
    return -1;
}

static inline int
read_bytes(int fd, unsigned char *buf, int len)
{
    int br = 0;
    while (br < len) {
        int rv = recv(fd, buf + br, len - br, 0);
        if (rv > 0) {
            br += rv;
        } else if (rv == 0) {
            return br;
        } else {
            if (br > 0) {
                return br;
            } else {
                return -1;
            }
        }
    }
    return br;
}

static inline int
write_bytes(int fd, unsigned char *buf, int len)
{
    int bw = 0;
    while (bw < len) {
        int rv = send(fd, buf + bw, len - bw, 0);
        if (rv > 0) {
            bw += rv;
        } else if (rv == 0) {
            return bw;
        } else {
            if (bw > 0) {
                return bw;
            } else {
                return -1;
            }
        }
    }
    return bw;
}

static inline int
parse_conf_file(char *cfil, int64_t *full_backup_mtimep, int64_t *snapp)
{
    FILE *cfp = fopen(cfil, "r");
    char cf[256];
    int got_fb = 0;
    int got_sn = 0;

    if (!cfp) {
        fprintf(stderr,
                    "parse_conf_file: Error %d reading conf file %s\n",
                    errno, cfil);
        return -1;
    }

    while (fgets(cf, sizeof(cf), cfp)) {
        if (sscanf(cf, "full_backup_mtime=%ld", full_backup_mtimep) == 1) {
             got_fb++;
             continue;
        } else if (sscanf(cf, "snapnumber=%ld", snapp)) {
             got_sn++;
             continue;
        }
    }

    if (got_fb > 0 && got_sn > 0) {
        return 0;
    } else {
        return -1;
    }
}

static inline int
write_conf_file(char *cfil, int64_t gen, int64_t snap)
{
    FILE *cfp = fopen(cfil, "w+");
    if (!cfp) {
        fprintf(stderr,
                    "write_conf_file: Error %d creating conf file %s\n",
                    errno, cfil);
        return -1;
    } else {
        fprintf(cfp, "full_backup_mtime=%ld\n", gen);
        fprintf(cfp, "snapnumber=%ld\n", snap);
        fflush(cfp);
        fsync(fileno(cfp));
        fclose(cfp);
        return 0;
    }
}

/*
 * backup_disk_base stores information that is common
 * to livebackup_snap and livebackup_disk.
 */
typedef struct _backup_disk_base {
    backup_disk_info bdinfo;
    char        conf_file[PATH_MAX];
    char        snap_file[PATH_MAX];
    char        dirty_bitmap_file[PATH_MAX];
    int         dirty_bitmap_len;
    unsigned char *dirty_bitmap;
} backup_disk_base;

/*
 * livebackup_snap stores the state of a single virtual drive in
 * the snapshot structure.
 */
typedef struct _livebackup_snap {
    backup_disk_base bd_base;
    BlockDriverState *backup_base_bs;
    BlockDriverState *backup_cow_bs;
    unsigned char *in_cow_bitmap;
    int64_t       in_cow_bitmap_count;
    struct _livebackup_snap *next;
} livebackup_snap;

/*
 * livebackup_disk stores the state of a single virtual drive in
 * during normal operation of the VM
 */
typedef struct _livebackup_disk {
    backup_disk_base bd_base;
    livebackup_snap *snap_backup_disk; /* points to the snap, if snap active */
    struct _livebackup_disk *next;
} livebackup_disk;

/*
 * At any given time, there can be a single snapshot
 * called in_progress_snap in the system.
 */
typedef struct _snapshot {
    livebackup_snap *backup_disks; /* List of virtual drives in livebackup */
    BlockDriver *backup_snap_drv; /* driver used for livebackup COW (qcow2) */
    unsigned char *backup_tmp_buffer;   /* used for sync I/O copy cow and */
                                        /* reading in blocks to write to */
                                        /* the client over the socket */
    int destroy;
} snapshot;

typedef struct _aiowr_interposer_cluster {
    int64_t first_cluster;
    int64_t last_cluster;
    uint8_t *cow_tmp_buffer;
    QEMUIOVector *cow_tmp_qiov;
    int ret;
    int state;
#define AIOWR_CLUSTER_COWRD 1
#define AIOWR_CLUSTER_COWWR 2
#define AIOWR_CLUSTER_DONE 3
    struct _aiowr_interposer_cluster *next;
    struct _aiowr_interposer *up;
} aiowr_interposer_cluster;

typedef struct _aiowr_interposer {
    /* bs of original write that we intercepted */
    BlockDriverState *bs;

    /* Params to the original bdrv_aio_write that we intercepted */
    BlockDriverCompletionFunc *cb;
    void *opaque;
    int64_t sector_num;
    int nb_sectors;
    QEMUIOVector *qiov;

    /* cluster that we are COWing */
    aiowr_interposer_cluster *clusters;

    struct _aiowr_interposer *next;
} aiowr_interposer;

livebackup_disk *open_dirty_bitmap(const char *filename);
void close_dirty_bitmap(BlockDriverState *bs);
void set_dirty(BlockDriverState *bs, int64_t sector_num,
                                 int nb_sectors);
BlockDriverAIOCB *livebackup_interposer(BlockDriverState *bs,
                                int64_t sector_num,
                                 QEMUIOVector *qiov, int nb_sectors,
                                 BlockDriverCompletionFunc *cb, void *opaque);
int start_backup_listener(void);
void livebackup_flush(BlockDriverState *bs);

#endif /* _LIVEBACKUP_H_ */
