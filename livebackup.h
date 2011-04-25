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

#include "block.h"
#include "block_int.h"

/*********************** Begin Protocol Definition ****************************/
typedef struct _backup_request {
    int64_t	opcode;
#define B_NOOP			0
#define B_GET_VDISK_COUNT	1
#define B_DO_SNAP		2
#define B_GET_BLOCKS		3
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
    int64_t	max_blocks;
    int64_t     dirty_blocks;
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

typedef struct _get_blocks_result {
    int64_t             status;
#define B_GET_BLOCKS_SUCCESS                 0
#define B_GET_BLOCKS_NO_MORE_BLOCKS          1
#define B_GET_BLOCKS_ERROR_UNKNOWN          -1
#define B_GET_BLOCKS_ERROR_NO_SNAP_AVAIL    -2
#define B_GET_BLOCKS_ERROR_INVALID_DISK     -3
#define B_GET_BLOCKS_ERROR_IOREAD           -4
#define B_GET_BLOCKS_ERROR_BASE_FILE        -5
    int64_t             offset;
    int64_t             blocks;
} get_blocks_result;
#define BACKUP_MAX_BLOCKS_IN_1_RESP          32
#define BACKUP_BLOCK_SIZE                    512

typedef struct _destroy_snap_result {
    int64_t		status;
#define B_DESTROY_SNAP_SUCCESS               0
#define B_DESTROY_SNAP_ERROR_NO_SNAP        -1
} destroy_snap_result;

/************************* End Protocol Definition ****************************/

static unsigned char mp[8] = { 128, 64, 32, 16, 8, 4, 2, 1};
static unsigned char mpo[8] = { 127, 191, 223, 239, 247, 251, 253, 254};

static inline void set_block_dirty(unsigned char *bitmap, int64_t sector_num, int64_t *count_ptr)
{
    int64_t off = sector_num/8;
    int64_t bitoff = sector_num%8;
    uint8_t ch = *(bitmap + off);
    if (ch & mpo[bitoff]) {
        *(bitmap + off) = ch | mp[bitoff];
    } else {
        *(bitmap + off) = ch | mp[bitoff];
        *count_ptr = (*count_ptr) + 1;
    }
}

static inline void set_blocks_dirty(unsigned char *bitmap,
                    int64_t sector_num, int nb_sectors,
                    int64_t *count_ptr) {
    int i;
    for (i = 0; i < nb_sectors; i++) {
        set_block_dirty(bitmap, sector_num + i, count_ptr);
    }
}

static inline int
is_block_dirty(unsigned char *dirty_bitmap, int64_t block)
{
    unsigned char ch = *(dirty_bitmap + (block/8));
    unsigned char ch1 = ch & mp[block%8];
    if (ch1 != 0) {
	return 1;
    } else {
        return 0;
    }
}

/*
 * return offset >= 0 of next available dirty block
 * return < 0 if there are no more dirty blocks
 */
static inline int
get_next_dirty_block_offset(unsigned char *dirty_bitmap, int64_t max_blocks_in_dirty_bitmap,
        int64_t curblock, int maxblocks,
        int64_t *ret_block, int *ret_dirty_blocks)
{
    while (curblock < max_blocks_in_dirty_bitmap) {
        if (is_block_dirty(dirty_bitmap, curblock)) {
            int i;
            for (i = 1; i < maxblocks; i++) {
                if (!is_block_dirty(dirty_bitmap, curblock + i)) {
                    break;
                }
            }
            *ret_block = curblock;
            *ret_dirty_blocks = i;
            return 0;
        }
        curblock++;
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


typedef struct _backup_disk {
    backup_disk_info bdinfo;
    char        conf_file[PATH_MAX];
    char        snap_file[PATH_MAX];
    char        dirty_bitmap_file[PATH_MAX];
    int         dirty_bitmap_len;
    /*
     * backup_base_bs and backup_cow_bs are used
     * only by the backup_disk struct in the snap,
     * not in the main drive list
     */
    BlockDriverState *backup_base_bs;
    BlockDriverState *backup_cow_bs;
    unsigned char *dirty_bitmap;
    unsigned char *in_cow_bitmap;
    int64_t       in_cow_bitmap_count;
    /*
     * snap_backup_disk is used only 
     * in the main drive list
     * and not in the backup_disk struct in the snap
     * It is used to save a pointer to the backup_disk
     * struct in the snapshot
     */
    struct _backup_disk *snap_backup_disk;
    struct _backup_disk *next;
} backup_disk;

typedef struct _snapshot {
    backup_disk *backup_disks;
    BlockDriver *backup_snap_drv;
    unsigned char *backup_tmp_buffer;
} snapshot;

typedef struct _aiowr_interposer {
    /* bs of original write that we intercepted */
    BlockDriverState *bs;

    unsigned int state;
#define AIOWR_INTERPOSER_COW_READ	1
#define AIOWR_INTERPOSER_COW_WRITE	2
#define AIOWR_INTERPOSER_ACTUAL_WRITE	3
    /* Params to the original bdrv_aio_write */
    BlockDriverCompletionFunc *cb;
    void *opaque;
    int64_t sector_num;
    int nb_sectors;
    QEMUIOVector *qiov;

    /* members used for the COW read and write */
    uint8_t *cow_tmp_buffer;
    QEMUIOVector *cow_tmp_qiov;

    struct _aiowr_interposer *next;
} aiowr_interposer;

backup_disk *open_dirty_bitmap(const char *filename);
void close_dirty_bitmap(BlockDriverState *bs);
void aiowrite_cb_interposer(void *opaque, int ret);
void set_dirty(BlockDriverState *bs, int64_t sector_num,
                                 int nb_sectors);
BlockDriverAIOCB *set_dirty_and_start_async(BlockDriverState *bs, int64_t sector_num,
                                 QEMUIOVector *qiov, int nb_sectors,
                                 BlockDriverCompletionFunc *cb, void *opaque);
int start_backup_listener(void);

#endif /* _LIVEBACKUP_H_ */
