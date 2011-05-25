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

#include "livebackup.h"

static livebackup_disk *backup_disks = NULL;

static aiowr_interposer *aiowr_interposers = NULL;

static pthread_mutex_t backup_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t backup_cond = PTHREAD_COND_INITIALIZER;
static int waiting_for_aio_writes_to_be_done = 0;
static snapshot *in_progress_snap = NULL;

char *livebackup_port;
char *livebackup_dir;

static void
remove_from_interposer_list(aiowr_interposer *ac)
{
    aiowr_interposer *prev, *cur;
    cur = aiowr_interposers;
    prev = NULL;
    while (cur) {
        if (cur == ac) {
            if (prev)
                prev->next = cur->next;
            else
                aiowr_interposers = cur->next;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
}

/*
 * Checks if any of the entries in the
 * aiowr_interposer list have a COW
 * read or write pending. If so, return
 * 1, otherwise return 0
 */
static int
check_interposer_list_for_cow(void)
{
    aiowr_interposer *cur = aiowr_interposers;
    while (cur) {
        if (cur->clusters) {
            return 1;
        }
        cur = cur->next;
    }
    return 0;
}

/*
 * must be called while holding the backup_mutex
 */
static void
actually_destroy_snap(void)
{
    livebackup_snap *itr;
    livebackup_disk *bitr;

    if (!in_progress_snap) {
        return;
    }

    if (in_progress_snap->backup_tmp_buffer)
        qemu_free(in_progress_snap->backup_tmp_buffer);

    /* walk the list of backup_disks in this snapshot and clean them out */
    itr = in_progress_snap->backup_disks;
    while (itr != NULL) {
        livebackup_snap *save;
        qemu_free(itr->bd_base.dirty_bitmap);
        qemu_free(itr->in_cow_bitmap);
        if (itr->backup_base_bs) bdrv_close(itr->backup_base_bs);
        if (itr->backup_cow_bs) bdrv_close(itr->backup_cow_bs);
        unlink(itr->bd_base.snap_file);
        save = itr;
        itr = itr->next;
        qemu_free(save);
    }

    /* in the list of this VM's backup_disks, NULL out the ptr to the snap */
    bitr = backup_disks;
    while (bitr != NULL) {
        bitr->snap_backup_disk = NULL;
        bitr = bitr->next;
    }

    qemu_free(in_progress_snap);
    in_progress_snap = NULL;
}

static void
free_aiowr_interposer_cluster(aiowr_interposer *ac)
{
    if (ac->clusters) {
        aiowr_interposer_cluster *to_free = ac->clusters;
        aiowr_interposer_cluster *save = NULL;
        while (to_free) {
            save = to_free->next;
            if (to_free->cow_tmp_buffer) {
                qemu_free(to_free->cow_tmp_buffer);
            }
            if (to_free->cow_tmp_qiov) {
                qemu_iovec_destroy(to_free->cow_tmp_qiov);
                qemu_free(to_free->cow_tmp_qiov);
            }
            qemu_free(to_free);
            to_free = save;
        }
        ac->clusters = NULL;
    }
}

static void
aiowrite_cb_interposer_realwr(void *opaque, int ret)
{
    aiowr_interposer *ac = (aiowr_interposer *)opaque;
    BlockDriverCompletionFunc *saved_cb;
    void *saved_opaque;
    BlockDriverState *bs;
    livebackup_disk *bd;

    /* Actual write completed. */
    pthread_mutex_lock(&backup_mutex);

    saved_cb = ac->cb;
    saved_opaque = ac->opaque;

    bs = ac->bs;
    bd = bs->livebackup_disk;
    if (!bd) {
        fprintf(stderr, "aiowrite_cb_interposer_realwr: Error. bd null\n");
        ret = -1;
    }

    free_aiowr_interposer_cluster(ac);
    remove_from_interposer_list(ac);
    free(ac);

    /*
     * If in_progress_snap->destroy is set, then
     * check all the items in our interposer list
     * If we have no pending COW reads or writes,
     * then destroy the snap
     */
    if (in_progress_snap && in_progress_snap->destroy) {
        if (!check_interposer_list_for_cow()) {
            actually_destroy_snap();
        }
    }

    /*
     * If our interposer list is empty, and we have a
     * snap request waiting, signal that thread.
     */
    if (aiowr_interposers == NULL) {
        if (waiting_for_aio_writes_to_be_done) {
            pthread_cond_signal(&backup_cond);
        }
    }
    pthread_mutex_unlock(&backup_mutex);
    saved_cb(saved_opaque, ret);
}

static void
aiowrite_cb_interposer_cow(void *opaque, int ret)
{
    aiowr_interposer_cluster *ac_cl = (aiowr_interposer_cluster *)opaque;
    aiowr_interposer *ac = NULL;
    aiowr_interposer_cluster *ac_cl_iter = NULL;
    BlockDriverState *bs = NULL;
    livebackup_disk *bd = NULL;
    livebackup_snap *snap_bd = NULL;

    pthread_mutex_lock(&backup_mutex);

    /* get a bunch of backpointers with careful validity checking */
    ac = ac_cl->up; /* backpointer from cluster to interposer state */
    bs = ac->bs;
    bd = bs->livebackup_disk; /* backptr from interposer to livebackup_disk */
    if (!bd) {
        fprintf(stderr, "aiowrite_cb_interposer_cow: Error. bd null\n");
        goto unlock_and_exit;
    }
    snap_bd = bd->snap_backup_disk; /* backptr from livebackup_disk to snap */

    ac_cl->ret = ret;
    if (ac_cl->state == AIOWR_CLUSTER_COWRD) {
        if (ret == 0) {
            ac_cl->state = AIOWR_CLUSTER_COWWR;
            bdrv_aio_writev(snap_bd->backup_cow_bs,
                ac_cl->first_cluster * BACKUP_BLOCKS_PER_CLUSTER,
                ac_cl->cow_tmp_qiov,
                (ac_cl->last_cluster-ac_cl->first_cluster)
                            * BACKUP_BLOCKS_PER_CLUSTER,
                aiowrite_cb_interposer_cow, ac_cl);
        } else {
            ac_cl->state = AIOWR_CLUSTER_DONE;
        }
    } else if (ac_cl->state == AIOWR_CLUSTER_COWWR) {
        int64_t i;

        for (i = ac_cl->first_cluster; i < ac_cl->last_cluster; i++) {
            /* Set this cluster's bit in the in_cow_bitmap */
            set_cluster_dirty(snap_bd->in_cow_bitmap,
                                            i, &snap_bd->in_cow_bitmap_count);
        }
        ac_cl->state = AIOWR_CLUSTER_DONE;
    }
    /* check if all clusters' COW read and write is complete */
    ac_cl_iter = ac->clusters;
    while (ac_cl_iter) {
        if (ac_cl_iter->state != AIOWR_CLUSTER_DONE)
            goto unlock_and_exit;
        ac_cl_iter = ac_cl_iter->next;
    }
    free_aiowr_interposer_cluster(ac);
    /* All clusters' COW read and write is complete */
    bs->drv->bdrv_aio_writev(bs, ac->sector_num, ac->qiov,
                        ac->nb_sectors, aiowrite_cb_interposer_realwr, ac);

unlock_and_exit:
    pthread_mutex_unlock(&backup_mutex);
}

static BlockDriverAIOCB *
make_aio_cluster(int64_t cur_first_cluster, int64_t cur_last_cluster,
                livebackup_snap *snap_bd, aiowr_interposer *ac)
{
    BlockDriverAIOCB *ret = NULL;
    aiowr_interposer_cluster *ac_cl = qemu_mallocz(sizeof(*ac_cl));

    ac_cl->first_cluster = cur_first_cluster;
    ac_cl->last_cluster = cur_last_cluster;
    ac_cl->cow_tmp_buffer = qemu_memalign(512,
                    (ac_cl->last_cluster - ac_cl->first_cluster)
                                * BACKUP_CLUSTER_SIZE);
    ac_cl->cow_tmp_qiov = qemu_mallocz(sizeof(*ac_cl->cow_tmp_qiov));
    ac_cl->state = AIOWR_CLUSTER_COWRD;
    qemu_iovec_init(ac_cl->cow_tmp_qiov, 1);
    qemu_iovec_add(ac_cl->cow_tmp_qiov, ac_cl->cow_tmp_buffer,
                    (ac_cl->last_cluster - ac_cl->first_cluster)
                                * BACKUP_CLUSTER_SIZE);
    ret = snap_bd->backup_base_bs->drv->bdrv_aio_readv(
            snap_bd->backup_base_bs,
            ac_cl->first_cluster * BACKUP_BLOCKS_PER_CLUSTER,
            ac_cl->cow_tmp_qiov,
            (ac_cl->last_cluster - ac_cl->first_cluster)
                * BACKUP_BLOCKS_PER_CLUSTER,
            aiowrite_cb_interposer_cow, ac_cl);
    ac_cl->up = ac;
    ac_cl->next = ac->clusters;
    ac->clusters = ac_cl;
    return ret;
}

/*
 * Every write to a livebackup drive is intercepted, and
 * its state is maintained in our list of pending writes
 * aiowr_interposers. Before starting a snapshot, the
 * aiowr_interposers list must be empty. We wait upto 40
 * seconds for this list to empty.
 * During a snapshot, we create a COW file of all writes
 * to the base drive before scheduling the write to the
 * base drive.
 */
BlockDriverAIOCB *
livebackup_interposer(BlockDriverState *bs, int64_t sector_num,
                                 QEMUIOVector *qiov, int nb_sectors,
                                 BlockDriverCompletionFunc *cb, void *opaque)
{
    aiowr_interposer *ac = NULL;
    BlockDriverAIOCB *ret = NULL;

    pthread_mutex_lock(&backup_mutex);
    if (bs->livebackup_disk) {
        livebackup_disk *bd = (livebackup_disk *) bs->livebackup_disk;

        /* set the blocks as dirty in this livebackup drive's dirty bitmap */
        set_blocks_dirty(bd->bd_base.dirty_bitmap, sector_num, nb_sectors,
                                    &bd->bd_base.bdinfo.dirty_clusters);

        ac = calloc(1, sizeof(aiowr_interposer));
        ac->bs = bs;
        ac->cb = cb;
        ac->opaque = opaque;
        ac->sector_num = sector_num;
        ac->qiov = qiov;
        ac->nb_sectors = nb_sectors;
        ac->next = aiowr_interposers;
        aiowr_interposers = ac;

        /* if there is no snapshot in progress, then schedule the actual wr */
        if (!in_progress_snap || in_progress_snap->destroy) {
            /* COW is not necessary. Initiate the actual write */
            goto schedule_real_wr;
        }

        /*
         * For every cluster that this write specifies, check
         * if we need to do a COW of the original cluster.
         */
        int64_t first_cluster;
        int64_t last_cluster;
        int64_t i;
        int64_t cur_first_cluster;
        int64_t cur_last_cluster;
        livebackup_snap *snap_bd = bd->snap_backup_disk;

        first_cluster = sector_num / BACKUP_BLOCKS_PER_CLUSTER;
        last_cluster = (sector_num+nb_sectors+BACKUP_BLOCKS_PER_CLUSTER-1)
                            /BACKUP_BLOCKS_PER_CLUSTER;

        i = cur_first_cluster = cur_last_cluster = first_cluster;
        while (i < last_cluster) {
            if (is_cluster_dirty(snap_bd->bd_base.dirty_bitmap, i) &&
                            !is_cluster_dirty(snap_bd->in_cow_bitmap, i)) {
                i++;
                cur_last_cluster = i;
            } else {
                if (cur_last_cluster > cur_first_cluster) {
                    ret = make_aio_cluster(cur_first_cluster,
                                            cur_last_cluster, snap_bd,
                                            ac);
                }
                i++;
                cur_first_cluster = cur_last_cluster = i;
            }
        }
        if (cur_last_cluster > cur_first_cluster) {
            ret = make_aio_cluster(cur_first_cluster,
                                    cur_last_cluster, snap_bd,
                                    ac);
        }
        if (ac->clusters == NULL) {
             /* No cow necessary. Start real wr */
            goto schedule_real_wr;
        } else {
            goto unlock_and_exit;
        }

schedule_real_wr:
        ret = bs->drv->bdrv_aio_writev(bs, sector_num, qiov,
                                nb_sectors, aiowrite_cb_interposer_realwr, ac);
        /* Fall through to unlock and exit ... */
    }
unlock_and_exit:
    pthread_mutex_unlock(&backup_mutex);
    return ret;
}

/*
 * you must call this function while
 * holding the backup_mutex
 */
static void
wait_for_aio_empty(int num_tensecs)
{
    if (aiowr_interposers != NULL) {
        int retries;
        for (retries = 0; retries < num_tensecs; retries++) {
            struct timespec tms;
            clock_gettime(CLOCK_REALTIME, &tms);
            tms.tv_sec += 10;

            /*
             * There are outstanding writes. Wait for those to be done
             * before doing the snapshot.
             */
            waiting_for_aio_writes_to_be_done = 1;
            pthread_cond_timedwait(&backup_cond, &backup_mutex, &tms);
            waiting_for_aio_writes_to_be_done = 0;
            if (aiowr_interposers == NULL) {
                break;
            }
        }
    }
}

void
livebackup_flush(BlockDriverState *bs)
{
    pthread_mutex_lock(&backup_mutex);
    if (bs->livebackup_disk) {
        wait_for_aio_empty(6);
    }
    pthread_mutex_unlock(&backup_mutex);
}

static inline void
copy_cow_clusters(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    if (in_progress_snap) {
        livebackup_disk *bd = (livebackup_disk *) bs->livebackup_disk;
        livebackup_snap *snap_bd = bd->snap_backup_disk;
        int64_t first_cluster;
        int64_t last_cluster;
        int64_t i;

        first_cluster = sector_num / BACKUP_BLOCKS_PER_CLUSTER;
        last_cluster = (sector_num + nb_sectors + BACKUP_BLOCKS_PER_CLUSTER - 1)
                        /BACKUP_BLOCKS_PER_CLUSTER;

        /* Create COW of each cluster in the backup snapshot's dirty bitmap */
        for (i = first_cluster; i < last_cluster; i++) {
            if (is_cluster_dirty(snap_bd->bd_base.dirty_bitmap, i)) {
                /* If sector is in dirty map of snap, then do a COW */
                if (bdrv_read(bs, i * BACKUP_BLOCKS_PER_CLUSTER,
                                in_progress_snap->backup_tmp_buffer,
                                BACKUP_BLOCKS_PER_CLUSTER) < 0) {
                    fprintf(stderr,
                            "copy_cow_clusters: Error. read COW of "
                            "cluster %ld failed\n", i);
                } else {
                    int rv;
                    if ((rv = bdrv_write(snap_bd->backup_cow_bs,
                            i * BACKUP_BLOCKS_PER_CLUSTER,
                            in_progress_snap->backup_tmp_buffer,
                            BACKUP_BLOCKS_PER_CLUSTER)) < 0) {
                        fprintf(stderr,
                            "copy_cow_clusters: Error. write COW of "
                            "cluster %ld failed %d\n", i, rv);
                    } else {
                        /* Set this cluster's bit in the in_cow_bitmap */
                        set_cluster_dirty(snap_bd->in_cow_bitmap,
                                        i, &snap_bd->in_cow_bitmap_count);
                    }
                }
            }
        }
    }
}

void 
set_dirty(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    pthread_mutex_lock(&backup_mutex);
    if (bs->livebackup_disk) {
        livebackup_disk *bd = (livebackup_disk *) bs->livebackup_disk;

        set_blocks_dirty(bd->bd_base.dirty_bitmap, sector_num, nb_sectors,
                        &bd->bd_base.bdinfo.dirty_clusters);
        copy_cow_clusters(bs, sector_num, nb_sectors);
    }

    pthread_mutex_unlock(&backup_mutex);
}

static int
remove_from_backup_disk_list(livebackup_disk *bd)
{
    livebackup_disk *prev = NULL;
    livebackup_disk *cur = backup_disks;

    while (cur != NULL) {
            if (cur == bd) {
                if (prev != NULL)
                    prev->next = cur->next;
                else
                    backup_disks = cur->next;
                return 0;
            }
            prev = cur;
            cur = cur->next;
    }
    fprintf(stderr, "Cannot find backup_disk %s in list\n",
                    bd->bd_base.bdinfo.name);
    return -1;
}

static void
append_to_list(livebackup_disk **list_head, livebackup_disk *bd)
{
        livebackup_disk *prev = NULL;
        livebackup_disk *cur = *list_head;

        while (cur != NULL) {
            prev = cur;
            cur = cur->next;
        }
        if (prev != NULL) {
            prev->next = bd;
        } else {
            *list_head = bd;
        }
        bd->next = NULL;
}

static void
append_to_snap_list(livebackup_snap **list_head, livebackup_snap *bd)
{
        livebackup_snap *prev = NULL;
        livebackup_snap *cur = *list_head;

        while (cur != NULL) {
            prev = cur;
            cur = cur->next;
        }
        if (prev != NULL) {
            prev->next = bd;
        } else {
            *list_head = bd;
        }
        bd->next = NULL;
}

static int
get_num_backup_disks(void)
{
    livebackup_disk *cur = backup_disks;
    int count = 0;

    while (cur != NULL) {
        cur = cur->next;
        count++;
    }
    return count;
}

static int
read_in_dirty_bitmap(char *filename, unsigned char **dbmp, int dbmp_len)
{
    int dfd;
    struct stat stb;

    if ((dfd = open(filename, O_RDWR)) >= 0) {
        if (fstat(dfd, &stb) == 0) {
            if (dbmp_len != stb.st_size) {
                fprintf(stderr,
                    "read_in_dirty_bitmap: error in dirty "
                    "bitmap len(%d,%ld) of %s\n",
                    dbmp_len, stb.st_size, filename);
                qemu_free(*dbmp);
                *dbmp = NULL;
                return -1;
            } else {
                int rrv = read(dfd, *dbmp, stb.st_size);
                if (rrv != stb.st_size) {
                    fprintf(stderr,
                        "read_in_dirty_bitmap: error %d reading "
                        "dirty_bitmap from %s\n",
                        errno, filename);
                    qemu_free(*dbmp);
                    *dbmp = NULL;
                    return -1;
                } else {
                    fprintf(stderr,
                      "read_in_dirty_bitmap: read %d byts "
                      "from existing dirty_bitmap fl %s\n",
                      rrv, filename);
                    return 0;
                }
            }
        } else {
            fprintf(stderr,
                "read_in_dirty_bitmap: error %d stat of %s\n", errno, filename);
            return -1;
        }
    } else {
        fprintf(stderr, "read_in_dirty_bitmap: error %d opening %s\n",
           errno, filename);
        return -1;
    }
}

//-----------------------------------------------------------------------------
// MurmurHashNeutral2, by Austin Appleby

// Same as MurmurHash2, but endian- and alignment-neutral.
// Half the speed though, alas.

static unsigned int
MurmurHashNeutral2 ( const void * key, int len, unsigned int seed )
{
    const unsigned int m = 0x5bd1e995;
    const int r = 24;

    unsigned int h = seed ^ len;

    const unsigned char * data = (const unsigned char *)key;

    while(len >= 4)
    {
        unsigned int k;

        k  = data[0];
        k |= data[1] << 8;
        k |= data[2] << 16;
        k |= data[3] << 24;

        k *= m; 
        k ^= k >> r; 
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }
        
    switch(len)
    {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0];
                h *= m;
    };

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
} 

static void
create_hashfilename(const char *vdisk_file, char *hashfn, int hashfnlen)
{
    unsigned int hv = MurmurHashNeutral2(vdisk_file, strlen(vdisk_file), 0);
    snprintf(hashfn, hashfnlen, "%.8x", (int32_t) hv);
}

livebackup_disk *
livebackup_init(const char *filename, int64_t total_sectors)
{
    char dirty_bitmap_file[PATH_MAX];
    char hfn[16];
    char conf_file[PATH_MAX];
    char snap_file[PATH_MAX];
    struct stat sta, stb;
    int64_t full_backup_mtime = 0;
    int64_t snap = 0;
    int dirty_bitmap_valid = 0;
    livebackup_disk *retv;

fprintf(stderr, "livebackup_init: Entered. fn %s, ts %ld\n", filename, total_sectors);
    if (!livebackup_dir || total_sectors <= 0) {
        /* We need a livebackup_dir to store snap and COW files */
        /* Also, we need to know the length of the virtual drive */
        return NULL;
    }
    create_hashfilename(filename, hfn, sizeof(hfn));
    snprintf(conf_file, sizeof(conf_file), "%s/%s.conf", livebackup_dir, hfn);
    snprintf(dirty_bitmap_file, sizeof(dirty_bitmap_file),
                "%s/%s.dirty_bitmap", livebackup_dir, hfn);
    snprintf(snap_file, sizeof(snap_file),
                "%s/%s.qcow2", livebackup_dir, hfn);

    if (stat(filename, &sta) != 0) {
        /* 'filename' does not exist? */
        return NULL;
    }
    if (stat(conf_file, &stb) != 0) {
        /*
         * conf file does not exist
         * New full backup
         */
        fprintf(stderr, "livebackup_init: Conf %s does not exist."
            " dirty_bitmap is invalid.\n", conf_file);
        full_backup_mtime = sta.st_mtime;
        snap = 0;
        dirty_bitmap_valid = 0;
    } else {
        /*
         * conf file exists
         * Hence, dirty bitmap is valid.
         * Incremental backup is feasible
         */
        fprintf(stderr, "livebackup_init: Conf %s exists.\n", conf_file);
        if (parse_conf_file(conf_file, &full_backup_mtime, &snap) == 0) {
            fprintf(stderr,
                "livebackup_init: bitmap valid mtime %ld snap %ld\n",
                full_backup_mtime, snap);
            dirty_bitmap_valid = 1;
        } else {
            fprintf(stderr, "livebackup_init: Conf file exists,"
                            " but contents invalid. New full backup\n");
            full_backup_mtime = sta.st_mtime;
            snap = 0;
            dirty_bitmap_valid = 0;
        }
    }
    if (unlink(conf_file) != 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "livebackup_init: Error. Unlink %s rv %d\n",
                conf_file, errno);
        }
    }

    retv = qemu_mallocz(sizeof(livebackup_disk));
    if (!retv) {
        fprintf(stderr,
                "livebackup_init: error allocating livebackup_disk for %s\n",
                filename);
        return NULL;
    }

    strncpy(retv->bd_base.bdinfo.name, filename,
                                sizeof(retv->bd_base.bdinfo.name));
    strncpy(retv->bd_base.conf_file, conf_file,
                                sizeof(retv->bd_base.conf_file));
    strncpy(retv->bd_base.dirty_bitmap_file, dirty_bitmap_file,
                                sizeof(retv->bd_base.dirty_bitmap_file));
    strncpy(retv->bd_base.snap_file, snap_file,
                                sizeof(retv->bd_base.snap_file));

    retv->bd_base.bdinfo.max_clusters = total_sectors/BACKUP_BLOCKS_PER_CLUSTER;
    retv->bd_base.dirty_bitmap_len = (retv->bd_base.bdinfo.max_clusters + 7)/8;
    retv->next = NULL;

    retv->bd_base.dirty_bitmap = qemu_mallocz(retv->bd_base.dirty_bitmap_len);
    if (retv->bd_base.dirty_bitmap == NULL) {
        fprintf(stderr,
               "livebackup_init: error allocating dirty_bitmap for %s\n",
               filename);
        qemu_free(retv);
        return NULL;
    }

    retv->bd_base.bdinfo.full_backup_mtime = full_backup_mtime;
    retv->bd_base.bdinfo.snapnumber = snap;

    pthread_mutex_lock(&backup_mutex);
    append_to_list(&backup_disks, retv);
    pthread_mutex_unlock(&backup_mutex);

    if (!dirty_bitmap_valid) {
        memset(retv->bd_base.dirty_bitmap, 0xff,
                                            retv->bd_base.dirty_bitmap_len);
        retv->bd_base.bdinfo.dirty_clusters = retv->bd_base.bdinfo.max_clusters;
        return retv;
    }
    read_in_dirty_bitmap(dirty_bitmap_file, &retv->bd_base.dirty_bitmap,
                                            retv->bd_base.dirty_bitmap_len);
    if (unlink(dirty_bitmap_file) != 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "livebackup_init: Error. Unlink %s rv %d\n",
                    dirty_bitmap_file, errno);
        }
    }
    return retv;
}

void
deinit_livebackup(BlockDriverState *bs)
{
    int dfd;
    livebackup_disk *bd;

    pthread_mutex_lock(&backup_mutex);

    bd = (livebackup_disk *) bs->livebackup_disk;
    if (bd != NULL) {

        /*
         * If we're shutting down while a snap is active, then OR the snap's
         * dirty bitmap with this one, and roll back the snapnumber by one
         */
        if (in_progress_snap) {
            if (bd->snap_backup_disk) {
                int64_t it;
                livebackup_snap *snbd =  bd->snap_backup_disk;

                for (it = 0; it < bd->bd_base.bdinfo.max_clusters; it++) {
                    if (is_cluster_dirty(snbd->bd_base.dirty_bitmap, it)) {
                        set_cluster_dirty(bd->bd_base.dirty_bitmap, it,
                                        &bd->bd_base.bdinfo.dirty_clusters);
                    }
                }
                bd->bd_base.bdinfo.snapnumber--;
            }
        }

        if ((dfd = open(bd->bd_base.dirty_bitmap_file, O_RDWR|O_CREAT|O_TRUNC,
                                                    S_IRUSR|S_IWUSR)) >= 0) {
            int bw = bd->bd_base.dirty_bitmap_len;
            while (bw > 0) {
                int bt = write(dfd, bd->bd_base.dirty_bitmap 
                                    + (bd->bd_base.dirty_bitmap_len - bw), bw);
                if (bt > 0) {
                    bw -= bt;
                } else {
                    fprintf(stderr,
                        "Error rv %d errno %d while writing out dirty bitmap\n",
                        bt, errno);
                    break;
                }
            }
            fsync(dfd);
            close(dfd);
            /*
            fprintf(stderr, "Wrote a dirty_bitmap %s of len %d\n",
                bd->bd_base.dirty_bitmap_file, bd->bd_base.dirty_bitmap_len);
             */
        } else {
            fprintf(stderr,
                    "Error %d opening %s while writing out dirty bitmap\n",
                    errno, bd->bd_base.dirty_bitmap_file);
        }

        write_conf_file(bd->bd_base.conf_file,
                        bd->bd_base.bdinfo.full_backup_mtime,
                        bd->bd_base.bdinfo.snapnumber);

        remove_from_backup_disk_list(bd);
        qemu_free(bd->bd_base.dirty_bitmap);
        bd->bd_base.dirty_bitmap = NULL;
        bd->bd_base.dirty_bitmap_len = 0;
        qemu_free(bd);
        bs->livebackup_disk = NULL;
    }
    pthread_mutex_unlock(&backup_mutex);
}

static int
backup_get_vdisk_count(int fd)
{
    get_vdisk_count_result res;
    int bw;

    res.status = get_num_backup_disks();

    if ((bw = write_bytes(fd, (unsigned char *) &res, sizeof(res))) 
                                    != sizeof(res)) {
        fprintf(stderr,
            "qemu.get_vdisk_count: error %d writing result\n",
            errno);
        return -1;
    }

    if (res.status > 0) {
        if (in_progress_snap != NULL) {
            livebackup_snap *itr = in_progress_snap->backup_disks;
            while (itr) {
                bw = write_bytes(fd, (unsigned char *) &itr->bd_base.bdinfo,
                             sizeof(itr->bd_base.bdinfo));
                if (bw != sizeof(itr->bd_base.bdinfo)) {
                    fprintf(stderr,
                        "qemu.get_vdisk_count: error %d writing result data\n",
                        errno);
                    return -1;
                }
                itr = itr->next;
            }
        } else {
            livebackup_disk *itr = backup_disks;
            while (itr) {
                bw = write_bytes(fd, (unsigned char *) &itr->bd_base.bdinfo,
                             sizeof(itr->bd_base.bdinfo));
                if (bw != sizeof(itr->bd_base.bdinfo)) {
                    fprintf(stderr,
                        "qemu.get_vdisk_count: error %d writing result data\n",
                        errno);
                    return -1;
                }
                itr = itr->next;
            }
        }
    }
    return 0;
}

static livebackup_snap *
create_backup_disk_for_snap(livebackup_disk *in)
{
    livebackup_snap *out;
    out = qemu_mallocz(sizeof(*out));
    if (out == NULL) {
        fprintf(stderr,
                "create_backup_disk_for_snap: alloc of backup_disk failed\n");
        return NULL;
    }
    out->bd_base = in->bd_base;
    in->snap_backup_disk = out;
    return out;
}

/*
 * When a backup client calls us and asks us to take a snapshot,
 * here are the things we do:
 * - lock backup_mutex
 * - allocate a snapshot struct that describes the state of all
 *   virtual disks, their dirty bitmaps at the time of snap, and
 *   other misc information.
 * - move the dirty_bitmap buffers for each vdisk into the snapshot
 * - allocate new dirty_bitmap buffers for each vdisk
 * - read the conf file for each vdisk, bump up the snapnumber and
 *   write it back out.
 * - unlock the backup_mutex
 *
 * From now on, until destroy_snap is called, every write from the
 * VM is checked against our saved snapshot dirty_bitmap. If the
 * block is marked as dirty in our snapshot dirty_bitmap, a read
 * is performed from the base file, and the block is saved in our
 * snapshot's cow file before the write from the VM is allowed to
 * proceed.
 *
 * Then a backup program calls us and starts transferring blocks
 * from the snapshot over to the backup computer.
 */
static int
backup_do_snap(int fd, backup_request *req)
{
    do_snap_result res;
    livebackup_disk *itr;

    pthread_mutex_lock(&backup_mutex);

    if (in_progress_snap != NULL) {
        res.status = B_DO_SNAP_RES_ALREADY;
        goto write_result_and_exit;
    }

    /* Wait for upto 4 * 10 seconds if there are pending writes */
    wait_for_aio_empty(4);
    if (aiowr_interposers != NULL) {
        res.status = B_DO_SNAP_RES_PENDING_WRITES;
        goto write_result_and_exit;
    }

    in_progress_snap = qemu_mallocz(sizeof(*in_progress_snap));
    if (in_progress_snap == NULL) {
        res.status = B_DO_SNAP_RES_NOMEM;
        goto write_result_and_exit;
    }
    in_progress_snap->backup_tmp_buffer = qemu_memalign(512,
                BACKUP_MAX_CLUSTERS_IN_1_RESP * BACKUP_CLUSTER_SIZE);
    if (in_progress_snap->backup_tmp_buffer == NULL) {
        res.status = B_DO_SNAP_RES_NOMEM;
        goto write_result_and_exit;
    }

    in_progress_snap->backup_disks = NULL;
    itr = backup_disks;
    while (itr != NULL) {
        livebackup_snap *new_bd = NULL;
        unsigned char *new_dirty_bitmap = NULL;
        unsigned char *in_cow_bitmap = NULL;

        /*
         * If the client is asking for a full backup, drop the old dirty bitmap,
         * set all blocks dirty, and write the new full_backup_mtime and snap=0
         * into the conf file
         */
        if (req->param1 == B_DO_SNAP_FULLBACKUP) {
            struct stat sta;
            int tfd;

            if ((tfd = open(itr->bd_base.bdinfo.name,
                        O_WRONLY|O_NOCTTY|O_NONBLOCK|O_LARGEFILE, 0666)) >= 0) {
                char tv[PATH_MAX];
                sprintf(tv, "/proc/self/fd/%d", tfd);
                utimes(tv, NULL);
                close(tfd);
            } else {
                fprintf(stderr,
                        "Error %d opening %s to set mtime for full backup\n",
                        errno, itr->bd_base.bdinfo.name);
            }
            if (stat(itr->bd_base.bdinfo.name, &sta) != 0) {
                fprintf(stderr,
                        "backup_do_snap: Error %d stat'ing base file %s\n",
                        errno, itr->bd_base.bdinfo.name);
                res.status = B_DO_SNAP_RES_NOMEM;
                goto write_result_and_exit;
            }
            itr->bd_base.bdinfo.full_backup_mtime = sta.st_mtime;
            itr->bd_base.bdinfo.snapnumber = 0;
            memset(itr->bd_base.dirty_bitmap, 0xff,
                    itr->bd_base.dirty_bitmap_len);
            itr->bd_base.bdinfo.dirty_clusters = itr->bd_base.bdinfo.max_clusters;
        }

        new_bd = create_backup_disk_for_snap(itr);
        new_dirty_bitmap = qemu_mallocz(itr->bd_base.dirty_bitmap_len);
        in_cow_bitmap = qemu_mallocz(itr->bd_base.dirty_bitmap_len);
        if (new_bd == NULL || new_dirty_bitmap == NULL 
                        || in_cow_bitmap == NULL) {
            res.status = B_DO_SNAP_RES_NOMEM;
            if (new_dirty_bitmap != NULL) qemu_free(new_dirty_bitmap);
            if (in_cow_bitmap != NULL) qemu_free(in_cow_bitmap);
            goto write_result_and_exit;
        }

        itr->bd_base.dirty_bitmap = new_dirty_bitmap;
        itr->bd_base.bdinfo.dirty_clusters = 0;
        itr->bd_base.bdinfo.snapnumber++;

        new_bd->in_cow_bitmap = in_cow_bitmap;
        new_bd->in_cow_bitmap_count = 0;

        if (bdrv_file_open(&new_bd->backup_base_bs,
                         new_bd->bd_base.bdinfo.name, 0/* read only */)) {
            fprintf(stderr, "backup_do_snap: Error opening base file %s\n",
                        new_bd->bd_base.bdinfo.name);
            res.status = B_DO_SNAP_RES_NOMEM;
            goto write_result_and_exit;
        }
        if (in_progress_snap->backup_snap_drv == NULL) {
            in_progress_snap->backup_snap_drv = bdrv_find_format("qcow2");
            if (in_progress_snap->backup_snap_drv == NULL) {
                fprintf(stderr,
                    "backup_do_snap: Error. Could not find qcow2 driver\n");
                res.status = B_DO_SNAP_RES_NOMEM;
                goto write_result_and_exit;
            }
        }
        if (in_progress_snap->backup_snap_drv) {
            QEMUOptionParameter *options;
            options = parse_option_parameters("",
                    in_progress_snap->backup_snap_drv->create_options, NULL);
            set_option_parameter_int(options, BLOCK_OPT_SIZE,
                    itr->bd_base.bdinfo.max_clusters);
            if (bdrv_create(in_progress_snap->backup_snap_drv,
                        itr->bd_base.snap_file, options)) {
                fprintf(stderr,
                    "backup_do_snap: Error creating snap cow file %s\n",
                    itr->bd_base.snap_file);
                res.status = B_DO_SNAP_RES_NOMEM;
                goto write_result_and_exit;
            } else {
                if (bdrv_file_open(&new_bd->backup_cow_bs,
                            itr->bd_base.snap_file, BDRV_O_RDWR)) {
                    fprintf(stderr,
                        "backup_do_snap: Error opening snap cow file %s\n",
                        itr->bd_base.snap_file);
                    res.status = B_DO_SNAP_RES_NOMEM;
                    goto write_result_and_exit;
                }
            }
        }

        if (0) { /* Test livebackup by creating a lvm snapshot and comparing */
            char snapname[PATH_MAX];
            char cmd[1024];
            int rv = 0;
            char *lst;
            
            if ((lst = strrchr(new_bd->bd_base.bdinfo.name, '/')) != NULL) {
                snprintf(snapname, sizeof(snapname), "%s_backup", lst + 1);
            } else {
                snprintf(snapname, sizeof(snapname), "%s_backup",
                         new_bd->bd_base.bdinfo.name);
            }
            snprintf(cmd, sizeof(cmd), "/sbin/lvcreate -L8G -s -n %s %s",
                        snapname, new_bd->bd_base.bdinfo.name);
            rv = system(cmd);
            if (rv != 0) {
                fprintf(stderr, "Error %d exec'ing %s during do_snap\n",
                    rv, cmd);
            }
        }
        append_to_snap_list(&in_progress_snap->backup_disks, new_bd);
        itr = itr->next;
    }

    res.status = B_DO_SNAP_RES_SUCCESS;

write_result_and_exit:
    pthread_mutex_unlock(&backup_mutex);
    if (write_bytes(fd, (unsigned char *) &res, sizeof(res)) != sizeof(res)) {
        fprintf(stderr, "backup_do_snap: Error %d writing res %ld\n",
               errno, res.status);
        return -1;
    } else {
        return 0;
    }
}

static livebackup_snap *
get_backup_disk(snapshot *snapsh, int disk_number)
{
    int i = 0;
    livebackup_snap *itr = snapsh->backup_disks;
    while (itr != NULL) {
        if (disk_number == i) {
            return itr;
        }
        itr = itr->next;
        i++;
    }
    return NULL;
}

static int
backup_get_clusters(int fd, backup_request *req)
{
    get_clusters_result res;
    livebackup_snap *bd;
    int64_t off = 0;
    int num = 0;
    int write_data = 0;
    int bitr;

    pthread_mutex_lock(&backup_mutex);
    if (in_progress_snap == NULL) {
        res.status = B_GET_CLUSTERS_ERROR_NO_SNAP_AVAIL;
        goto write_result_and_exit;
    }
    bd = get_backup_disk(in_progress_snap, req->param1);
    if (bd == NULL) {
        res.status = B_GET_CLUSTERS_ERROR_INVALID_DISK;
        goto write_result_and_exit;
    }
    if (get_next_dirty_cluster_offset(bd->bd_base.dirty_bitmap,
                bd->bd_base.bdinfo.max_clusters,
                req->param2, BACKUP_MAX_CLUSTERS_IN_1_RESP, &off, &num) < 0) {
        res.status = B_GET_CLUSTERS_NO_MORE_CLUSTERS;
        goto write_result_and_exit;
    }
    /*
     * read these blocks, from the COW file if it is in the COW file,
     * or from the base file
     */
    for (bitr = 0; bitr < num; bitr++) {
        if (is_cluster_dirty(bd->in_cow_bitmap, off + bitr)) {
            if (bdrv_read(bd->backup_cow_bs,
                        (off + bitr) * BACKUP_BLOCKS_PER_CLUSTER,
                        in_progress_snap->backup_tmp_buffer
                            + (bitr * BACKUP_CLUSTER_SIZE),
                        BACKUP_BLOCKS_PER_CLUSTER) != 0) {
                fprintf(stderr,
                    "backup_get_clusters: Error reading COW offset %ld\n",
                        off + bitr);
                res.status = B_GET_CLUSTERS_ERROR_IOREAD;
                goto write_result_and_exit;
            }
        } else {
            if (bdrv_read(bd->backup_base_bs,
                        (off + bitr) * BACKUP_BLOCKS_PER_CLUSTER,
                        in_progress_snap->backup_tmp_buffer
                            + (bitr * BACKUP_CLUSTER_SIZE),
                        BACKUP_BLOCKS_PER_CLUSTER) != 0) {
                fprintf(stderr,
                        "backup_get_clusters: Error reading base offset %ld\n",
                        off + bitr);
                res.status = B_GET_CLUSTERS_ERROR_IOREAD;
                goto write_result_and_exit;
            }
        }
    }
    res.status = B_GET_CLUSTERS_SUCCESS;
    res.offset = off;
    res.clusters = (int64_t) num;
    write_data = 1;

write_result_and_exit:
    pthread_mutex_unlock(&backup_mutex);
    if (write_bytes(fd, (unsigned char *) &res, sizeof(res)) != sizeof(res)) {
        fprintf(stderr, "backup_get_clusters: Error %d writing res %ld\n",
               errno, res.status);
        return -1;
    } else {
        if (write_data) {
            if (write_bytes(fd, in_progress_snap->backup_tmp_buffer,
                    num * BACKUP_CLUSTER_SIZE) != num * BACKUP_CLUSTER_SIZE) {
                fprintf(stderr,
                    "backup_get_clusters: Error %d writing res data\n", errno);
                return -1;
            }
        }
        return 0;
    }
}

static int
backup_destroy_snap(int fd, backup_request *req)
{
    destroy_snap_result res;
    pthread_mutex_lock(&backup_mutex);
    if (!in_progress_snap) {
        res.status = B_DESTROY_SNAP_ERROR_NO_SNAP;
    } else {
        in_progress_snap->destroy = 1;
        res.status = B_DESTROY_SNAP_SUCCESS;
    }
    pthread_mutex_unlock(&backup_mutex);
    if (write_bytes(fd, (unsigned char *) &res, sizeof(res)) != sizeof(res)) {
        fprintf(stderr, "backup_destroy_snap: Error %d writing res %ld\n",
               errno, res.status);
        return -1;
    } else {
        return 0;
    }
}

static int
do_backup(int fd)
{
    while (1) {
        backup_request req;
        int br;

        br = read_bytes(fd, (unsigned char *) &req, sizeof(req));
        if (br == sizeof(req)) {
            switch (req.opcode) {
            case B_GET_VDISK_COUNT:
                if (backup_get_vdisk_count(fd) < 0) {
                    return -1;
                }
                break;
            case B_DO_SNAP:
                if (backup_do_snap(fd, &req) < 0) {
                    return -1;
                }
                break;
            case B_DESTROY_SNAP:
                if (backup_destroy_snap(fd, &req) < 0) {
                    return -1;
                }
                break;
            case B_GET_CLUSTERS:
                if (backup_get_clusters(fd, &req) < 0) {
                    return -1;
                }
                break;
            default:
                break;
            }
        } else if (br == 0) {
            /* peer close connection cleanly */
            return 0;
        } else {
            fprintf(stderr,
                "qemu.process_backup: Error. read %d bytes instead of %lu\n",
                br, sizeof(req));
            return -1;
        }
    }
}

static pthread_t backup_thread_id;

static void *
backup_thread(void *unused)
{
    sigset_t set;
    int lport;

    sigfillset(&set);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    if (livebackup_port != NULL) {
        lport = atoi(livebackup_port);
    } else {
        fprintf(stderr, "Backup port not specified. LiveBackup disabled\n");
        return NULL;
    }

    while (1) {
        int listen_socket = -1;
        struct in_addr *in;
        struct sockaddr_in addr;
        struct sockaddr_in aaddr;
        unsigned aadrlen = sizeof(aaddr);
        int opt;
        int fd = -1;

        addr.sin_family = AF_INET;
        addr.sin_port = htons(lport);
        in = (struct in_addr *) &addr.sin_addr.s_addr;
        in->s_addr = 0L;

        listen_socket = socket(PF_INET, SOCK_STREAM, 0);
        if (listen_socket < 0) {
            fprintf(stderr,
                "qemu.backup_thread: Error %d opening listen socket\n", errno);
            goto error;
        }

        opt = 1;
        if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR,
                    &opt, sizeof(opt)) == -1) {
            fprintf(stderr,
                "qemu.backup_thread: Error %d setting reuseaddr\n", errno);
            goto error;
        }

        if (bind(listen_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            fprintf(stderr, "qemu.backup_thread: Error %d binding\n", errno);
            goto error;
        }

        if (listen(listen_socket, 128) == -1) {
            fprintf(stderr, "qemu.backup_thread: Error %d listening\n", errno);
            goto error;
        }

        if ((fd = accept(listen_socket, &aaddr, &aadrlen)) < 0) {
            fprintf(stderr, "qemu.backup_thread: Error %d accepting\n", errno);
            goto error;
        }

        do_backup(fd);

        if (fd >= 0) close(fd);
error:
        if (listen_socket != -1) {
            close(listen_socket);
            listen_socket = -1;
        }
    }
    return NULL;
}

int
start_backup_listener(void)
{
    pthread_attr_t attr;
    int ret;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&backup_thread_id, &attr, backup_thread, NULL);
    pthread_attr_destroy(&attr);

    return ret;
}
