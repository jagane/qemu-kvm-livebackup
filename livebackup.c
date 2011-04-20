#include "livebackup.h"

static backup_disk *backup_disks = NULL;

static aiowr_interposer *aiowr_interposers = NULL;

static pthread_mutex_t backup_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t backup_cond = PTHREAD_COND_INITIALIZER;
static int waiting_for_aio_writes_to_be_done = 0;
static snapshot *in_progress_snap = NULL;

char *backup_port;

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
                aiowr_interposers = NULL;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
}

void
aiowrite_cb_interposer(void *opaque, int ret)
{
    aiowr_interposer *ac = (aiowr_interposer *)opaque;
    BlockDriverCompletionFunc *saved_cb;
    void *saved_opaque;
    BlockDriverState *bs;
    backup_disk *bd;
    backup_disk *snap_bd;
    int call_cb = 0;

    pthread_mutex_lock(&backup_mutex);

    saved_cb = ac->cb;
    saved_opaque = ac->opaque;

    bs = ac->bs;
    bd = bs->backup_disk;
    if (!bd) {
        fprintf(stderr, "aiowrite_cb_interposer: Error. bd null\n");
        ret = -1;
        call_cb = 1;
        goto unlock_and_exit;
    }

    if (ac->state == AIOWR_INTERPOSER_COW_READ) {
        /* COW read completed. Initiate COW write */
// fprintf(stderr, "[D:%d@%ld to %p(%p,%p)]\n", ac->nb_sectors, ac->sector_num, ac->buf, ac->cb, ac->opaque);
        if (ret == 0) {
            ac->state = AIOWR_INTERPOSER_COW_WRITE;
            snap_bd = bd->snap_backup_disk;
            bdrv_aio_writev(snap_bd->backup_cow_bs,
                           ac->sector_num, ac->cow_tmp_qiov, ac->nb_sectors,
                           aiowrite_cb_interposer, ac);
            call_cb = 0;
        } else {
            fprintf(stderr, "Error in COW read of %d sectors @ %ld\n",
                ac->nb_sectors, ac->sector_num);
            if (ac->cow_tmp_buffer) qemu_free(ac->cow_tmp_buffer);
            remove_from_interposer_list(ac);
            free(ac);
            call_cb = 1;
        }
    } else if(ac->state == AIOWR_INTERPOSER_COW_WRITE) {
        /* COW write completed. Initiate actual write */
// fprintf(stderr, "[E:%d@%ld to %p(%p,%p)]\n", ac->nb_sectors, ac->sector_num, ac->buf, ac->cb, ac->opaque);
        if (ret == 0) {
            ac->state = AIOWR_INTERPOSER_ACTUAL_WRITE;
            qemu_free(ac->cow_tmp_buffer);
            ac->cow_tmp_buffer = NULL;
            bs->drv->bdrv_aio_writev(bs, ac->sector_num, ac->qiov,
						 ac->nb_sectors, aiowrite_cb_interposer, ac);
            call_cb = 0;
        } else {
            fprintf(stderr, "Error in COW write of %d sectors @ %ld\n",
                ac->nb_sectors, ac->sector_num);
            if (ac->cow_tmp_buffer) qemu_free(ac->cow_tmp_buffer);
            remove_from_interposer_list(ac);
            free(ac);
            call_cb = 1;
        }
    } else {
        /* Actual write completed. */
        /* Remove async req from our interposer list */
// fprintf(stderr, "[F:%d@%ld to %p(%p,%p)]\n", ac->nb_sectors, ac->sector_num, ac->buf, ac->cb, ac->opaque);
        remove_from_interposer_list(ac);
        free(ac);
    
        call_cb = 1;
    }
unlock_and_exit:
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
    if (call_cb) {
        saved_cb(saved_opaque, ret);
    }
}

static inline void
copy_cow_blocks(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    if (in_progress_snap) {
        backup_disk *bd = (backup_disk *) bs->backup_disk;
        backup_disk *snap_bd = bd->snap_backup_disk;
        int i;

        /* Create COW of each block that's in the backup snapshot's dirty bitmap */
        for (i = 0; i < nb_sectors; i++) {
            if (is_block_dirty(snap_bd->dirty_bitmap, sector_num + i)) {
                /* If sector is in dirty map of snap, then do a COW */
                if (bdrv_read(bs, sector_num + i, in_progress_snap->backup_tmp_buffer, 1) < 0) {
                    fprintf(stderr, "copy_cow_blocks: Error. read COW of block %ld failed\n",
                                    sector_num + i);
                } else {
                    int rv;
                    if ((rv = bdrv_write(snap_bd->backup_cow_bs, sector_num + i,
                             in_progress_snap->backup_tmp_buffer, 1)) < 0) {
                        fprintf(stderr, "copy_cow_blocks: Error. write COW of block %ld failed %d\n",
                                    sector_num + i, rv);
                    } else {
                        /* Set this block's bit in the in_cow_bitmap */
                        set_block_dirty(snap_bd->in_cow_bitmap, sector_num + i, &snap_bd->in_cow_bitmap_count);
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
    if (bs->backup_disk) {
        backup_disk *bd = (backup_disk *) bs->backup_disk;

        set_blocks_dirty(bd->dirty_bitmap, sector_num, nb_sectors, &bd->bdinfo.dirty_blocks);
        copy_cow_blocks(bs, sector_num, nb_sectors);
    }

    pthread_mutex_unlock(&backup_mutex);
}

static inline int
is_copy_cow_necessary(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    if (in_progress_snap) {
        backup_disk *bd = (backup_disk *) bs->backup_disk;
        backup_disk *snap_bd = bd->snap_backup_disk;
        int i;

        /* Create COW of each block that's in the backup snapshot's dirty bitmap */
        for (i = 0; i < nb_sectors; i++) {
            if (is_block_dirty(snap_bd->dirty_bitmap, sector_num + i)) {
                return 1;
            }
        }
        return 0;
    } else {
        return 0;
    }
}

BlockDriverAIOCB *
set_dirty_and_start_async(BlockDriverState *bs, int64_t sector_num,
                                 QEMUIOVector *qiov, int nb_sectors,
                                 BlockDriverCompletionFunc *cb, void *opaque)
{
    aiowr_interposer *ac = NULL;
    BlockDriverAIOCB *ret = NULL;

    pthread_mutex_lock(&backup_mutex);
    if (bs->backup_disk) {
        backup_disk *bd = (backup_disk *) bs->backup_disk;

        set_blocks_dirty(bd->dirty_bitmap, sector_num, nb_sectors, &bd->bdinfo.dirty_blocks);

        ac = calloc(1, sizeof(aiowr_interposer));
        ac->bs = bs;
        ac->cb = cb;
        ac->opaque = opaque;
        ac->sector_num = sector_num;
        ac->qiov = qiov;
        ac->nb_sectors = nb_sectors;

        ac->next = aiowr_interposers;
        aiowr_interposers = ac;

        if (is_copy_cow_necessary(bs, sector_num, nb_sectors)) {
            /* COW is necessary. Initiate the COW read */
            backup_disk *snap_bd = bd->snap_backup_disk;
            ac->state = AIOWR_INTERPOSER_COW_READ;
            ac->cow_tmp_buffer = qemu_memalign(512, nb_sectors * BACKUP_BLOCK_SIZE);
            ac->cow_tmp_qiov = qemu_mallocz(sizeof(*qiov));
            qemu_iovec_init(ac->cow_tmp_qiov, 1);
            qemu_iovec_add(ac->cow_tmp_qiov, ac->cow_tmp_buffer, nb_sectors * BACKUP_BLOCK_SIZE);

// fprintf(stderr, "[B:%d@%ld to %p(%p,%p)]\n", nb_sectors, sector_num, buf, cb, opaque);

            ret = snap_bd->backup_base_bs->drv->bdrv_aio_readv(snap_bd->backup_base_bs, sector_num, ac->cow_tmp_qiov,
						 nb_sectors, aiowrite_cb_interposer, ac);
        } else {
            /* COW is not necessary. Initiate the actual write */
            ac->state = AIOWR_INTERPOSER_ACTUAL_WRITE;

// fprintf(stderr, "[C:%d@%ld to %p(%p,%p)]\n", nb_sectors, sector_num, buf, cb, opaque);
            ret = bs->drv->bdrv_aio_writev(bs, sector_num, qiov, nb_sectors, aiowrite_cb_interposer, ac);
        }
    }
    pthread_mutex_unlock(&backup_mutex);
    return ret;
}

static int
remove_from_backup_disk_list(backup_disk *bd)
{
    backup_disk *prev = NULL;
    backup_disk *cur = backup_disks;

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
    fprintf(stderr, "Cannot find backup_disk %s in list\n", bd->bdinfo.name);
    return -1;
}

static void
append_to_list(backup_disk **list_head, backup_disk *bd)
{
        backup_disk *prev = NULL;
        backup_disk *cur = *list_head;

        while (cur != NULL) {
            prev = cur;
            cur = cur->next;
        }
        if (prev != NULL) {
            prev->next = bd;
        } else {
            *list_head = bd;
        }
}

static int
get_num_backup_disks(void)
{
    backup_disk *cur = backup_disks;
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
                    "read_in_dirty_bitmap: error in dirty bitmap len(%d,%ld) of %s\n",
                    dbmp_len, stb.st_size, filename);
                qemu_free(*dbmp);
                *dbmp = NULL;
                return -1;
            } else {
                int rrv = read(dfd, *dbmp, stb.st_size);
                if (rrv != stb.st_size) {
                    fprintf(stderr,
                        "read_in_dirty_bitmap: error %d reading dirty_bitmap from %s\n",
                        errno, filename);
                    qemu_free(*dbmp);
                    *dbmp = NULL;
                    return -1;
                } else {
                    fprintf(stderr,
                      "read_in_dirty_bitmap: read %d byts from existing dirty_bitmap fl %s\n",
                      rrv, filename);
                    return 0;
                }
            }
        } else {
            fprintf(stderr, "read_in_dirty_bitmap: error %d stat of %s\n", errno, filename);
            return -1;
        }
    } else {
        fprintf(stderr, "read_in_dirty_bitmap: error %d opening %s\n",
           errno, filename);
        return -1;
    }
}

/*
 * If the virtual disk file filename has a config file called
 * filename.livebackupconf present in the same directory, then this
 * virtual disk is part of the livebackup set.
 *
 * Next, if the config file was modified after the virtual disk file
 * then the persistent dirty blocks bitmap file is considered valid,
 * and an incremental backup is possible.
 *
 * If the config file was modified before the virtual disk file was
 * modified, then the VM probably crashed without allowing the
 * livebackup code to write out the dirty blocks bitmap and the
 * conf file correctly and exit cleanly. Hence the backup must become
 * a full backup.
 */
backup_disk *
open_dirty_bitmap(const char *filename)
{
    char dirty_bitmap_file[PATH_MAX];
    char conf_file[PATH_MAX];
    char snap_file[PATH_MAX];
    struct stat sta, stb;
    int64_t full_backup_mtime = 0;
    int64_t snap = 0;
    int dirty_bitmap_valid = 0;
    backup_disk *retv;

    sprintf(conf_file, "%s.livebackupconf", filename);
    if (stat(conf_file, &stb) != 0) {
	/*
         * conf file does not exist. This virtual disk is not part of the
         * disks that are backed up
         */
        fprintf(stderr, "open_dirty_bitmap: conf file %s does not exist\n",
          conf_file);
        return NULL;
    }
    /* conf file exists */
    if (stat(filename, &sta) != 0) {
        /* filename does not exist? */
        return NULL;
    }
    if (sta.st_mtime > stb.st_mtime) {
        /* conf file was modified before vdisk file. New full backup */
        fprintf(stderr, "open_dirty_bitmap: Conf\n\t%s - %s"
            " was modified before vdisk\n\t%s - %s."
            " Hence dirty_bitmap is invalid.",
             conf_file, ctime(&stb.st_mtime), filename, ctime(&sta.st_mtime));
        full_backup_mtime = sta.st_mtime;
        snap = 0;
        dirty_bitmap_valid = 0;
        write_conf_file(conf_file, full_backup_mtime, snap);
    } else {
        /* conf file was modified after vdisk file. Incremental backup */
        fprintf(stderr, "open_dirty_bitmap: Conf\n\t%s - %s"
                        " is newer than vdisk\n\t%s - %s",
                        conf_file, ctime(&stb.st_mtime),
                        filename, ctime(&sta.st_mtime));
        if (parse_conf_file(conf_file, &full_backup_mtime, &snap) == 0) {
            fprintf(stderr, "open_dirty_bitmap: dirty_bitmap valid. New snap\n");
            dirty_bitmap_valid = 1;
        } else {
            fprintf(stderr, "open_dirty_bitmap: Conf file exists,"
                            " but contents invalid. New full backup\n");
            dirty_bitmap_valid = 0;
            unlink(dirty_bitmap_file);
            full_backup_mtime = sta.st_mtime;
            snap = 0;
            dirty_bitmap_valid = 0;
            write_conf_file(conf_file, full_backup_mtime, snap);
        }
    }
    snprintf(dirty_bitmap_file, sizeof(dirty_bitmap_file),
                "%s.dirty_bitmap", filename);
    snprintf(snap_file, sizeof(snap_file),
                "%s.snap.qcow", filename);

    retv = qemu_mallocz(sizeof(backup_disk));
    if (!retv) {
        fprintf(stderr,
                "open_dirty_bitmap: error allocating backup_disk for %s\n",
                filename);
        return NULL;
    }

    strncpy(retv->bdinfo.name, filename, sizeof(retv->bdinfo.name));
    strncpy(retv->conf_file, conf_file, sizeof(retv->conf_file));
    strncpy(retv->dirty_bitmap_file, dirty_bitmap_file, sizeof(retv->dirty_bitmap_file));
    strncpy(retv->snap_file, snap_file, sizeof(retv->snap_file));

    retv->dirty_bitmap_len = ((sta.st_size / 512) + 7)/8;
    retv->bdinfo.max_blocks = sta.st_size/512;
    retv->next = NULL;

    retv->dirty_bitmap = qemu_mallocz(retv->dirty_bitmap_len);
    if (retv->dirty_bitmap == NULL) {
        fprintf(stderr,
               "open_dirty_bitmap: error allocating dirty_bitmap for %s\n",
               filename);
        qemu_free(retv);
        return NULL;
    }

    retv->bdinfo.full_backup_mtime = full_backup_mtime;
    retv->bdinfo.snapnumber = snap;

    append_to_list(&backup_disks, retv);
    if (!dirty_bitmap_valid) {
        memset(retv->dirty_bitmap, 0xff, retv->dirty_bitmap_len);
        retv->bdinfo.dirty_blocks = retv->bdinfo.max_blocks;
        return retv;
    }
    read_in_dirty_bitmap(dirty_bitmap_file, &retv->dirty_bitmap, retv->dirty_bitmap_len);
    return retv;
}

void
close_dirty_bitmap(BlockDriverState *bs)
{
    int dfd;
    backup_disk *bd;

    pthread_mutex_lock(&backup_mutex);

    bd = (backup_disk *) bs->backup_disk;
    if (bd != NULL) {

        /*
         * If we're shutting down while a snap is in progress, then OR the snap's
         * dirty bitmap with this one, and roll back the snapnumber by one
         */
        if (in_progress_snap) {
            if (bd->snap_backup_disk) {
                int64_t it;
                backup_disk *snbd =  bd->snap_backup_disk;

                for (it = 0; it < bd->bdinfo.max_blocks; it++) {
                    if (is_block_dirty(snbd->dirty_bitmap, it)) {
                        set_block_dirty(bd->dirty_bitmap, it, &bd->bdinfo.dirty_blocks);
                    }
                }
                bd->bdinfo.snapnumber--;
            }
        }

        if ((dfd = open(bd->dirty_bitmap_file, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR)) >= 0) {
            int bw = bd->dirty_bitmap_len;
            while (bw > 0) {
                int bt = write(dfd, bd->dirty_bitmap + (bd->dirty_bitmap_len - bw), bw);
                if (bt > 0) {
                    bw -= bt;
                } else {
                    fprintf(stderr, "Error rv %d errno %d while writing out dirty bitmap\n",
		        bt, errno);
                    break;
                }
	    }
            close(dfd);
            fprintf(stderr, "Wrote a dirty_bitmap %s of len %d\n",
	        bd->dirty_bitmap_file, bd->dirty_bitmap_len);
        } else {
            fprintf(stderr, "Error %d opening %s while writing out dirty bitmap\n",
                errno, bd->dirty_bitmap_file);
        }

        write_conf_file(bd->conf_file, bd->bdinfo.full_backup_mtime, bd->bdinfo.snapnumber);

        remove_from_backup_disk_list(bd);
        qemu_free(bd->dirty_bitmap);
        bd->dirty_bitmap = NULL;
        bd->dirty_bitmap_len = 0;
        qemu_free(bd);
        bs->backup_disk = NULL;
    }
    pthread_mutex_unlock(&backup_mutex);
}

static int
backup_get_vdisk_count(int fd)
{
    get_vdisk_count_result res;
    int bw;

    res.status = get_num_backup_disks();

    if ((bw = write_bytes(fd, (unsigned char *) &res, sizeof(res))) != sizeof(res)) {
        fprintf(stderr,
            "qemu.get_vdisk_count: error %d writing result\n",
            errno);
        return -1;
    }

    if (res.status > 0) {
        backup_disk *itr = backup_disks;
	if (in_progress_snap != NULL) {
        	itr = in_progress_snap->backup_disks;
	} else {
        	itr = backup_disks;
	}
        while (itr) {
            bw = write_bytes(fd, (unsigned char *) &itr->bdinfo,
                             sizeof(itr->bdinfo));
            if (bw != sizeof(itr->bdinfo)) {
                fprintf(stderr,
                    "qemu.get_vdisk_count: error %d writing result data\n",
                    errno);
                return -1;
            }
            itr = itr->next;
        }
    }
    return 0;
}

static backup_disk *
create_backup_disk_for_snap(backup_disk *in)
{
    backup_disk *out;
    out = qemu_mallocz(sizeof(*out));
    if (out == NULL) {
        fprintf(stderr, "create_backup_disk_for_snap: alloc of backup_disk failed\n");
        return NULL;
    }
    *out = *in;
    in->snap_backup_disk = out;
    out->next = NULL;
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
    backup_disk *itr;

    pthread_mutex_lock(&backup_mutex);

    if (in_progress_snap != NULL) {
        res.status = B_DO_SNAP_RES_ALREADY;
        goto write_result_and_exit;
    }

    /* Wait for upto 4 * 10 seconds if there are pending writes */
    if (aiowr_interposers != NULL) {
        int retries;
        for (retries = 0; retries < 4; retries++) {
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
                                              BACKUP_MAX_BLOCKS_IN_1_RESP * BACKUP_BLOCK_SIZE);
    if (in_progress_snap->backup_tmp_buffer == NULL) {
        res.status = B_DO_SNAP_RES_NOMEM;
        goto write_result_and_exit;
    }

    in_progress_snap->backup_disks = NULL;
    itr = backup_disks;
    while (itr != NULL) {
        backup_disk *new_bd;
        unsigned char *new_dirty_bitmap;
        unsigned char *in_cow_bitmap;

        /*
         * If the client is asking for a full backup, drop the old dirty bitmap,
         * set all blocks dirty, and write the new full_backup_mtime and snap=0
         * into the conf file
         */
        if (req->param1 == B_DO_SNAP_FULLBACKUP) {
            struct stat sta;
	    int tfd;

	    if ((tfd = open(itr->bdinfo.name, O_WRONLY|O_NOCTTY|O_NONBLOCK|O_LARGEFILE, 0666)) >= 0) {
		char tv[PATH_MAX];
		sprintf(tv, "/proc/self/fd/%d", tfd);
		utimes(tv, NULL);
		close(tfd);
	    } else {
		fprintf(stderr,
			"Error %d opening %s to set mtime for full backup\n",
			errno, itr->bdinfo.name);
	    }
            if (stat(itr->bdinfo.name, &sta) != 0) {
                fprintf(stderr, "backup_do_snap: Error %d stat'ing base file %s\n",
                        errno, itr->bdinfo.name);
                res.status = B_DO_SNAP_RES_NOMEM;
                goto write_result_and_exit;
            }
            itr->bdinfo.full_backup_mtime = sta.st_mtime;
            itr->bdinfo.snapnumber = 0;
            memset(itr->dirty_bitmap, 0xff, itr->dirty_bitmap_len);
            itr->bdinfo.dirty_blocks = itr->bdinfo.max_blocks;
        }

        new_bd = create_backup_disk_for_snap(itr);
        new_dirty_bitmap = qemu_mallocz(itr->dirty_bitmap_len);
        in_cow_bitmap = qemu_mallocz(itr->dirty_bitmap_len);
        if (new_bd == NULL || new_dirty_bitmap == NULL || in_cow_bitmap == NULL) {
            res.status = B_DO_SNAP_RES_NOMEM;
            goto write_result_and_exit;
        }

        itr->dirty_bitmap = new_dirty_bitmap;
        itr->bdinfo.dirty_blocks = 0;
        itr->bdinfo.snapnumber++;
        write_conf_file(itr->conf_file, itr->bdinfo.full_backup_mtime, itr->bdinfo.snapnumber);

        new_bd->in_cow_bitmap = in_cow_bitmap;
        new_bd->in_cow_bitmap_count = 0;

        if (bdrv_file_open(&new_bd->backup_base_bs, new_bd->bdinfo.name, 0/* read only */)) {
            fprintf(stderr, "backup_do_snap: Error opening base file %s\n",
                        new_bd->bdinfo.name);
            res.status = B_DO_SNAP_RES_NOMEM;
            goto write_result_and_exit;
        }
        if (in_progress_snap->backup_snap_drv == NULL) {
            in_progress_snap->backup_snap_drv = bdrv_find_format("qcow2");
            if (in_progress_snap->backup_snap_drv == NULL) {
                fprintf(stderr, "backup_do_snap: Error. Could not find qcow2 driver\n");
                res.status = B_DO_SNAP_RES_NOMEM;
                goto write_result_and_exit;
            }
        }
        if (in_progress_snap->backup_snap_drv) {
            QEMUOptionParameter *options;
            options = parse_option_parameters("", in_progress_snap->backup_snap_drv->create_options, NULL);
            set_option_parameter_int(options, BLOCK_OPT_SIZE, itr->bdinfo.max_blocks);
            if (bdrv_create(in_progress_snap->backup_snap_drv,
                        itr->snap_file, options)) {
                fprintf(stderr, "backup_do_snap: Error creating snap cow file %s\n",
                    itr->snap_file);
                res.status = B_DO_SNAP_RES_NOMEM;
                goto write_result_and_exit;
            } else {
                if (bdrv_file_open(&new_bd->backup_cow_bs, itr->snap_file, BDRV_O_RDWR)) {
                    fprintf(stderr, "backup_do_snap: Error opening snap cow file %s\n",
                        itr->snap_file);
                    res.status = B_DO_SNAP_RES_NOMEM;
                    goto write_result_and_exit;
                }
            }
        }

        append_to_list(&in_progress_snap->backup_disks, new_bd);
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

static backup_disk *
get_backup_disk(snapshot *snapsh, int disk_number)
{
    int i = 0;
    backup_disk *itr = snapsh->backup_disks;
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
backup_get_blocks(int fd, backup_request *req)
{
    get_blocks_result res;
    backup_disk *bd;
    int64_t off = 0;
    int num = 0;
    int write_data = 0;
    int bitr;

    pthread_mutex_lock(&backup_mutex);
    if (in_progress_snap == NULL) {
        res.status = B_GET_BLOCKS_ERROR_NO_SNAP_AVAIL;
        goto write_result_and_exit;
    }
    bd = get_backup_disk(in_progress_snap, req->param1);
    if (bd == NULL) {
        res.status = B_GET_BLOCKS_ERROR_INVALID_DISK;
        goto write_result_and_exit;
    }
    if (get_next_dirty_block_offset(bd->dirty_bitmap, bd->bdinfo.max_blocks,
		 req->param2, BACKUP_MAX_BLOCKS_IN_1_RESP, &off, &num) < 0) {
        res.status = B_GET_BLOCKS_NO_MORE_BLOCKS;
        goto write_result_and_exit;
    }
    /* read these blocks, from the COW file if it is in the COW file, or from the base file */
    for (bitr = 0; bitr < num; bitr++) {
        if (is_block_dirty(bd->in_cow_bitmap, off + bitr)) {
            if (bdrv_read(bd->backup_cow_bs, off + bitr,
                          in_progress_snap->backup_tmp_buffer + (bitr * BACKUP_BLOCK_SIZE),
                          1) != 0) {
                fprintf(stderr, "backup_get_blocks: Error reading COW offset %ld\n",
                        off + bitr);
                res.status = B_GET_BLOCKS_ERROR_IOREAD;
                goto write_result_and_exit;
            }
        } else {
            if (bdrv_read(bd->backup_base_bs, off + bitr,
                          in_progress_snap->backup_tmp_buffer + (bitr * BACKUP_BLOCK_SIZE),
                          1) != 0) {
                fprintf(stderr, "backup_get_blocks: Error reading base offset %ld\n",
                        off + bitr);
                res.status = B_GET_BLOCKS_ERROR_IOREAD;
                goto write_result_and_exit;
            }
        }
    }
    res.status = B_GET_BLOCKS_SUCCESS;
    res.offset = off;
    res.blocks = (int64_t) num;
    write_data = 1;

write_result_and_exit:
    pthread_mutex_unlock(&backup_mutex);
    if (write_bytes(fd, (unsigned char *) &res, sizeof(res)) != sizeof(res)) {
        fprintf(stderr, "backup_get_blocks: Error %d writing res %ld\n",
               errno, res.status);
        return -1;
    } else {
        if (write_data) {
            if (write_bytes(fd, in_progress_snap->backup_tmp_buffer, num * BACKUP_BLOCK_SIZE) !=
                                                   num * BACKUP_BLOCK_SIZE) {
                fprintf(stderr, "backup_get_blocks: Error %d writing res data\n", errno);
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
    backup_disk *itr;

    pthread_mutex_lock(&backup_mutex);

    if (!in_progress_snap) {
        res.status = B_DESTROY_SNAP_ERROR_NO_SNAP;
        goto write_result_and_exit;
    }

    qemu_free(in_progress_snap->backup_tmp_buffer);

    /* walk the list of backup_disks in this snapshot and clean them out */
    itr = in_progress_snap->backup_disks;
    while (itr != NULL) {
        backup_disk *save;
        qemu_free(itr->dirty_bitmap);
        qemu_free(itr->in_cow_bitmap);
        if (itr->backup_base_bs) bdrv_close(itr->backup_base_bs);
        if (itr->backup_cow_bs) bdrv_close(itr->backup_cow_bs);
        unlink(itr->snap_file);
        save = itr;
        itr = itr->next;
        qemu_free(save);
    }

    /* in the list of this VM's backup_disks, NULL out the ptr to the snap */
    itr = backup_disks;
    while (itr != NULL) {
        itr->snap_backup_disk = NULL;
        itr = itr->next;
    }

    qemu_free(in_progress_snap);
    in_progress_snap = NULL;

    res.status = B_DESTROY_SNAP_SUCCESS;

write_result_and_exit:
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
            case B_GET_BLOCKS:
                if (backup_get_blocks(fd, &req) < 0) {
                    return -1;
                }
	        break;
            case B_DESTROY_SNAP:
                if (backup_destroy_snap(fd, &req) < 0) {
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

    if (backup_port != NULL) {
	lport = atoi(backup_port);
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
            fprintf(stderr, "qemu.backup_thread: Error %d opening listen socket\n", errno);
            goto error;
        }

        opt = 1;
        if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            fprintf(stderr, "qemu.backup_thread: Error %d setting reuseaddr\n", errno);
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
