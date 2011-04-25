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

#include "qemu-common.h"
#include "qemu-option.h"
#include "qemu-error.h"
#include "osdep.h"
#include "sysemu.h"
#include "block_int.h"
#include <stdio.h>
#include "livebackup.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <netdb.h>
#include <utime.h>

static backup_disk_info *get_vdisk_list(int fd, int *ret_num_disks);
static int is_incremental_possible(char *local_vm_dir, int num_disks,
        backup_disk_info *bd);
static int do_snap(int fd, int full, int64_t *snapres);
static int process_one_disk(int fd, char *dirname, int disk,
        backup_disk_info *bd);
static int
get_blocks(int fd, int disk, int64_t curblock,
        int64_t *ret_status, int64_t *ret_off, int64_t *ret_blocks,
        unsigned char *ret_data);
static int destroy_snap(int fd, int64_t *snapres);
static int is_incremental_possible_1_vdisk(char *local_vm_dir,
        backup_disk_info *bd);
static int delete_all_files(char *dir);
static int move_all_files(char *dst, char *src);
static int touch_all_conf_files(char *d, int num_disks, backup_disk_info *bd);

static unsigned char rbuf[BACKUP_MAX_BLOCKS_IN_1_RESP * BACKUP_BLOCK_SIZE];

int
main(int argc, char **argv)
{
    int port;
    struct in_addr in;
    struct sockaddr_in addr;
    int fd;
    int rv;
    int opt;
    int num_disks = 0;
    backup_disk_info *bd = NULL;
    backup_disk_info *bdcur = NULL;
    int do_fullbackup = 0;
    int64_t snapres;
    char full_backup_tmp[PATH_MAX];
    int diskind;

    error_set_progname(argv[0]);

    bdrv_init();

    if (argc != 4) {
        fprintf(stderr, "Usage: %s local_vm_dir vm_server port\n",
			argv[0]);
        return -1;
    }

    port = atoi(argv[3]);

    if (inet_aton(argv[2], &in) == 0) {
        struct hostent *ent;

        ent = gethostbyname(argv[2]);
        if (ent == NULL) {
            goto error;
        }
        memcpy(&in, ent->h_addr, sizeof(in));
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, &in, sizeof(in));

    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Error %d opening socket\n", errno);
        return -1;
    }

    rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rv < 0) {
        fprintf(stderr, "Error %d connecting socket\n", errno);
        return -1;
    }

    opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) == -1) {
        fprintf(stderr, "Error %d setting reuseaddr\n", errno);
        goto error;
    }

    if ((bd = get_vdisk_list(fd, &num_disks)) == NULL) {
        fprintf(stderr, "Error getting vdisk list\n");
        return -1;
    }

    if (!is_incremental_possible(argv[1], num_disks, bd)) {
        fprintf(stderr, "doing full backup\n");
        do_fullbackup = 1;
    }
    if (do_snap(fd, do_fullbackup, &snapres) < 0) {
        fprintf(stderr, "Error executing do_snap command\n");
        return -1;
    }

    if ((bd = get_vdisk_list(fd, &num_disks)) == NULL) {
        fprintf(stderr, "Error getting vdisk list 1\n");
        return -1;
    }

    if (do_fullbackup) {
        sprintf(full_backup_tmp, "%s/tmp", argv[1]);
        if (mkdir(full_backup_tmp, 0755) != 0) {
            if (errno != EEXIST) {
                fprintf(stderr, "Error %d creating tmp directory "
                    "for new full backup %s\n",
                    errno, full_backup_tmp);
                return -1;
            }
        }
        delete_all_files(full_backup_tmp);
        for (diskind = 0; diskind < num_disks; diskind++) {
            bdcur = bd + diskind;
            if (process_one_disk(fd, full_backup_tmp, diskind, bdcur) < 0) {
                fprintf(stderr, "Error. Disk %d(%s). Processing fail\n",
                    diskind, bdcur->name);
                goto error;
            }
        }
        move_all_files(argv[1], full_backup_tmp);
        touch_all_conf_files(argv[1], num_disks, bd);
    } else {
        for (diskind = 0; diskind < num_disks; diskind++) {
            bdcur = bd + diskind;
            if (process_one_disk(fd, argv[1], diskind, bdcur) < 0) {
                fprintf(stderr, "Error. Disk %d(%s). Processing fail\n",
                    diskind, bdcur->name);
                goto error;
            }
        }
    }

    if (destroy_snap(fd, &snapres) < 0) {
        fprintf(stderr, "Error executing destroy_snap command\n");
        return -1;
    }
    return 0;

error:
    /* Note: We don't destroy snap on error */
    exit (-1);
    
}

static int
delete_all_files(char *d)
{
    DIR *dir = opendir(d);
    struct dirent *de;
    char delf[PATH_MAX];
    
    if (dir != NULL) {
        while ((de = readdir(dir)) != NULL) {
            sprintf(delf, "%s/%s", d, de->d_name);
            unlink(delf);
        }
    }
    return 0;
}

static int
move_all_files(char *dst, char *src)
{
    DIR *dir = opendir(src);
    struct dirent *de;
    char srcp[PATH_MAX];
    char dstp[PATH_MAX];
    
    if (dir != NULL) {
        while ((de = readdir(dir)) != NULL) {
            if (!strncmp(de->d_name, ".", 1) ||
                    !strncmp(de->d_name, "..", 2))
                continue;
            sprintf(srcp, "%s/%s", src, de->d_name);
            sprintf(dstp, "%s/%s", dst, de->d_name);
            if (rename(srcp, dstp) != 0) {
                fprintf(stderr, "Warning: Error %d renaming %s to %s\n",
                    errno, srcp, dstp);
            }
        }
    }
    return 0;
}

static int
touch_all_conf_files(char *d, int num_disks, backup_disk_info *bd)
{
    char conf_file[PATH_MAX];
    int diskind;
    char *last;

    for (diskind = 0; diskind < num_disks; diskind++) {
        last = strrchr(bd->name, '/');
        if (last == NULL) {
            sprintf(conf_file, "%s/%s.livebackupconf", d, bd->name);
        } else {
            sprintf(conf_file, "%s/%s.livebackupconf", d, last + 1);
        }
        utime(conf_file, NULL);
        bd++;
    }
    return 0;
}

static backup_disk_info *
get_vdisk_list(int fd, int *ret_num_disks)
{
    backup_request    req;
    get_vdisk_count_result    resp;
    backup_disk_info    *bd = NULL;
    backup_disk_info    *bdcur = NULL;

    req.opcode = B_GET_VDISK_COUNT;
    req.param1 = 0;

    if (write_bytes(fd, (unsigned char *) &req, sizeof(req)) 
                            != sizeof(req)) {
        fprintf(stderr, "error %d writing get_vdisk_list req\n", errno);
        return NULL;
    }
    if (read_bytes(fd, (unsigned char *) &resp, sizeof(resp)) 
                            != sizeof(resp)) {
        fprintf(stderr, "error %d reading get_vdisk_list res\n", errno);
        return NULL;
    }
    if (resp.status > 0) {
        int i;

        *ret_num_disks = resp.status;

        bd = malloc(resp.status * sizeof(backup_disk_info));
        if (read_bytes(fd, (unsigned char *) bd,
                resp.status * sizeof(backup_disk_info))
                != resp.status * sizeof(backup_disk_info)) {
            fprintf(stderr, "error %d reading get_vdisk_list resps\n",
                 errno);
            return NULL;
        }
        for (i = 0; i < resp.status; i++) {
            bdcur = bd + i;
            fprintf(stderr,
                "disk%d=%s. full_backup_mtime %ld, snap %ld\n",
                i, bdcur->name, bdcur->full_backup_mtime, bdcur->snapnumber);
        }
    }

    return bd;
}

static int
is_incremental_possible_1_vdisk(char *local_vm_dir, backup_disk_info *bd)
{
    char conf_file[PATH_MAX];
    char vdisk_file[PATH_MAX];
    struct stat stconf, stv;
    char *last;

    last = strrchr(bd->name, '/');
    if (last == NULL) {
        sprintf(conf_file, "%s/%s.livebackupconf", local_vm_dir, bd->name);
        sprintf(vdisk_file, "%s/%s", local_vm_dir, bd->name);
    } else {
        sprintf(conf_file, "%s/%s.livebackupconf", local_vm_dir, last + 1);
        sprintf(vdisk_file, "%s/%s", local_vm_dir, last + 1);
    }
    if (stat(conf_file, &stconf) == 0) {
        if (stat(vdisk_file, &stv) == 0) {
            if (stconf.st_mtime > stv.st_mtime) {
                /* conf file was modified later than vdisk file */
                int64_t full_backup_mtime;
                int64_t snap;
                if (!parse_conf_file(conf_file, &full_backup_mtime, &snap)) {
                    if (full_backup_mtime == bd->full_backup_mtime
                            && (snap+1) == bd->snapnumber) {
                        return 1;
                    }
                }
            }
        }
    }
    return 0; /* incremental backup is not possible for this vdisk */
}

static int
is_incremental_possible(char *local_vm_dir, int num_disks, backup_disk_info *bd)
{
    int diskind;
    backup_disk_info *vbd = bd;

    for (diskind = 0; diskind < num_disks; diskind++) {
        if (is_incremental_possible_1_vdisk(local_vm_dir, vbd) == 0) {
            return 0;
        }
        vbd++;
    }
    /* All disks match */
    return 1;
}

static int
do_snap(int fd, int full, int64_t *snapres)
{
    backup_request        req;
    do_snap_result        resp;

    req.opcode = B_DO_SNAP;
    req.param1 = full ? B_DO_SNAP_FULLBACKUP : B_DO_SNAP_INCRBACKUP;

    if (write_bytes(fd, (unsigned char *) &req, sizeof(req)) 
                            != sizeof(req)) {
        fprintf(stderr, "error %d writing do_snap req\n", errno);
        return -1;
    }
    if (read_bytes(fd, (unsigned char *) &resp, sizeof(resp)) 
                            != sizeof(resp)) {
        fprintf(stderr, "error %d reading do_snap res\n", errno);
        return -1;
    }
    *snapres = resp.status;
    return 0;
}

/*
 * returns:
 * -1: error
 *  0: success
 * Read blocks from the remote qemu-kvm, and then:
 */
static int
process_one_disk(int fd, char *dirname, int disk, backup_disk_info *bd)
{
    char *last = NULL;
    char conf_file[PATH_MAX];
    char vdisk_file[PATH_MAX];
    int vdisk_fd;
    int64_t off, new_off, status, blocks;

    last = strrchr(bd->name, '/');
    if (last == NULL) {
        sprintf(conf_file, "%s/%s.livebackupconf", dirname, bd->name);
        sprintf(vdisk_file, "%s/%s", dirname, bd->name);
    } else {
        sprintf(conf_file, "%s/%s.livebackupconf", dirname, last + 1);
        sprintf(vdisk_file, "%s/%s", dirname, last + 1);
    }
    if ((vdisk_fd = open(vdisk_file, O_CREAT|O_RDWR,
                        S_IRUSR|S_IWUSR)) < 0) {
        fprintf(stderr, "Error %d opening file %s\n",
                 errno, vdisk_file);
        return -1;
    }

    off = 0;
    while (off < bd->max_blocks) {
        if (get_blocks(fd, disk, off, &status, &new_off, &blocks, rbuf)
                                < 0) {
            fprintf(stderr, "Error: Disk %d(%s) get_blocks(off=%ld)\n",
                disk, bd->name, off);
            return -1;
        } else {
            if (status == B_GET_BLOCKS_SUCCESS) {
                if (0) {
                    int i;
                    for (i = 0; i < blocks; i++)
                        fprintf(stderr, "%ld\n",
                            new_off + i);
                }
                if (vdisk_fd >= 0) {
                    int bwr = pwrite(vdisk_fd,
                                rbuf,
                                blocks * 512,
                                new_off * 512);
                    if (bwr != (blocks * 512)) {
                        fprintf(stderr, "Error %d write of cur base",
                                errno);
                        return -1;
                    }
                }
                off = new_off + blocks;
                if (0) {
                    struct timespec tms;
                    tms.tv_sec = 0;
                    tms.tv_nsec = 20000000; /* 20 ms */
                    nanosleep(&tms, NULL);
                }
                continue;
            } else if (status == B_GET_BLOCKS_NO_MORE_BLOCKS) {
                break;
            } else {
                fprintf(stderr, "Error: Disk %d(%s) "
                    "get_blocks(off=%ld).status=%ld\n",
                    disk, bd->name, off, status);
                return -1;
            }
        }
    }
    if (vdisk_fd >= 0) close(vdisk_fd);
    write_conf_file(conf_file, bd->full_backup_mtime, bd->snapnumber);
    return 0;
}

static int
get_blocks(int fd, int disk, int64_t curblock,
        int64_t *ret_status, int64_t *ret_off, int64_t *ret_blocks,
        unsigned char *ret_data)
{
    backup_request        req;
    get_blocks_result    resp;

    req.opcode = B_GET_BLOCKS;
    req.param1 = (int64_t) disk;
    req.param2 = curblock;

    if (write_bytes(fd, (unsigned char *) &req, sizeof(req)) 
                            != sizeof(req)) {
        fprintf(stderr, "error %d writing get_blocks req\n", errno);
        return -1;
    }
    if (read_bytes(fd, (unsigned char *) &resp, sizeof(resp)) 
                            != sizeof(resp)) {
        fprintf(stderr, "error %d reading get_blocks res\n", errno);
        return -1;
    }
    *ret_status = resp.status;
    if (resp.status == B_GET_BLOCKS_SUCCESS) {
        if (read_bytes(fd, ret_data, resp.blocks * BACKUP_BLOCK_SIZE) 
                    != (resp.blocks * BACKUP_BLOCK_SIZE)) {
            fprintf(stderr, "error %d reading get_blocks data\n",
                errno);
            return -1;
        }
        *ret_off = resp.offset;
        *ret_blocks = resp.blocks;
    } else {
        *ret_off = 0;
        *ret_blocks = 0;
    }
    return 0;
}

static int
destroy_snap(int fd, int64_t *snapres)
{
    backup_request        req;
    destroy_snap_result    resp;

    req.opcode = B_DESTROY_SNAP;
    req.param1 = 0;

    if (write_bytes(fd, (unsigned char *) &req, sizeof(req)) 
                            != sizeof(req)) {
        fprintf(stderr, "error %d writing destroy_snap req\n", errno);
        return -1;
    }
    if (read_bytes(fd, (unsigned char *) &resp, sizeof(resp)) 
                            != sizeof(resp)) {
        fprintf(stderr, "error %d reading destroy_snap res\n", errno);
        return -1;
    }
    *snapres = resp.status;
    return 0;
}

