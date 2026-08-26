#include "FilesystemShare.h"
#include "PathSandbox.h"

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>
#include <smb2/libsmb2-raw.h>
#include <smb2/smb2-errors.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define INAS_MAX_HANDLES 256
#define INAS_SHARE_DEFAULT "inas"
#define PAD_TO_64BIT(len) (((len) + 0x07u) & 0xfffffff8u)

struct inas_handle {
        int in_use;
        smb2_file_id id;
        int fd;
        DIR *dir;
        char path[PATH_MAX];
        int is_dir;
        int delete_on_close;
        uint32_t enum_index;
        int enum_done;
        uint32_t access;
};

struct inas_state {
        pthread_mutex_t lock;
        pthread_t thread;
        int thread_started;
        volatile int running;
        int listen_fd;
        uint16_t port;
        char root[PATH_MAX];
        char share[64];
        char user[128];
        char password[128];
        char hostname[128];
        struct inas_handle handles[INAS_MAX_HANDLES];
        uint64_t id_counter;
        atomic_int clients;
        atomic_uint_fast64_t bytes;
        struct smb2_server server;
};

static struct inas_state g;

static void
fill_file_id(smb2_file_id id, uint64_t n)
{
        memset(id, 0, SMB2_FD_SIZE);
        memcpy(id, &n, sizeof(n));
}

static int
file_id_equal(const smb2_file_id a, const smb2_file_id b)
{
        return memcmp(a, b, SMB2_FD_SIZE) == 0;
}

static struct inas_handle *
handle_lookup(const smb2_file_id id)
{
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                if (g.handles[i].in_use && file_id_equal(g.handles[i].id, id)) {
                        return &g.handles[i];
                }
        }
        return NULL;
}

static struct inas_handle *
handle_alloc(void)
{
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                if (!g.handles[i].in_use) {
                        memset(&g.handles[i], 0, sizeof(g.handles[i]));
                        g.handles[i].in_use = 1;
                        g.handles[i].fd = -1;
                        g.id_counter++;
                        fill_file_id(g.handles[i].id, g.id_counter);
                        return &g.handles[i];
                }
        }
        return NULL;
}

static void
handle_free(struct inas_handle *h)
{
        if (!h || !h->in_use) {
                return;
        }
        if (h->fd >= 0) {
                close(h->fd);
        }
        if (h->dir) {
                closedir(h->dir);
        }
        if (h->delete_on_close) {
                if (h->is_dir) {
                        rmdir(h->path);
                } else {
                        unlink(h->path);
                }
        }
        memset(h, 0, sizeof(*h));
        h->fd = -1;
}

static uint64_t
timespec_to_smb(const struct timespec *ts)
{
        struct smb2_timeval tv;
        tv.tv_sec = ts->tv_sec;
        tv.tv_usec = (long)(ts->tv_nsec / 1000);
        return smb2_timeval_to_win(&tv);
}

static void
stat_to_timeval(const struct timespec *ts, struct smb2_timeval *out)
{
        out->tv_sec = ts->tv_sec;
        out->tv_usec = (long)(ts->tv_nsec / 1000);
}

static uint32_t
stat_to_attrs(const struct stat *st)
{
        if (S_ISDIR(st->st_mode)) {
                return SMB2_FILE_ATTRIBUTE_DIRECTORY;
        }
        return SMB2_FILE_ATTRIBUTE_NORMAL;
}

static int
share_from_tree_path(const uint16_t *path, uint16_t path_length, char *out, size_t out_len)
{
        if (!path || path_length < 2 || !out || out_len == 0) {
                return -1;
        }
        const char *utf8 = smb2_utf16_to_utf8(path, path_length / 2);
        if (!utf8) {
                return -1;
        }
        const char *slash = strrchr(utf8, '\\');
        const char *name = slash ? slash + 1 : utf8;
        if (name[0] == '\0') {
                free((void *)utf8);
                return -1;
        }
        snprintf(out, out_len, "%s", name);
        free((void *)utf8);
        return 0;
}

static int
authorize_user(struct smb2_server *srvr, struct smb2_context *smb2,
               const char *user, const char *domain, const char *workstation)
{
        (void)srvr;
        (void)domain;
        (void)workstation;
        pthread_mutex_lock(&g.lock);
        int ok = user && strcasecmp(user, g.user) == 0 && g.password[0] != '\0';
        if (ok) {
                smb2_set_user(smb2, g.user);
                smb2_set_password(smb2, g.password);
        }
        pthread_mutex_unlock(&g.lock);
        return ok ? 0 : -1;
}

static int
session_established(struct smb2_server *srvr, struct smb2_context *smb2)
{
        (void)srvr;
        (void)smb2;
        atomic_fetch_add(&g.clients, 1);
        return 0;
}

static int
destruction_event(struct smb2_server *srvr, struct smb2_context *smb2)
{
        (void)srvr;
        (void)smb2;
        int n = atomic_fetch_sub(&g.clients, 1);
        if (n <= 1) {
                atomic_store(&g.clients, 0);
        }
        return 0;
}

static int
logoff_cmd(struct smb2_server *srvr, struct smb2_context *smb2)
{
        (void)srvr;
        (void)smb2;
        return 0;
}

static int
tree_connect_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                 struct smb2_tree_connect_request *req,
                 struct smb2_tree_connect_reply *rep)
{
        (void)srvr;
        (void)smb2;
        char share[128];
        if (share_from_tree_path(req->path, req->path_length, share, sizeof(share)) != 0) {
                return -1;
        }
        if (strcasecmp(share, g.share) != 0) {
                return -1;
        }
        rep->share_type = SMB2_SHARE_TYPE_DISK;
        rep->share_flags = SMB2_SHAREFLAG_NO_CACHING | SMB2_SHAREFLAG_ENCRYPT_DATA;
        rep->capabilities = 0;
        rep->maximal_access = 0x001f01ff;
        return 0;
}

static int
tree_disconnect_cmd(struct smb2_server *srvr, struct smb2_context *smb2, const uint32_t tree_id)
{
        (void)srvr;
        (void)smb2;
        (void)tree_id;
        return 0;
}

static int
open_path(struct inas_handle *h, const char *path, struct smb2_create_request *req, struct stat *st)
{
        int is_dir_req = (req->create_options & SMB2_FILE_DIRECTORY_FILE) != 0;
        int is_file_req = (req->create_options & SMB2_FILE_NON_DIRECTORY_FILE) != 0;
        int exists = (stat(path, st) == 0);

        if (exists && is_dir_req && !S_ISDIR(st->st_mode)) {
                return -ENOTDIR;
        }
        if (exists && is_file_req && S_ISDIR(st->st_mode)) {
                return -EISDIR;
        }

        uint32_t disp = req->create_disposition;
        if (!exists) {
                if (disp == SMB2_FILE_OPEN || disp == SMB2_FILE_OVERWRITE) {
                        return -ENOENT;
                }
                if (is_dir_req) {
                        if (mkdir(path, 0755) != 0) {
                                return -errno;
                        }
                } else {
                        int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
                        if (fd < 0) {
                                return -errno;
                        }
                        h->fd = fd;
                }
        } else {
                if (disp == SMB2_FILE_CREATE) {
                        return -EEXIST;
                }
                if (S_ISDIR(st->st_mode)) {
                        if (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF || disp == SMB2_FILE_SUPERSEDE) {
                                return -EISDIR;
                        }
                } else {
                        int flags = O_RDWR;
                        if (disp == SMB2_FILE_OVERWRITE || disp == SMB2_FILE_OVERWRITE_IF || disp == SMB2_FILE_SUPERSEDE) {
                                flags |= O_TRUNC;
                        }
                        if (disp == SMB2_FILE_SUPERSEDE) {
                                unlink(path);
                                flags = O_RDWR | O_CREAT | O_TRUNC;
                        }
                        int fd = open(path, flags, 0644);
                        if (fd < 0) {
                                fd = open(path, O_RDONLY);
                                if (fd < 0) {
                                        return -errno;
                                }
                        }
                        h->fd = fd;
                }
        }

        if (stat(path, st) != 0) {
                return -errno;
        }
        h->is_dir = S_ISDIR(st->st_mode);
        if (h->is_dir) {
                h->dir = opendir(path);
                if (!h->dir) {
                        return -errno;
                }
        }
        snprintf(h->path, sizeof(h->path), "%s", path);
        h->delete_on_close = (req->create_options & SMB2_FILE_DELETE_ON_CLOSE) != 0;
        h->access = req->desired_access;
        return 0;
}

static int
create_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
           struct smb2_create_request *req, struct smb2_create_reply *rep)
{
        (void)srvr;
        (void)smb2;
        char resolved[PATH_MAX];
        const char *name = req->name ? req->name : "";
        if (inas_path_resolve(g.root, name, resolved, sizeof(resolved)) != 0) {
                return -1;
        }

        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_alloc();
        if (!h) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        struct stat st;
        memset(&st, 0, sizeof(st));
        int err = open_path(h, resolved, req, &st);
        if (err != 0) {
                handle_free(h);
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        memcpy(rep->file_id, h->id, SMB2_FD_SIZE);
        rep->file_attributes = stat_to_attrs(&st);
        rep->end_of_file = (uint64_t)st.st_size;
        rep->allocation_size = (uint64_t)st.st_blocks * 512ull;
        rep->creation_time = timespec_to_smb(&st.st_birthtimespec);
        rep->last_access_time = timespec_to_smb(&st.st_atimespec);
        rep->last_write_time = timespec_to_smb(&st.st_mtimespec);
        rep->change_time = timespec_to_smb(&st.st_ctimespec);
        rep->oplock_level = SMB2_OPLOCK_LEVEL_NONE;
        pthread_mutex_unlock(&g.lock);
        return 0;
}

static int
close_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
          struct smb2_close_request *req, struct smb2_close_reply *rep)
{
        (void)srvr;
        (void)smb2;
        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_lookup(req->file_id);
        if (!h) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        struct stat st;
        memset(&st, 0, sizeof(st));
        stat(h->path, &st);
        memset(rep, 0, sizeof(*rep));
        rep->file_attributes = stat_to_attrs(&st);
        rep->end_of_file = (uint64_t)st.st_size;
        handle_free(h);
        pthread_mutex_unlock(&g.lock);
        return 0;
}

static int
flush_cmd(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_flush_request *req)
{
        (void)srvr;
        (void)smb2;
        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_lookup(req->file_id);
        if (!h) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        if (h->fd >= 0) {
                fsync(h->fd);
        }
        pthread_mutex_unlock(&g.lock);
        return 0;
}

static int
read_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
         struct smb2_read_request *req, struct smb2_read_reply *rep)
{
        (void)srvr;
        (void)smb2;
        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_lookup(req->file_id);
        if (!h || h->fd < 0) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        uint32_t len = req->length;
        uint8_t *buf = malloc(len ? len : 1);
        if (!buf) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        ssize_t n = pread(h->fd, buf, len, (off_t)req->offset);
        pthread_mutex_unlock(&g.lock);
        if (n < 0) {
                free(buf);
                return -1;
        }
        if (n == 0) {
                free(buf);
                rep->data = NULL;
                rep->data_length = 0;
                rep->data_remaining = 0;
                return 0;
        }
        rep->data = buf;
        rep->data_length = (uint32_t)n;
        rep->data_remaining = 0;
        atomic_fetch_add(&g.bytes, (uint64_t)n);
        return 0;
}

static int
write_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
          struct smb2_write_request *req, struct smb2_write_reply *rep)
{
        (void)srvr;
        (void)smb2;
        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_lookup(req->file_id);
        if (!h || h->fd < 0) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        ssize_t n = pwrite(h->fd, req->buf, req->length, (off_t)req->offset);
        pthread_mutex_unlock(&g.lock);
        if (n < 0) {
                return -1;
        }
        rep->count = (uint32_t)n;
        rep->remaining = 0;
        atomic_fetch_add(&g.bytes, (uint64_t)n);
        return 0;
}

static int
match_pattern(const char *name, const char *pattern)
{
        if (!pattern || pattern[0] == '\0' || strcmp(pattern, "*") == 0 || strcmp(pattern, "*.*") == 0) {
                return 1;
        }
        /* Very small glob: * and ? */
        const char *n = name;
        const char *p = pattern;
        while (*n && *p) {
                if (*p == '*') {
                        p++;
                        if (*p == '\0') {
                                return 1;
                        }
                        while (*n) {
                                if (match_pattern(n, p)) {
                                        return 1;
                                }
                                n++;
                        }
                        return 0;
                }
                if (*p == '?' || *p == *n) {
                        p++;
                        n++;
                        continue;
                }
                return 0;
        }
        while (*p == '*') {
                p++;
        }
        return *n == '\0' && *p == '\0';
}

static int
query_directory_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
                    struct smb2_query_directory_request *req,
                    struct smb2_query_directory_reply *rep)
{
        (void)srvr;
        (void)smb2;
        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_lookup(req->file_id);
        if (!h || !h->is_dir) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        if (req->flags & (SMB2_RESTART_SCANS | SMB2_REOPEN)) {
                h->enum_index = 0;
                h->enum_done = 0;
                if (h->dir) {
                        rewinddir(h->dir);
                }
        }
        if (h->enum_done) {
                pthread_mutex_unlock(&g.lock);
                rep->output_buffer = NULL;
                rep->output_buffer_length = 0;
                return 0;
        }
        if (!h->dir) {
                h->dir = opendir(h->path);
                if (!h->dir) {
                        pthread_mutex_unlock(&g.lock);
                        return -1;
                }
        }

        const char *pattern = req->name ? req->name : "*";
        struct dirent *de;
        struct smb2_fileidbothdirectoryinformation *entries = NULL;
        size_t count = 0;
        size_t cap = 0;
        rewinddir(h->dir);
        uint32_t skip = h->enum_index;
        uint32_t seen = 0;

        while ((de = readdir(h->dir)) != NULL) {
                if (!match_pattern(de->d_name, pattern)) {
                        continue;
                }
                if (seen++ < skip) {
                        continue;
                }
                if (count + 1 > cap) {
                        cap = cap ? cap * 2 : 16;
                        void *nbuf = realloc(entries, cap * sizeof(*entries));
                        if (!nbuf) {
                                free(entries);
                                pthread_mutex_unlock(&g.lock);
                                return -1;
                        }
                        entries = nbuf;
                }
                char full[PATH_MAX];
                snprintf(full, sizeof(full), "%s/%s", h->path, de->d_name);
                struct stat st;
                memset(&st, 0, sizeof(st));
                lstat(full, &st);
                struct smb2_fileidbothdirectoryinformation *e = &entries[count];
                memset(e, 0, sizeof(*e));
                e->file_index = h->enum_index + (uint32_t)count;
                stat_to_timeval(&st.st_birthtimespec, &e->creation_time);
                stat_to_timeval(&st.st_atimespec, &e->last_access_time);
                stat_to_timeval(&st.st_mtimespec, &e->last_write_time);
                stat_to_timeval(&st.st_ctimespec, &e->change_time);
                e->end_of_file = (uint64_t)st.st_size;
                e->allocation_size = (uint64_t)st.st_blocks * 512ull;
                e->file_attributes = stat_to_attrs(&st);
                e->file_id = (uint64_t)st.st_ino;
                e->name = strdup(de->d_name);
                count++;
                if (req->flags & SMB2_RETURN_SINGLE_ENTRY) {
                        break;
                }
        }
        h->enum_index += (uint32_t)count;
        if (count == 0) {
                h->enum_done = 1;
                pthread_mutex_unlock(&g.lock);
                rep->output_buffer = NULL;
                rep->output_buffer_length = 0;
                return 0;
        }

        size_t packed = PAD_TO_64BIT(sizeof(struct smb2_fileidbothdirectoryinformation)) * count;
        uint8_t *buf = calloc(1, packed);
        if (!buf) {
                for (size_t i = 0; i < count; i++) {
                        free((void *)entries[i].name);
                }
                free(entries);
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        for (size_t i = 0; i < count; i++) {
                memcpy(buf + i * PAD_TO_64BIT(sizeof(struct smb2_fileidbothdirectoryinformation)),
                       &entries[i], sizeof(entries[i]));
        }
        free(entries);
        pthread_mutex_unlock(&g.lock);
        rep->output_buffer = buf;
        rep->output_buffer_length = (uint32_t)packed;
        return 0;
}

static int
fill_basic(const struct stat *st, struct smb2_file_basic_info *info)
{
        memset(info, 0, sizeof(*info));
        stat_to_timeval(&st->st_birthtimespec, &info->creation_time);
        stat_to_timeval(&st->st_atimespec, &info->last_access_time);
        stat_to_timeval(&st->st_mtimespec, &info->last_write_time);
        stat_to_timeval(&st->st_ctimespec, &info->change_time);
        info->file_attributes = stat_to_attrs(st);
        return (int)sizeof(*info);
}

static int
fill_standard(const struct stat *st, struct smb2_file_standard_info *info)
{
        memset(info, 0, sizeof(*info));
        info->allocation_size = (uint64_t)st->st_blocks * 512ull;
        info->end_of_file = (uint64_t)st->st_size;
        info->number_of_links = (uint32_t)st->st_nlink;
        info->directory = S_ISDIR(st->st_mode) ? 1 : 0;
        return (int)sizeof(*info);
}

static int
query_info_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
               struct smb2_query_info_request *req,
               struct smb2_query_info_reply *rep)
{
        (void)srvr;
        (void)smb2;
        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_lookup(req->file_id);
        struct stat st;
        memset(&st, 0, sizeof(st));
        if (h) {
                stat(h->path, &st);
        } else {
                stat(g.root, &st);
        }
        pthread_mutex_unlock(&g.lock);

        void *info = NULL;
        int len = 0;

        if (req->info_type == SMB2_0_INFO_FILE) {
                switch (req->file_info_class) {
                case SMB2_FILE_BASIC_INFORMATION: {
                        struct smb2_file_basic_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        len = fill_basic(&st, p);
                        info = p;
                        break;
                }
                case SMB2_FILE_STANDARD_INFORMATION: {
                        struct smb2_file_standard_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        len = fill_standard(&st, p);
                        info = p;
                        break;
                }
                case SMB2_FILE_INTERNAL_INFORMATION: {
                        uint64_t *p = calloc(1, sizeof(uint64_t));
                        if (!p) return -1;
                        *p = (uint64_t)st.st_ino;
                        info = p;
                        len = 8;
                        break;
                }
                case SMB2_FILE_ACCESS_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p) return -1;
                        *p = 0x001f01ff;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_ALL_INFORMATION: {
                        struct smb2_file_all_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        fill_basic(&st, &p->basic);
                        fill_standard(&st, &p->standard);
                        p->index_number = (uint64_t)st.st_ino;
                        p->access_flags = 0x001f01ff;
                        p->name = (const uint8_t *)(h ? strrchr(h->path, '/') : (const char *)"");
                        if (p->name && p->name[0] == '/') {
                                p->name++;
                        }
                        if (!p->name) {
                                p->name = (const uint8_t *)"";
                        }
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_NETWORK_OPEN_INFORMATION: {
                        struct smb2_file_network_open_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        stat_to_timeval(&st.st_birthtimespec, &p->creation_time);
                        stat_to_timeval(&st.st_atimespec, &p->last_access_time);
                        stat_to_timeval(&st.st_mtimespec, &p->last_write_time);
                        stat_to_timeval(&st.st_ctimespec, &p->change_time);
                        p->allocation_size = (uint64_t)st.st_blocks * 512ull;
                        p->end_of_file = (uint64_t)st.st_size;
                        p->file_attributes = stat_to_attrs(&st);
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_EA_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p) return -1;
                        *p = 0;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_POSITION_INFORMATION: {
                        struct smb2_file_position_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_MODE_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p) return -1;
                        *p = 0;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_ALIGNMENT_INFORMATION: {
                        uint32_t *p = calloc(1, sizeof(uint32_t));
                        if (!p) return -1;
                        *p = 0;
                        info = p;
                        len = 4;
                        break;
                }
                case SMB2_FILE_NAME_INFORMATION: {
                        struct smb2_file_name_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        const char *leaf = h ? strrchr(h->path, '/') : NULL;
                        leaf = leaf ? leaf + 1 : (h ? h->path : g.share);
                        p->name = (const uint8_t *)leaf;
                        p->file_name_length = (uint32_t)(strlen(leaf) * 2);
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                default:
                        return -1;
                }
        } else if (req->info_type == SMB2_0_INFO_FILESYSTEM) {
                struct statvfs vfs;
                memset(&vfs, 0, sizeof(vfs));
                statvfs(g.root, &vfs);
                switch (req->file_info_class) {
                case SMB2_FILE_FS_VOLUME_INFORMATION: {
                        struct smb2_file_fs_volume_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        p->volume_serial_number = 0x314e4153;
                        p->volume_label = (const uint8_t *)"iNAS";
                        p->volume_label_length = 8;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_SIZE_INFORMATION: {
                        struct smb2_file_fs_size_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        p->total_allocation_units = vfs.f_blocks;
                        p->available_allocation_units = vfs.f_bavail;
                        p->sectors_per_allocation_unit = 1;
                        p->bytes_per_sector = (uint32_t)vfs.f_frsize;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_DEVICE_INFORMATION: {
                        struct smb2_file_fs_device_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        p->device_type = FILE_DEVICE_DISK;
                        p->characteristics = 0;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_ATTRIBUTE_INFORMATION: {
                        struct smb2_file_fs_attribute_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        p->filesystem_attributes = 0x00000002; /* CASE_PRESERVED */
                        p->maximum_component_name_length = 255;
                        p->filesystem_name = (const uint8_t *)"iNAS";
                        p->filesystem_name_length = 8;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                case SMB2_FILE_FS_FULL_SIZE_INFORMATION: {
                        struct smb2_file_fs_size_info *p = calloc(1, sizeof(*p));
                        if (!p) return -1;
                        p->total_allocation_units = vfs.f_blocks;
                        p->available_allocation_units = vfs.f_bavail;
                        p->sectors_per_allocation_unit = 1;
                        p->bytes_per_sector = (uint32_t)vfs.f_frsize;
                        info = p;
                        len = (int)sizeof(*p);
                        break;
                }
                default:
                        return -1;
                }
        } else {
                return -1;
        }

        rep->output_buffer = info;
        rep->output_buffer_length = (uint32_t)len;
        return len > 0 ? 0 : -1;
}

static int
set_info_cmd(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_set_info_request *req)
{
        (void)srvr;
        (void)smb2;
        pthread_mutex_lock(&g.lock);
        struct inas_handle *h = handle_lookup(req->file_id);
        if (!h) {
                pthread_mutex_unlock(&g.lock);
                return -1;
        }
        int rc = 0;
        if (req->info_type == SMB2_0_INFO_FILE) {
                switch (req->file_info_class) {
                case SMB2_FILE_DISPOSITION_INFORMATION: {
                        struct smb2_file_disposition_info *info = req->input_data;
                        if (info) {
                                h->delete_on_close = info->delete_pending ? 1 : 0;
                        }
                        break;
                }
                case SMB2_FILE_END_OF_FILE_INFORMATION: {
                        struct smb2_file_end_of_file_info *info = req->input_data;
                        if (info && h->fd >= 0) {
                                if (ftruncate(h->fd, (off_t)info->end_of_file) != 0) {
                                        rc = -1;
                                }
                        }
                        break;
                }
                case SMB2_FILE_RENAME_INFORMATION: {
                        struct smb2_file_rename_info *info = req->input_data;
                        if (!info || !info->file_name) {
                                rc = -1;
                                break;
                        }
                        char dest[PATH_MAX];
                        if (inas_path_resolve(g.root, (const char *)info->file_name, dest, sizeof(dest)) != 0) {
                                rc = -1;
                                break;
                        }
                        if (!info->replace_if_exist && access(dest, F_OK) == 0) {
                                rc = -1;
                                break;
                        }
                        if (rename(h->path, dest) != 0) {
                                rc = -1;
                                break;
                        }
                        snprintf(h->path, sizeof(h->path), "%s", dest);
                        break;
                }
                case SMB2_FILE_BASIC_INFORMATION:
                case SMB2_FILE_ALLOCATION_INFORMATION:
                case SMB2_FILE_POSITION_INFORMATION:
                case SMB2_FILE_MODE_INFORMATION:
                        break;
                default:
                        rc = -1;
                        break;
                }
        } else {
                rc = -1;
        }
        pthread_mutex_unlock(&g.lock);
        return rc;
}

static int
ioctl_cmd(struct smb2_server *srvr, struct smb2_context *smb2,
          struct smb2_ioctl_request *req, struct smb2_ioctl_reply *rep)
{
        (void)srvr;
        (void)smb2;
        memset(rep, 0, sizeof(*rep));
        rep->ctl_code = req->ctl_code;
        memcpy(rep->file_id, req->file_id, SMB2_FD_SIZE);
        if (req->ctl_code == SMB2_FSCTL_VALIDATE_NEGOTIATE_INFO) {
                return 0;
        }
        /* Unknown FSCTL: not fatal for common clients. */
        return 0;
}

static int
lock_cmd(struct smb2_server *srvr, struct smb2_context *smb2, struct smb2_lock_request *req)
{
        (void)srvr;
        (void)smb2;
        (void)req;
        return 0;
}

static int
echo_cmd(struct smb2_server *srvr, struct smb2_context *smb2)
{
        (void)srvr;
        (void)smb2;
        return 0;
}

static int
cancel_cmd(struct smb2_server *srvr, struct smb2_context *smb2)
{
        (void)srvr;
        (void)smb2;
        return 0;
}

static struct smb2_server_request_handlers g_handlers = {
        destruction_event,
        authorize_user,
        session_established,
        logoff_cmd,
        tree_connect_cmd,
        tree_disconnect_cmd,
        create_cmd,
        close_cmd,
        flush_cmd,
        read_cmd,
        write_cmd,
        NULL,
        NULL,
        lock_cmd,
        ioctl_cmd,
        cancel_cmd,
        echo_cmd,
        query_directory_cmd,
        NULL,
        query_info_cmd,
        set_info_cmd
};

static void
on_new_client(struct smb2_context *smb2, void *cb_data)
{
        (void)cb_data;
        smb2_set_version(smb2, SMB2_VERSION_ANY3);
        smb2_set_authentication(smb2, SMB2_SEC_NTLMSSP);
        smb2_set_seal(smb2, 1);
        smb2_set_sign(smb2, 1);
}

static void *
server_thread(void *arg)
{
        (void)arg;
        int err = smb2_serve_port(&g.server, 8, on_new_client, NULL);
        (void)err;
        g.running = 0;
        return NULL;
}

static void
extra_fdset(struct smb2_server *server, fd_set *rfds, fd_set *wfds, int *maxfd)
{
        (void)wfds;
        if (!g.running && server->fd >= 0) {
                shutdown(server->fd, SHUT_RDWR);
        }
        (void)rfds;
        (void)maxfd;
}

static void
extra_service(struct smb2_server *server, fd_set *rfds, fd_set *wfds)
{
        (void)rfds;
        (void)wfds;
        if (!g.running && server->fd >= 0) {
                close(server->fd);
                server->fd = -1;
        }
}

int
inas_smb_start(const inas_smb_config *config)
{
        if (!config || !config->root_path || !config->username || !config->password) {
                return -EINVAL;
        }
        pthread_mutex_lock(&g.lock);
        if (g.running) {
                pthread_mutex_unlock(&g.lock);
                return -EALREADY;
        }

        memset(&g.server, 0, sizeof(g.server));
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                handle_free(&g.handles[i]);
        }
        g.id_counter = 1;
        atomic_store(&g.clients, 0);
        atomic_store(&g.bytes, 0);

        if (!realpath(config->root_path, g.root)) {
                pthread_mutex_unlock(&g.lock);
                return -errno;
        }
        snprintf(g.share, sizeof(g.share), "%s",
                 config->share_name && config->share_name[0] ? config->share_name : INAS_SHARE_DEFAULT);
        snprintf(g.user, sizeof(g.user), "%s", config->username);
        snprintf(g.password, sizeof(g.password), "%s", config->password);
        if (config->hostname && config->hostname[0]) {
                snprintf(g.hostname, sizeof(g.hostname), "%s", config->hostname);
        } else {
                gethostname(g.hostname, sizeof(g.hostname));
        }

        g.server.handlers = &g_handlers;
        g.server.signing_enabled = 1;
        g.server.allow_anonymous = 0;
        g.server.port = config->port ? config->port : 445;
        g.server.max_transact_size = 0x100000;
        g.server.max_read_size = 0x100000;
        g.server.max_write_size = 0x100000;
        memcpy(g.server.guid, "iNAS-smb2-guid!", 16);
        snprintf(g.server.hostname, sizeof(g.server.hostname), "%s", g.hostname);
        snprintf(g.server.domain, sizeof(g.server.domain), "%s", "WORKGROUP");
        g.server.extra_fdset = extra_fdset;
        g.server.extra_service = extra_service;

        g.port = g.server.port;
        g.running = 1;
        g.thread_started = 0;
        int rc = pthread_create(&g.thread, NULL, server_thread, NULL);
        if (rc != 0) {
                g.running = 0;
                pthread_mutex_unlock(&g.lock);
                return -rc;
        }
        g.thread_started = 1;
        pthread_mutex_unlock(&g.lock);

        /* Wait briefly for bind so we can report the live port. */
        for (int i = 0; i < 50 && g.server.fd <= 0 && g.running; i++) {
                usleep(20000);
        }
        if (g.server.fd <= 0) {
                g.running = 0;
                pthread_join(g.thread, NULL);
                g.thread_started = 0;
                return -EADDRINUSE;
        }
        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        if (getsockname(g.server.fd, (struct sockaddr *)&addr, &alen) == 0) {
                g.port = ntohs(addr.sin_port);
        }
        return 0;
}

void
inas_smb_stop(void)
{
        pthread_mutex_lock(&g.lock);
        g.running = 0;
        if (g.server.fd >= 0) {
                shutdown(g.server.fd, SHUT_RDWR);
                close(g.server.fd);
                g.server.fd = -1;
        }
        int started = g.thread_started;
        pthread_mutex_unlock(&g.lock);
        if (started) {
                pthread_join(g.thread, NULL);
                g.thread_started = 0;
        }
        pthread_mutex_lock(&g.lock);
        for (int i = 0; i < INAS_MAX_HANDLES; i++) {
                handle_free(&g.handles[i]);
        }
        memset(g.password, 0, sizeof(g.password));
        pthread_mutex_unlock(&g.lock);
}

int
inas_smb_is_running(void)
{
        return g.running;
}

int
inas_smb_bound_port(void)
{
        return g.port;
}

int
inas_smb_client_count(void)
{
        return atomic_load(&g.clients);
}

uint64_t
inas_smb_bytes_transferred(void)
{
        return atomic_load(&g.bytes);
}

__attribute__((constructor))
static void
inas_init(void)
{
        pthread_mutex_init(&g.lock, NULL);
        g.server.fd = -1;
}
