#define _GNU_SOURCE
#include "detector.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define GUARD_BIN  "/app/guard/detector.bin"
#define GUARD_CONF "/app/guard/guard.conf"
#define PROSE_MAX  1024
#define NSUB       16

struct Submission {
    int    active;
    int    clean;
    long   words;
    long   late;
    long   draft;
    char   student[16];
    char   prose[48];
    size_t tlen;
    size_t tcap;
    char  *appendix;
};

union Slot {
    struct Submission sub;
    long              raw[sizeof(struct Submission) / sizeof(long)];
};

static struct {
    union Slot        anchor;
    struct Submission subs[NSUB];
} g_state;
#define submissions (g_state.subs)

static char g_gradebuf[0x400];

static void op_submit(void);
static void op_attach(void);
static void op_revise(void);
static void op_view(void);
static void op_score(void);
static void op_grade(void);
static void op_retract(void);
static void op_roster(void);

static void install_seccomp(void)
{
    static const int allow[] = {
        __NR_read, __NR_write, __NR_openat, __NR_open, __NR_lseek, __NR_close,
        __NR_newfstatat, __NR_fstat, __NR_brk, __NR_mmap, __NR_munmap,
        __NR_rt_sigreturn, __NR_getrandom, __NR_exit, __NR_exit_group,
    };
    const int n = (int)(sizeof(allow) / sizeof(allow[0]));
    struct sock_filter filt[2 + 1 + 64 + 2];
    int p = 0;

    filt[p++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                   (offsetof(struct seccomp_data, arch)));
    filt[p++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                   AUDIT_ARCH_X86_64, 1, 0);
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                   SECCOMP_RET_KILL_PROCESS);
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                   (offsetof(struct seccomp_data, nr)));
    for (int i = 0; i < n; i++)
        filt[p++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                       allow[i], (n - i), 0);
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                   SECCOMP_RET_KILL_PROCESS);
    filt[p++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                   SECCOMP_RET_ALLOW);

    struct sock_fprog prog = { .len = (unsigned short)p, .filter = filt };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) _exit(70);
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) _exit(71);
}

static size_t read_exact(void *buf, size_t len)
{
    size_t got = 0;
    char *b = buf;
    while (got < len) {
        size_t r = fread(b + got, 1, len - got, stdin);
        if (r == 0) break;
        got += r;
    }
    return got;
}

static void skip_bytes(size_t len)
{
    char tmp[256];
    while (len) {
        size_t chunk = len < sizeof tmp ? len : sizeof tmp;
        size_t r = fread(tmp, 1, chunk, stdin);
        if (r == 0) break;
        len -= r;
    }
}

static struct Submission *resolve(long id)
{
    if (id > NSUB - 1) {
        printf("err: no such report\n");
        return NULL;
    }
    return &submissions[id];
}

static void op_submit(void)
{
    char student[64];
    long words, late, draft, len;
    if (scanf("%63s %ld %ld %ld %ld", student, &words, &late, &draft, &len) != 5) {
        printf("err: bad submit\n");
        return;
    }
    getchar();

    if (len < 0) len = 0;
    if (len > PROSE_MAX) len = PROSE_MAX;
    char text[PROSE_MAX];
    size_t got = read_exact(text, (size_t)len);

    int slot = -1;
    for (int i = 0; i < NSUB; i++)
        if (!submissions[i].active) { slot = i; break; }
    if (slot < 0) {
        printf("err: desk full\n");
        return;
    }

    struct Submission *s = &submissions[slot];
    memset(s, 0, sizeof *s);
    s->active = 1;
    s->words = words;
    s->late = late;
    s->draft = draft;
    strncpy(s->student, student, sizeof s->student - 1);
    memcpy(s->prose, text, got < sizeof s->prose - 1 ? got : sizeof s->prose - 1);

    s->clean = detector_is_clean(text, got);
    printf("ok: report %d filed, status=%s\n", slot, s->clean ? "clean" : "quarantined");
}

static void op_attach(void)
{
    long id; int len;
    if (scanf("%ld %d", &id, &len) != 2) { printf("err: bad attach\n"); return; }
    getchar();

    struct Submission *s = resolve(id);
    if (!s) { skip_bytes(len > 0 ? (size_t)len : 0); return; }
    if (!s->clean) { printf("err: report quarantined\n"); skip_bytes(len > 0 ? (size_t)len : 0); return; }

    if (s->appendix == NULL) {
        s->appendix = malloc((size_t)len);
        s->tcap = (size_t)len;
    }
    size_t got = read_exact(s->appendix, (size_t)len);
    s->tlen = got;
    printf("ok: appendix on report %ld updated (%zu bytes)\n", id, got);
}

static void op_revise(void)
{
    long id, offset, bit;
    if (scanf("%ld %ld %ld", &id, &offset, &bit) != 3) { printf("err: bad revise\n"); return; }

    struct Submission *s = resolve(id);
    if (!s) return;
    if (!s->clean) { printf("err: report quarantined\n"); return; }
    if (!s->appendix) { printf("err: no berkas\n"); return; }

    *((unsigned char *)s->appendix + offset) |= (unsigned char)(1 << bit);
    printf("ok: berkas on report %ld annotated\n", id);
}

static void op_view(void)
{
    long id;
    if (scanf("%ld", &id) != 1) { printf("err: bad view\n"); return; }

    struct Submission *s = resolve(id);
    if (!s) return;
    if (!s->active) { printf("report %ld: withdrawn\n", id); return; }
    if (!s->clean) { printf("report %ld: quarantined\n", id); return; }

    printf("report %ld student=%s words=%ld late=%ld draft=%ld\n",
           id, s->student, s->words, s->late, s->draft);
    printf("prose: %.47s\n", s->prose);
    printf("appendix:\n");
    fflush(stdout);
    if (s->appendix) fwrite(s->appendix, 1, 0x80, stdout);
    fputc('\n', stdout);
}

static void op_score(void)
{
    long id;
    if (scanf("%ld", &id) != 1) { printf("err: bad score\n"); return; }

    struct Submission *s = resolve(id);
    if (!s) return;
    long *t = (long *)s;
    printf("telemetry %ld: %ld %ld %ld %ld\n", id, t[0], t[1], t[2], t[3]);
}

static void op_grade(void)
{
    long id;
    if (scanf("%ld", &id) != 1) { printf("err: bad grade\n"); return; }

    struct Submission *s = resolve(id);
    if (!s) return;
    long nilai = s->words - s->late * 10 + s->draft * 5;
    int k = snprintf(g_gradebuf, sizeof g_gradebuf,
                     "nilai report %ld: student=%s nilai=%ld verdict=%s\n",
                     id, s->active ? s->student : "-", nilai,
                     s->clean ? "process" : "hold");
    fwrite(g_gradebuf, 1, (size_t)k, stdout);
}

static void op_retract(void)
{
    long id;
    if (scanf("%ld", &id) != 1) { printf("err: bad retract\n"); return; }

    struct Submission *s = resolve(id);
    if (!s) return;
    free(s->appendix);
    s->active = 0;
    printf("ok: report %ld withdrawn\n", id);
}

static void op_roster(void)
{
    printf("roster:\n");
    for (int i = 0; i < NSUB; i++)
        if (submissions[i].active)
            printf("  %d %s %s\n", i, submissions[i].student,
                   submissions[i].clean ? "clean" : "quarantined");
}

static void banner(void)
{
    printf("== Lapor Mas Keii ==\n");
    printf("perintah: SUBMIT ATTACH REVISE VIEW SCORE GRADE RETRACT ROSTER QUIT\n");
}

static void command_loop(void)
{
    char op[32];
    while (scanf("%31s", op) == 1) {
        if (!strcmp(op, "SUBMIT"))       op_submit();
        else if (!strcmp(op, "ATTACH"))  op_attach();
        else if (!strcmp(op, "REVISE"))  op_revise();
        else if (!strcmp(op, "VIEW"))    op_view();
        else if (!strcmp(op, "SCORE"))   op_score();
        else if (!strcmp(op, "GRADE"))   op_grade();
        else if (!strcmp(op, "RETRACT")) op_retract();
        else if (!strcmp(op, "ROSTER"))  op_roster();
        else if (!strcmp(op, "QUIT"))    break;
        else printf("err: unknown command\n");
        fflush(stdout);
    }
    fflush(NULL);
    exit(0);
}

static void init_state(void)
{
    if (detector_load(GUARD_BIN, GUARD_CONF) != 0) {
        fprintf(stderr, "detector: cannot load %s / %s\n", GUARD_BIN, GUARD_CONF);
        exit(1);
    }
    memset(submissions, 0, sizeof submissions);
    memset(g_gradebuf, 0, sizeof g_gradebuf);

    long *a = (long *)&submissions[-1];
    if ((void *)a != (void *)&g_state.anchor) {
        fprintf(stderr, "layout: telemetry record not where expected\n");
        exit(2);
    }
    a[0] = (long)(void *)op_submit;
    a[1] = (long)(void *)op_view;
    a[2] = (long)(void *)op_attach;
    a[3] = (long)(void *)op_score;
}

static void reap(int sig) { (void)sig; while (waitpid(-1, NULL, WNOHANG) > 0) {} }

int main(int argc, char **argv)
{
    int port = (argc > 1) ? atoi(argv[1]) : 9000;

    init_state();

    signal(SIGCHLD, reap);
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) != 0) { perror("bind"); return 1; }
    if (listen(lfd, 64) != 0) { perror("listen"); return 1; }

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; break; }
        pid_t pid = fork();
        if (pid == 0) {
            close(lfd);
            dup2(cfd, 0);
            dup2(cfd, 1);
            dup2(cfd, 2);
            if (cfd > 2) close(cfd);

            banner();
            fflush(stdout);
            install_seccomp();
            command_loop();
            _exit(0);
        }
        close(cfd);
    }
    close(lfd);
    return 0;
}
