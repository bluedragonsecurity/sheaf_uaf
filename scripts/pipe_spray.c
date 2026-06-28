#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/resource.h>
#define MAX_PIPES 8192
static int  fds[MAX_PIPES][2];
static char alive[MAX_PIPES];
static int  count = 0;
static volatile sig_atomic_t stop_flag = 0;
static void on_sigint(int s) { (void)s; stop_flag = 1; }

static void raise_nofile(void) {
    struct rlimit rl;
    
    rl.rlim_cur = rl.rlim_max = MAX_PIPES * 2 + 64;
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) 
        perror("setrlimit");
}

static void close_all(void) {
    for (int i = 0; i < count; i++) {
        if (alive[i]) { 
            close(fds[i][0]); 
            close(fds[i][1]); 
            alive[i] = 0; 
        }
    }
    count = 0;
}

/* alloc N pipes; optionally F_SETPIPE_SZ to control pipe_buffer array tier */
static int alloc_burst(int n, int pages) {
    int ok = 0;

    for (int i = 0; i < n && count < MAX_PIPES; i++) {
        if (pipe(fds[count]) < 0) {
            if (errno == EMFILE || errno == ENFILE) break;
            perror("pipe"); break;
        }
        if (pages > 0) {
            (void)fcntl(fds[count][1], F_SETPIPE_SZ, pages * 4096);
        }
        alive[count] = 1;
        count++; ok++;
    }

    return ok;
}

/* free N pipes from top (LIFO) -> push to pcs->main->objects[size++] */
static int free_burst(int n) {
    int ok = 0, j = 0;

    for (int i = count - 1; i >= 0 && ok < n; i--) {
        if (alive[i]) {
            close(fds[i][0]); close(fds[i][1]);
            alive[i] = 0; ok++;
        }
    }
    for (int i = 0; i < count; i++) {
        if (alive[i]) {
            if (i != j) { 
                fds[j][0] = fds[i][0]; 
                fds[j][1] = fds[i][1]; 
                alive[j] = 1; 
                alive[i] = 0; 
            }
            j++;
        }
    }
    count = j;

    return ok;
}

static void usage(const char *p) {
    fprintf(stderr,
        "usage: %s [-a alloc_burst] [-f free_burst] [-d delay_us] [-p pipe_pages]\n"
        "  default: -a 16 -f 16 -d 500000 -p 0 (= 16 pages default -> kmalloc-cg-1024)\n"
        "  -p 2  -> 80 B  -> kmalloc-cg-96  (cap=60)\n"
        "  -p 4  -> 160 B -> kmalloc-cg-192 (cap=60)\n"
        "  -p 16 -> 640 B -> kmalloc-cg-1024 (cap=12)\n"
        "  -p 32 -> 1280B -> kmalloc-cg-2048 (cap=12)\n"
        "  -p 64 -> 2560B -> kmalloc-cg-4096 (cap=4)\n", p);
}

int main(int argc, char **argv) {
    int alloc_n = 16, free_n = 16, delay_us = 500000, pages = 0;
    int opt;
    int phase = 0;

    while ((opt = getopt(argc, argv, "a:f:d:p:h")) != -1) {
        switch (opt) {
            case 'a': alloc_n  = atoi(optarg); break;
            case 'f': free_n   = atoi(optarg); break;
            case 'd': delay_us = atoi(optarg); break;
            case 'p': pages    = atoi(optarg); break;
            default : usage(argv[0]); return 1;
        }
    }
    signal(SIGINT, on_sigint);
    raise_nofile();
    fprintf(stderr,
        "[dragon-spray] pid=%d  alloc=%d free=%d delay=%dus pages=%d\n"
        "[dragon-spray] target: pipe_buffer arrays via kcalloc(pipe_bufs, 40, GFP_KERNEL_ACCOUNT)\n",
        getpid(), alloc_n, free_n, delay_us, pages);
    alloc_burst(64, pages);
    fprintf(stderr, "[dragon-spray] warmup: count=%d\n", count);
    while (!stop_flag) {
        time_t now = time(NULL);
        if (phase == 0) {
            int a = alloc_burst(alloc_n, pages);
            fprintf(stderr, "[%ld] ALLOC b=%d total=%d  (drain pcs->main LIFO top, then miss->barn/slab)\n",
                    now, a, count);
            phase = 1;
        } else {
            int f = free_burst(free_n);
            fprintf(stderr, "[%ld] FREE  b=%d total=%d  (push pcs->main objects[size++], overflow->barn)\n",
                    now, f, count);
            phase = 0;
        }
        usleep(delay_us);
    }
    fprintf(stderr, "\n[dragon-spray] cleanup, closing %d pipes\n", count);
    close_all();

    return 0;
}