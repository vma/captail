/* test_inotify.c - example inotify use.
 *
 * Copyright (c) 2018 - SIP Solutions.
 * Author: Vallimamod Abdullah <vma@sipsolutions.fr>
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#define EVENT_SIZE sizeof (struct inotify_event)
#define BUFLEN 10 * (EVENT_SIZE + NAME_MAX + 1)

char *debug = NULL;

void dbg(const char *fmt, ...) {
    if (debug) {
        va_list ap;
        fprintf(stderr, ">> DBG: ");
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        if (fmt[strlen(fmt) - 1] != '\n') {
            fprintf(stderr, "\n");
        }
    }
}

int main(int argc, char **argv) {
    int fd, wd;
    ssize_t nr;
    char buf[BUFLEN];
    char *p;
    struct inotify_event *ev;

    if (argc != 2) {
        fprintf(stderr, "usage: %s file\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    debug = getenv("DEBUG");

    fd = inotify_init();
    if (fd == -1) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }
    wd = inotify_add_watch(fd, argv[1], IN_MODIFY);
    if (wd == -1) {
        perror("inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        int i = 0;

        nr = read(fd, buf, BUFLEN);
        if (nr < 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        while (i < nr) {
            dbg("i=%d / nr = %d", i, nr);
            ev = (struct inotify_event *) &buf[i];
            if (ev->mask & IN_MODIFY) {
                dbg("file %s was modified", ev->name);
            }
            i += EVENT_SIZE + ev->len;
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    exit(EXIT_SUCCESS);
}
