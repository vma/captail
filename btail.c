/* btail.c - tailf for binary files
 *
 * Copyright (c) 2018 - SIP Solutions.
 * Author: Vallimamod Abdullah <vma@sipsolutions.fr>
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EVENT_SIZE sizeof (struct inotify_event)
#define EVENT_BUFLEN 10 * (EVENT_SIZE + NAME_MAX + 1)
#define BUFLEN 512

char *progname, *debug = NULL;

void usage(void) {
    fprintf(stderr, "%s - binary tailf\n\n", progname);
    fprintf(stderr, "usage : %s [ -offset ] [ file ]\n", progname);
    fprintf(stderr, "  offset : output offset bytes from the end of file\n");
    fprintf(stderr, "  file   : binary file to stream, defaults to stdin\n");
    exit(EXIT_FAILURE);
}

void fatal(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "FATAL: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", strerror(errno));
    exit(EXIT_FAILURE);
}

void dbg(const char *fmt, ...) {
    if (debug) {
        va_list ap;
        fprintf(stderr, "DBG: ");
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        if (fmt[strlen(fmt) - 1] != '\n') {
            fprintf(stderr, "\n");
        }
    }
}

void copy_stream(int ifd, int ofd) {
    int nread = 0, nwrote;
    unsigned char rbuf[BUFLEN];

    while ((nread = read(ifd, rbuf, BUFLEN))) {
        if (nread == -1) fatal("read(%d)", ifd);
        dbg("read %d", nread);
        nwrote = write(ofd, rbuf, nread);
        if (nwrote < 0) fatal("write()");
        dbg("wrote %d", nwrote);
    }
    fsync(ofd);
}

int main(int argc, char **argv) {
    off_t offset = 0;
    char *fname = NULL;
    int fd, infd, wd, rv, nread = 0;

    progname = argv[0];
    debug = getenv("DEBUG");
    if (argc > 3 || (argc >= 2 && !strncmp(argv[1], "-h", 2))) {
        usage();
    }

    if (argc == 3) {
        if (argv[1][0] == '-') {
            offset = atol(argv[1]);
        }
        fname = argv[2];
    }

    if (argc == 2) {
        if (argv[1][0] == '-') {
            offset = atol(argv[1]);
        } else {
            fname = argv[1];
        }
    }

    if (fname == NULL) {
        fd = 0;
    } else {
        fd = open(fname, O_RDONLY);
        if (fd < 0) fatal("open() %s", fname);
        infd = inotify_init();
        if (infd < 0) fatal("inotify_init()");
        wd = inotify_add_watch(infd, fname, IN_MODIFY|IN_CLOSE_WRITE);
        if (wd < 0) fatal("inotify_add_watch()");
    }

    dbg("argc=%d offset=%ld fname=%s fd=%d infd=%d", argc, offset, fname, fd, infd);

    if (fd > 0 && offset <= 0) {
        offset = lseek(fd, offset, SEEK_END);
        if (offset < 0) fatal("lseek()");
    }

    copy_stream(fd, 1);

    for (;;) {
        int i = 0;
        ssize_t inr;
        char inbuf[EVENT_BUFLEN];
        struct inotify_event *ev;

        inr = read(infd, inbuf, EVENT_BUFLEN);
        if (inr < 0) fatal("event read()");

        while (i < inr) {
            ev = (struct inotify_event *) &inbuf[i];
            if (ev->mask & IN_MODIFY) {
                dbg("file %s modified", ev->name);
                copy_stream(fd, 1);
            }
            if (ev->mask & IN_CLOSE_WRITE) {
                dbg("file %s closed", ev->name);
                goto end;
            }
            i += EVENT_SIZE + ev->len;
        }
    }

end:
    inotify_rm_watch(infd, wd);
    close(infd);
    close(fd);
    exit(EXIT_SUCCESS);
}
