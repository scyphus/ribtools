/*_
 * Copyright 2009 WIDE Project. All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <panda@hongo.wide.ad.jp>
 */

/* $Id: extract-rib.c,v 0d6e5d383a92 2010/08/27 04:28:27 Hirochika $ */

#include "mrt.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Main
 */
int
main(int argc, const char *const argv[], const char *const envp[])
{
    unsigned char hbuf[12];
    int p;
    size_t nread;
    struct mrt_header header;
    unsigned char *body;

    /* 0-11:: header: time, type, subtype, packet length */
    /* 12-(packet length):: body */

    p = -1;
    for ( ;; ) {
        if ( feof(stdin) ) {
            break;
        }

        /* Read MRT header */
        nread = fread(hbuf, sizeof(char), sizeof(hbuf), stdin);
        /* Complete header? */
        if ( nread == 0 && feof(stdin) ) {
            /* End-of-file */
            break;
        } else if ( nread != 12 ) {
            /* Incomplete header */
            fputs("Incomplete header\n", stderr);
            exit(EXIT_FAILURE);
        }
        header = parse_mrt_header(hbuf);

        /* Read MRT message */
        body = malloc(header.message_length);
        if ( NULL == body ) {
            fputs("malloc(): Memory error\n.", stderr);
            exit(-1);
        }
        nread = fread(body, sizeof(char), header.message_length, stdin);
        if ( nread != header.message_length ) {
            /* Incomplete message */
            fputs("Incomplete message", stderr);
            exit(EXIT_FAILURE);
        }
        (void)parse_mrt_message(&header, body, nread);
        free(body);
    }

    return 0;
}


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
