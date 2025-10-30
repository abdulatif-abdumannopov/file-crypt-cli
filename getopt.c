#include "getopt.h"
#include <stdio.h>
#include <string.h>

char *optarg;
int optind = 1, opterr = 1, optopt;

int getopt(int argc, char * const argv[], const char *optstring) {
    static int sp = 1;
    char *cp;

    if (sp == 1) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }

    optopt = argv[optind][sp];
    cp = strchr(optstring, optopt);

    if (!cp) {
        if (opterr && *optstring != ':')
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], optopt);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }

    if (cp[1] == ':') {
        if (argv[optind][sp + 1] != '\0')
            optarg = &argv[optind++][sp + 1];
        else if (++optind >= argc) {
            if (*optstring == ':') return ':';
            if (opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], optopt);
            sp = 1;
            return '?';
        } else
            optarg = argv[optind++];
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return optopt;
}

