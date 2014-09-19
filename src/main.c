/* Proxylite - Main
 *
 * Copyright (C) 2014 Bruno Jesus
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA */

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "sock.h"
#include "connection.h"

#define APP_VERSION "0.2"

void sigproc(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
        stop_proxy();
}

void print_help(char *name)
{
    char *p;

    p = name + strlen(name);
    while(p != name && *p != '\\' && *p != '/') p--;
    if (p != name)
        name = p + 1;
    printf("Proxylite %s - Simple, no threads, non-caching proxy server\n"
           "   Usage: %s [OPTIONS]\n\n"
           "   -h|--help    Show this help and quit\n"
           "   -f|--fork    Run in background (does not work in Windows)\n"
           "   -d|--debug   Print some debug messages while running\n"
           "   -4|--ipv4    Prefer IPV4 while resolving names\n"
           "   -6|--ipv6    Prefer IPV6 while resolving names\n"
           "   -p4 <port>   Port to bind the IPV4 socket\n"
           "   -p6 <port>   Port to bind the IPV6 socket\n"
           "   -b4 <ipv4>   Local IP to bind the IPV4 socket\n"
           "   -b6 <ipv6>   Local IP to bind the IPV6 socket\n\n"
           "    --test <name> <port> Do 100 connections to the specified proxy\n"
           "                         and request the '/' URI from 5 well known\n"
           "                         sites, quit after the test.\n"
           "   --ltest <name> <port> Same as previous but connects to 127.0.0.1:80\n"
           "\nIf -b4|-b6 is not set they will bind to all available addresses.\n"
           "To disable IPV4 don't set -p4 or set to 0 (zero), same for IPV6.\n"
           "If -4 and -6 are used as argument the last used will be preferred.\n"
           "Using -f|--fork disables -d|--debug\n\n"
           ,APP_VERSION, name);
    exit(2);
}

int main(int argc, char *argv[])
{
    int ret = 0, debug = 0, port_v4 = 0, port_v6 = 0;
    char *bind_v4 = NULL, *bind_v6 = NULL, *name = *argv;
    enum SOCK_FAMILY preferred_family = ANY;

    signal(SIGINT, sigproc);
    signal(SIGTERM, sigproc);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    if (!getuid() || !geteuid())
    {
        printf("This program cannot be run as root.\n");
        exit(3);
    }
#endif

    if (argc > 1)
    {
        while (--argc)
        {
            argv++;
            if (!strcmp(*argv, "--debug") || !strcmp(*argv, "-d"))
                debug++;
            else if (!strcmp(*argv, "--fork") || !strcmp(*argv, "-f"))
                ret = 1;
            else if (!strcmp(*argv, "--help") || !strcmp(*argv, "-h"))
                print_help(name);
            else if (!strcmp(*argv, "--ipv4") || !strcmp(*argv, "-4"))
                preferred_family = IPV4;
            else if (!strcmp(*argv, "--ipv6") || !strcmp(*argv, "-6"))
                preferred_family = IPV6;
            else if (!strcmp(*argv, "-p4") && argc > 1)
            {
                port_v4 = atoi(*(++argv));
                argc--;
            }
            else if(!strcmp(*argv, "--test") && argc > 2)
            {
                multi_test(1, argv[1], (unsigned short) atoi(argv[2]));
                exit(0);
            }
            else if(!strcmp(*argv, "--ltest") && argc > 2)
            {
                multi_test(0, argv[1], (unsigned short) atoi(argv[2]));
                exit(0);
            }
            else if (!strcmp(*argv, "-p6") && argc > 1)
            {
                port_v6 = atoi(*(++argv));
                argc--;
            }
            else if (!strcmp(*argv, "-b4") && argc > 1)
            {
                bind_v4 = *(++argv);
                argc--;
            }
            else if (!strcmp(*argv, "-b6") && argc > 1)
            {
                bind_v6 = *(++argv);
                argc--;
            }
        }
    }
    else
        print_help(argv[0]);

    if (ret)
    {
#ifndef _WIN32
        ret = fork();
        debug = 0;
        if (ret)
            exit (ret > 0 ? 0 : 1);
#else
        printf("Forking to background is not supported in Windows.\n");
#endif
    }

    ret = 1;
    if (debug)
        printf("IPV4 - %s:%d\tIPV6 - [%s]:%d\n",
               bind_v4 ? bind_v4 : "0.0.0.0", port_v4,
               bind_v6 ? bind_v6 : "::", port_v6);
    if (start_proxy(bind_v4, (unsigned short) port_v4,
                    bind_v6, (unsigned short) port_v6,
                    preferred_family, debug) > 0)
    {
        app_loop();
        ret = 0;
    }
    end_proxy();
    return ret;
}
