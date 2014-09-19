/* Proxylite - Socket abstraction
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

#include <string.h>
#include <stdlib.h>

#include "sock.h"

union MULTI_ADDR
{
    struct sockaddr generic;
    struct sockaddr_in f4;
    struct sockaddr_in6 f6;
    char buffer[SOCK_ADDR_SZ];
};

static int sockets_used;

static int sock_nonblock(int sock)
{
#ifndef _WIN32
	int flags;

	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1)
        flags = 0;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
    unsigned long flags;

	flags = 10;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*) &flags, sizeof(flags));
	flags = 1;
	return ioctlsocket(sock, FIONBIO, &flags);
#endif
}

int sock_connected(int sock)
{
    union MULTI_ADDR addr;
    socklen_t addrlen = sizeof(addr);

    return !getpeername(sock, &addr.generic, &addrlen) &&
           ((addr.generic.sa_family == AF_INET && addr.f4.sin_port) ||
            (addr.generic.sa_family == AF_INET6 && addr.f6.sin6_port));
}

int sock_pending_data(int sock)
{
    int avail;

#ifdef _WIN32
    unsigned long long_avail;

    long_avail = 0;
    ioctlsocket(sock, FIONREAD, &long_avail);
    avail = (int) long_avail;
#else
    avail = 0;
    ioctl(sock, FIONREAD, &avail);
#endif
    return avail;
}

int sock_ntop(void *buffer, char *str)
{
    union MULTI_ADDR *addr;
    int res = 0;

    addr = buffer;
    str[0] = '\0';
    if (addr->generic.sa_family == AF_INET)
    {
        char *p;

        /* It's well known that inet_ntoa is deprecated but for the sake of
         * studying we are using it here to show different functions. */
        p = inet_ntoa(addr->f4.sin_addr);
        if (p)
        {
            strcpy(str, p);
            res++;
        }
    }
    else if (addr->generic.sa_family == AF_INET6)
    {
#ifndef _WIN32
    /* inet_ntop does not exist in <= XP. */
        res = !inet_ntop(AF_INET6, &addr->f6.sin6_addr, str, SOCK_STR_SZ);
#else
        strcpy(str, "<Can't represent IPv6>");
#endif // _WIN32
    }
    return res;
}

int sock_accept(int listen_sock, void *buffer, unsigned long flags)
{
    socklen_t addrlen = SOCK_ADDR_SZ;
    int new_sock;

    new_sock = accept(listen_sock, buffer, &addrlen);
    if (new_sock != -1)
    {
        sockets_used++;
        /* Ensure that we never have more sockets than we can use select() on.
         * On Windows the struct fd_set is used with an array and a counter, so
         * we can't have more sockets than the array can fit.
         * On *nix all sockets are used as bits and the highest socket number
         * that can fit is specified as FD_SETSIZE. */
#ifndef _WIN32
        if (new_sock < FD_SETSIZE)
#else
        if (sockets_used < FD_SETSIZE)
#endif
        {
            if (flags & SOCK_ASYNC)
                sock_nonblock(new_sock);
        }
        else
        {
            sock_close(new_sock);
            new_sock = INVALID_SOCK;
        }
    }
    return new_sock;
}

static int recv_helper(int sock, void *buffer, int sz, int flags)
{
    int res;
    do
    {
        res = recv(sock, buffer, sz, MSG_NOSIGNAL | flags);
    }
    while (res == -1 && CHECK_EINTR);
    return res;
}
int sock_recv(int sock, void *buffer, int sz)
{
    return recv_helper(sock, buffer, sz, 0);
}

int sock_peek(int sock, void *buffer, int sz)
{
    return recv_helper(sock, buffer, sz, 0 | MSG_PEEK);
}

int sock_send(int sock, void *buffer, int sz)
{
    int res;
    do
    {
        res = send(sock, buffer, sz, MSG_NOSIGNAL);
    }
    while (res == -1 && CHECK_EINTR);
    return res;
}

void sock_close(int sock)
{
    if (sock != INVALID_SOCK)
    {
        sockets_used--;
        close(sock);
    }
}

int sock_init(void)
{
#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2,2), &wsaData))
		return 0;
#endif
    sockets_used = 0;
    return 1;
}

int sock_end(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
    return sockets_used == 0;
}

int sock_create(enum SOCK_FAMILY efamily, enum SOCK_TYPE etype,
                char *bind_addr, unsigned short port, unsigned long flags)
{
    int new_sock, family, type, proto;

    switch (efamily)
    {
        case IPV4:
            family = AF_INET;
            break;
        case IPV6:
            family = AF_INET6;
            break;
        default:
            return INVALID_SOCK;
    }
    switch (etype)
    {
        case TCP_SOCK:
            type = SOCK_STREAM;
            proto = IPPROTO_TCP;
            break;
        case UDP_SOCK:
            type = SOCK_DGRAM;
            proto = IPPROTO_UDP;
            break;
        default:
            return INVALID_SOCK;
    }

    new_sock = socket(family, type, proto);
    if (new_sock != -1)
    {
        union MULTI_ADDR addr;
        int res;
        socklen_t addrlen;

        sockets_used++;
        if (family == AF_INET)
        {
            if (bind_addr)
                addr.f4.sin_addr.s_addr = inet_addr(bind_addr);
            else
                addr.f4.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.f4.sin_family = family;
            addr.f4.sin_port = htons(port);
            memset(&addr.f4.sin_zero, 0x00, sizeof(addr.f4.sin_zero));
            addrlen = sizeof(addr.f4);
        }
        else
        {
#ifndef _WIN32
            if (bind_addr)
                inet_pton(AF_INET6, bind_addr, &addr.f6.sin6_addr);
            else
                addr.f6.sin6_addr = in6addr_any;
#else
            /* inet_pton is not supported in Windows <= XP */
            addr.f6.sin6_addr = in6addr_any;
#endif
            addr.f6.sin6_family = family;
            addr.f6.sin6_port = htons(port);
            addr.f6.sin6_flowinfo = 0;
            addr.f6.sin6_scope_id = 0;
            addrlen = sizeof(addr.f6);
        }
        if (flags & SOCK_ASYNC)
            sock_nonblock(new_sock);

        res = bind(new_sock, &addr.generic, addrlen);
        if (!res && (flags & SOCK_LISTEN))
            res = listen(new_sock, SOMAXCONN);

        if (res)
        {
            sock_close(new_sock);
            new_sock = INVALID_SOCK;
        }
    }
    return new_sock;
}

int sock_connect(void *buffer, unsigned long flags)
{
    union MULTI_ADDR *addr;
    int new_sock;

    addr = buffer;
    new_sock = socket(addr->generic.sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (new_sock != -1)
    {
        int addrlen, res;
        sockets_used++;

        if (flags & SOCK_ASYNC)
            sock_nonblock(new_sock);

        if (addr->generic.sa_family == AF_INET)
            addrlen = sizeof(addr->f4);
        else
            addrlen = sizeof(addr->f6);

        /* Zero means instant connect or -1 and correct errno means connecting. */
        res = connect(new_sock, &addr->generic, addrlen);
        if (res == -1 && !CHECK_EBLOCK)
        {
            sock_close(new_sock);
            new_sock = INVALID_SOCK;
        }
    }
    return new_sock;
}

int resolve_name(char *name, void *buffer, unsigned short port)
{
    struct addrinfo *info;
    union MULTI_ADDR *addr;
    int res;

    addr = buffer;
    res = getaddrinfo(name, NULL, NULL, &info);
    if (res)
        return 0;

    res = 1;
    memcpy(addr, info->ai_addr, info->ai_addrlen);
    if (addr->generic.sa_family == AF_INET)
        addr->f4.sin_port = htons(port);
    else if (addr->generic.sa_family == AF_INET6)
        addr->f6.sin6_port = htons(port);
    else
        res = -1;
    freeaddrinfo(info);
    return res;
}

int is_local_address(void *buffer)
{
    union MULTI_ADDR *addr;
    int res;

    addr = buffer;
    /* There is a single localhost address for IPV6, for
     * IPV4 any 127.x.x.x is considered localhost. */
    if (addr->generic.sa_family == AF_INET)
        res = !!((ntohl(addr->f4.sin_addr.s_addr) & 0x7F000000) == 0x7F000000);
    else
        res = IN6_IS_ADDR_LOOPBACK(&addr->f6.sin6_addr);
    return res;
}

int match_local_address(int sock, void *buffer)
{
    union MULTI_ADDR *addr, local;
    socklen_t addrlen;
    int res;

    addrlen = sizeof(local);
    if(getsockname(sock, &local.generic, &addrlen))
        return 0;
    addr = buffer;

    if (local.generic.sa_family != local.generic.sa_family)
        return 0;

    if (local.generic.sa_family == AF_INET)
        res = !memcmp(&addr->f4, &local.f4, addrlen);
    else
        res = !memcmp(&addr->f6, &local.f6, addrlen);

    return res;
}
