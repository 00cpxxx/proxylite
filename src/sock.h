/* Proxylite - Socket abstraction header
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

#ifndef SOCK_H
#define SOCK_H

int sock_init(void);
int sock_end(void);

enum SOCK_FAMILY
{
    IPV4,
    IPV6,
    ANY
};

enum SOCK_TYPE
{
    TCP_SOCK,
    UDP_SOCK
};

#define INVALID_SOCK -1
/* Enough for IPV4 and IPV6 addresses. */
#define SOCK_ADDR_SZ 32
/* Enough for the largest IPV6 in textual representation. */
#define SOCK_STR_SZ 64

/* Flags for sock_create, sock_connect, sock_accept. */
#define SOCK_NOFLAGS  0
#define SOCK_ASYNC    1
#define SOCK_LISTEN   2

int sock_create(enum SOCK_FAMILY efamily, enum SOCK_TYPE etype,
                char *bind_addr, unsigned short port, unsigned long flags);
int sock_recv(int sock, void *buffer, int sz);
int sock_peek(int sock, void *buffer, int sz);
int sock_send(int sock, void *buffer, int sz);
int sock_connect(void *address, unsigned long flags);
int sock_accept(int listen_sock, void *buffer, unsigned long flags);
void sock_close(int sock);
int sock_connected(int sock);
int sock_pending_data(int sock);
int sock_ntop(void *addr, char *str);

int resolve_name(char *name, void *buffer, unsigned short port, enum SOCK_FAMILY efamily);

int is_local_address(void *addr);
int match_local_address(int sock, void *addr);

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#define CHECK_EINTR (errno == EINTR)
#define CHECK_EBLOCK (errno == EAGAIN || errno == EINPROGRESS)
#define CHECK_BROKEN (errno == ECONNABORTED || errno == ECONNRESET || errno == ECONNREFUSED)
#define get_errno errno
#else
#if !defined(_WIN32_WINNT) || (_WIN32_WINNT < 0x0501)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define FD_SETSIZE 128
#include <windows.h>
#include <ws2tcpip.h>
#define socklen_t int
#define CHECK_EINTR (GetLastError() == WSAEINTR)
#define CHECK_EBLOCK (GetLastError() == WSAEWOULDBLOCK || GetLastError() == WSAEINPROGRESS)
#define CHECK_BROKEN (GetLastError() == WSAECONNABORTED || GetLastError() == WSAECONNRESET)
#define close closesocket
#define get_errno (int) GetLastError()
#define MSG_NOSIGNAL 0
#endif

#endif
