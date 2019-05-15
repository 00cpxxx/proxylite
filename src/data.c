/* Proxylite - Application core
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#ifndef _WIN32
#include <unistd.h>
#define os_sleep(x) usleep((x) * 1000)
#define min(x, y) (((x) > (y)) ? y : x)
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define os_sleep Sleep
#endif

#include "sock.h"
#include "connection.h"

/* What to send as reply to CONNECT requests, the Connection
 * close may be superfluous but it does not hurt. */
#define DEFAULT_TUNNEL_RESPONSE "HTTP/1.1 200 Connection established\r\n" \
                                "Connection: close\r\n\r\n"
#define DEFAULT_TUNNEL_RESPONSE_SZ (sizeof(DEFAULT_TUNNEL_RESPONSE) - 1)

#define HTTP_PREFIX "http://"
#define HTTP_PREFIX_SZ (sizeof(HTTP_PREFIX) - 1)
#define HTTP_HOST_HEADER "Host: "
#define HTTP_HOST_SZ (sizeof(HTTP_HOST_HEADER) - 1)

/* Max cache to store before stalling the connection (stop recv() to
 * disable TCP window size), the amounte of memory allocated will be
 * slightly above this value. */
#define HARD_BUFFER_LIMIT (512 * 1024)
/* Max send/recv per time. */
#define MAX_BUFFER_SZ 128 * 1024
/* A host name can have up to 255 bytes as per the standard. */
#define MAX_HOST_NAME 255
/* Timeout in seconds of silence between any side. */
#define MAX_TIMEOUT_BRIDGE 60
/* Timeout in seconds to wait for the full client header. */
#define MAX_TIMEOUT_HEADER 10
/* Default HTTP port. */
#define DEFAULT_HTTP_PORT  80

static struct CONFIG
{
    int master_sock[2], connections, unique_id;
    struct CONNECTION *head;
    int running, debug;
    unsigned long global_sent, global_recv;
    unsigned short port_v4, port_v6;
    enum SOCK_FAMILY preferred_family;
} cfg;

/* Return codes for the name resolve functions. Defines are used just to show
 * different ways to achieve the same thing. Do you know the advantages of enum? */
#define INVALID_REQUEST   -1
#define INVALID_METHOD    -2
#define INVALID_NO_HOST   -3
#define INVALID_PORT      -4
#define INVALID_HOST_SIZE -5
#define INVALID_RESOLVE   -6
#define STATUS_OK          1

enum CONN_STATE
{
    /* The client connection was just received, here we wait for the HTTP header. */
    ST_CLIENT_CONNECTED,
    /* We have the header, find the host we need to connect and resolve its name. */
    ST_FIND_HOST,
    /* Start the connection to the server or if we are already connected skip this step. */
    ST_CONNECT_SERVER,
    /* Wait for the connection to be established. */
    ST_WAIT_CONNECTION,
    /* Send data from server to client and vice-versa. */
    ST_BRIDGE,
    /* Cleanup the memory and sockets for this connection. */
    ST_CLEAR
    /* All states have a general timeout check. */
};

enum HTTP_ERROR
{
    /* Mal-formed HTTP request. */
    BAD_REQUEST = 0,
    /* Client tried to make we connect in our own proxy. */
    FORBIDDEN,
    /* Name resolution failed. */
    RESOLVE_FAILED,
    /* Attempt to connect to server failed. */
    CONNECT_FAILED,
    /* Timeout waiting for reply from server. */
    GATEWAY_TIMEOUT,
    /* The server is going down, just tell the users. */
    PROXY_DOWN,
    /* All is fine. */
    ERROR_FREE
};

/* Buffer memory pointer, current read position, current filled
 * position and max allocated memory for now. */
struct DATA_BUFFER
{
    unsigned char *buffer;
    int pos, used, max;
};

/* This is the connection object, every connection has one of this. */
struct CONNECTION
{
    enum CONN_STATE state;
    enum HTTP_ERROR error;
    time_t last_operation;
    int request_end, requests, reuses, unique_id, tunnel, header_sz;

    struct SOCKET
    {
        int sock, writable;
        time_t connection;
        struct DATA_BUFFER data;
        unsigned char addr[SOCK_ADDR_SZ];
    } client, server;

    struct CONNECTION *next, *prev;
};

/* Different levels of log verbosity. The log is mostly for development only. */
#define dprintf1 if(cfg.debug >= 1) printf
#define dprintf2 if(cfg.debug >= 2) printf
#define dprintf3 if(cfg.debug >= 3) printf

int send_http_error(int sock, enum HTTP_ERROR error)
{
    char buffer[512]; /* Enough for all cases below. */
    static const char *reasons[] = {
        "Bad HTTP Request.",
        "Invalid loop attempt detected.",
        "Name resolution failed.",
        "Connection to server failed.",
        "Timeout waiting for server reply.",
        "The proxy server is going down.",
    };
    static const int code[] = {400, 403, 500, 502, 504, 503};
    int sz, data_sz, res;

    /* The magic number below is the size of the error message including the error code. */
    data_sz = 134 + strlen(reasons[error]);

    /* We don't really care about what HTTP version the client used, to simplify
     * the error messages we will always reply with HTTP/1.1. Apache does the same. */
    sz = sprintf(buffer,
        "HTTP/1.1 %d Error\r\n"
        "Content-length: %d\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
        "<html><head>"
        "<title>proxylite Error - %d</title>"
        "</head><body>"
        "<h2>%s</h2>"
        "</body></html>",
        code[error], data_sz, code[error], reasons[error]);

    res = sock_send(sock, buffer, sz);
    if (res > 0)
        cfg.global_sent += res;
    return res == sz;
}

void skip_data(struct DATA_BUFFER *data, int skip_sz)
{
    int remaining;

    remaining = data->used - data->pos;
    if (skip_sz > remaining)
        skip_sz = remaining;
    data->pos += skip_sz;
}

int append_data(struct DATA_BUFFER *data, unsigned char *lbuffer, int sz)
{
    if (!data->buffer || (sz + data->used > data->max))
    {
        void *new_buffer;
        int new_size;

        /* Plus 16 just to ensure there is always space for a NULL byte */
        new_size = data->max ? data->max + data->max / 2 : MAX_BUFFER_SZ * 2;
        new_buffer = realloc(data->buffer, new_size + 16);
        if (!new_buffer)
            return -3;
        data->buffer = new_buffer;
        data->max = new_size;
    }

    memcpy(data->buffer + data->used, lbuffer, sz);
    data->used += sz;
    dprintf2("Appended %d to %d/%d bytes.\n", sz, data->used, data->max);
    return sz;
}

/* This function returns the amount of data sent. If it returns -1
 * it means try later. If this is the first socket send the return 0
 * means the connection was reseted/aborted. */
int send_buffer(int target_sock, struct DATA_BUFFER *data)
{
    int res = 0, remaining;

    remaining = data->used - data->pos;
    if (remaining)
    {
        int send_sz;

        send_sz = min(MAX_BUFFER_SZ, remaining);
        res = sock_send(target_sock, data->buffer + data->pos, send_sz);
        if (res > 0)
        {
            cfg.global_sent += res;
            data->pos += res;
            if (data->pos == data->used)
                data->pos = data->used = 0;
            dprintf2("Buffer sent %d/%d bytes, remaining %d bytes.\n",
                     res, send_sz, data->used - data->pos);
        }
        else
            dprintf3("Can't send %d bytes, errno %d\n",
                     send_sz, get_errno);
        /* If we can't send there is no problem, we will try again later. */
    }
    return res;
}

int recv_buffer(int source_sock, struct DATA_BUFFER *data, int relay_sock)
{
    unsigned char lbuffer[MAX_BUFFER_SZ], *p = lbuffer;
    int res, res2 = 0;

    /* If the other side buffer is full don't read more data from this side.
     * This means that the other side is not draining the data as fast as this
     * side is receiving it. */
    if (data->used >= HARD_BUFFER_LIMIT)
    {
        /* Since we can't receive try at least sending some more buffer. */
        if (relay_sock != INVALID_SOCK)
            send_buffer(relay_sock, data);
        return -2;
    }

    res = sock_recv(source_sock, p, sizeof(lbuffer));
    if (res > 0)
    {
        cfg.global_recv += res;
        /* If there is no data in the buffer send it directly to other side.
         * If there is data in the buffer we have to queue the data to avoid
         * sending things out of order. */
        if (relay_sock != INVALID_SOCK)
        {
            send_buffer(relay_sock, data);
            if (data->used == data->pos)
            {
                res2 = sock_send(relay_sock, p, res);
                if (res2 > 0)
                {
                    cfg.global_sent += res2;
                    dprintf2("Bridged %d/%d bytes.\n", res2, res);
                    res -= res2;
                    p += res2;
                }
            }
        }

        /* Is there any data that was not relayed? This means that send()
         * returned error or less than what we asked it to send. */
        if (res)
        {
            res = append_data(data, p, res);
            /* If we can't append the data abort the connection! */
            if (res < 0)
                res2 = 0;
        }
    }
    else if (res < 0)
    {
        /* Is this a fatal error? */
        if (CHECK_BROKEN)
            res = 0;
        dprintf2("recv() error %d.\n", get_errno);
    }
    return res + res2;
}

void clear_connection(struct CONNECTION *conn)
{
    sock_close(conn->client.sock);
    sock_close(conn->server.sock);

    if (conn->server.data.buffer)
        free(conn->server.data.buffer);
    if (conn->client.data.buffer)
        free(conn->client.data.buffer);
    cfg.connections--;
    dprintf1("#%d Clear connection (requests : %d, reuses : %d, total : %d).\n",
             conn->unique_id, conn->requests, conn->reuses, cfg.connections);
}

struct CONNECTION* new_connection(int listen_sock)
{
    struct CONNECTION *conn = NULL;
    int new_sock;
    char addr[SOCK_ADDR_SZ];

    new_sock = sock_accept(listen_sock, addr, SOCK_ASYNC);
    if (new_sock != INVALID_SOCK)
    {
        conn = calloc(1, sizeof(*conn));
        if (conn)
        {
            char str[SOCK_STR_SZ];

            conn->client.sock = new_sock;
            memcpy(conn->client.addr, addr, sizeof(addr));
            conn->state = ST_CLIENT_CONNECTED;
            conn->server.sock = INVALID_SOCK;
            conn->unique_id = cfg.unique_id++;
            conn->error = ERROR_FREE;
            conn->client.writable = 1;
            /* Very lame approach to reset the ID. */
            if (cfg.unique_id > 100000)
                cfg.unique_id = 0;
            sock_ntop(addr, str);
            cfg.connections++;
            dprintf1("#%d New connection from '%s' (total : %d).\n",
                     conn->unique_id, str, cfg.connections);
        }
        else
            sock_close(new_sock);
    }
    return conn;
}

/* Returns the header size */
int full_header(char *header, int sz)
{
    char *p;

    header[sz] = '\0';
    /* HTTP spec states that the header ends in double empty line */
    p = strstr(header, "\r\n\r\n");
    return p != NULL ? (p - header) + 4 : 0;
}

/* Returns the size of the verb or zero if invalid */
int valid_verb(char *verb)
{
    /* Most common operations order in my opinion. */
    static const char *valid[] = {"GET", "POST", "CONNECT", "HEAD", "PUT", "DELETE", "OPTIONS"};
    static const int sizes[] = {3, 4, 7, 4, 3, 6, 7, 0};
    int i;

    for (i = 0; sizes[i]; i++)
    {
        if (!strcmp(verb, valid[i]))
            break;
    }
    return sizes[i];
}

int extract_host(char *header, char *verb, char *host, unsigned short *port, int *discarded)
{
    char *p, *p2, *eol, *after_uri, *uri_start, *file_start,
         *after_host, *port_ptr, *host_ptr;
    int sz, prefixed, sz_verb;

    *discarded = prefixed = 0;
    *port = DEFAULT_HTTP_PORT;

    eol = strchr(header, '\r');
    if (!eol) /* Insanity check. */
        return INVALID_REQUEST;
    *eol = '\0';

    /* A request is in the form: METHOD URI HTTP_VERSION\r\n. The first thing
     * to do is jumping the METHOD, and then the URI. Note that we are changing
     * the user buffer in the process but this is not problem, if any invalid
     * result is returned the connection will be closed and all data discarded. */
    p = strchr(header, ' ');
    if (!p)
        return INVALID_REQUEST;

    /* Since the end of line is '\0' we will ensure this second space is found
     * in the same line. */
    after_uri = strchr(p + 1, ' ');
    if (!after_uri)
        return INVALID_REQUEST;
    *eol = '\r';
    *after_uri = '\0';

    *p = '\0';
    sz_verb = valid_verb(header);
    if (!sz_verb)
        return INVALID_METHOD;
    strcpy(verb, header);
    *p = ' ';

    /* Try to find the host and port from the URI argument. If not possible
     * then we will look for the Host header. We don't don't really care that
     * Host will only be present in HTTP/1.1. */
    uri_start = ++p;
    host_ptr = strstr(eol, HTTP_HOST_HEADER);

    /* A CONNECT request will always have the host name as URI. */
    if(!strcmp(verb, "CONNECT"))
    {
        after_host = after_uri;
    }
    /* If the URI is prefixed with http:// we need to skip it and change the header. */
    else if (!memcmp(p, HTTP_PREFIX, HTTP_PREFIX_SZ))
    {
        p += HTTP_PREFIX_SZ;
        after_host = strchr(p, '/');
        if (!after_host)
            after_host = after_uri;
        prefixed++;
    }
    else
    {
        /* Not good, do we have a Host header? */
        if (host_ptr)
        {
            p = host_ptr + HTTP_HOST_SZ;
            after_host = strchr(p, '\r');
        }
        else
        {
            /* The URI is not prefixed with http:// and we don't have
             * the Host header, in this case the URI must be a host name. */
             after_host = after_uri;
        }
    }
    if (!after_host)
        return INVALID_REQUEST;
    file_start = after_host;

    port_ptr = NULL;
    /* An IPV6 request must have the form [IPV6] as stated in the HTTP RFC. */
    if (*p == '[')
    {
        p2 = strchr(p, ']');
        if (!p2)
            return INVALID_REQUEST;
        p2++;
        if (*p2 == ':')
            port_ptr = p2 + 1;
    }
    else
    {
        p2 = strchr(p, ':');
        if (p2)
            port_ptr = p2 + 1;
    }
    if (port_ptr)
    {
        /* The port number can be in the URI or in the Host header.
         * Ensure we don't find the : in the wrong part of the URI. */
        if ((!host_ptr && port_ptr < eol) || (host_ptr && port_ptr < after_host))
        {
            int int_port;

            int_port = atoi(port_ptr);
            if (int_port < 1 || int_port > 65535)
                return INVALID_PORT;
            *port = (unsigned short) int_port;
            after_host = port_ptr - 1;
        }
    }

    sz = after_host - p;
    if (sz > MAX_HOST_NAME)
        return INVALID_HOST_SIZE;

    /* If this is an IPV6 skip the [] */
    if (*p == '[')
    {
        p++;
        sz -= 2;
    }

    memcpy(host, p, sz);
    host[sz] = '\0';
    *after_uri = ' ';

    /* Do we need to strip the http://hostname from the URI?
     * Yes if there is a Host header and the URI started with http://. */
    if (prefixed && host_ptr)
    {
        /* What we are doing here is move the METHOD to the exact
         * position before the '/' in the URI and then adding a
         * blank space. Faster than recoding the whole header just
         * to change the first line. */
        *discarded = file_start - uri_start;
        memcpy(header + *discarded, verb, sz_verb);
        header[*discarded + sz_verb] = ' ';
    }
    return STATUS_OK;
}

int resolve_address(char *host, unsigned short port, void *buffer)
{
    char str[SOCK_STR_SZ];
    int res;

    dprintf1("... ");
    res = resolve_name(host, buffer, port, cfg.preferred_family);
    if (res <= 0)
    {
        dprintf1("Resolve '%s' failed with error %d.\n", host, res);
        return INVALID_RESOLVE;
    }

    sock_ntop(buffer, str);
    dprintf1("Host '%s:%d' resolved to '%s'.\n", host, port, str);
    return STATUS_OK;
}

#define FD_SETS_RE(x) {                     \
                        FD_SET(x, &set[0]); \
                        FD_SET(x, &set[2]); \
                      }
#define FD_ADD_POLL(x, y) {                 \
                            FD_SET(x, y);   \
                            if (x > maxsd)  \
                                maxsd = x;  \
                          }
void app_loop(void)
{
    time_t now, current;
    int loops_per_sec;

    cfg.running = 1;
    loops_per_sec = 0;
    now = time(NULL);
    while (cfg.running)
    {
        struct CONNECTION *p, *new, *n;
        struct timeval timeout;
        fd_set set[3];
        int maxsd, res, changes, fast_select;
        unsigned int i; /* Has to be unsigned to avoid warning due to sizeof. */

        FD_ZERO(&set[0]);
        FD_ZERO(&set[1]);
        FD_ZERO(&set[2]);

        maxsd = cfg.master_sock[0] > cfg.master_sock[1] ? cfg.master_sock[0] : cfg.master_sock[1];
        if (cfg.master_sock[0] != INVALID_SOCK)
            FD_SETS_RE(cfg.master_sock[0]);
        if (cfg.master_sock[1] != INVALID_SOCK)
            FD_SETS_RE(cfg.master_sock[1]);

        /* We will use this in a lot of places and even if the loop takes
         * over one second to run there is no problem, our timeouts don't
         * need to be very strict. */
        current = time(NULL);
        if (current != now)
        {
            i = current - now;
            dprintf1("Loops %d - Spent %u second(s) - Sent %lu Kb/s, Recv %lu Kb/s\n",
                     loops_per_sec, i, cfg.global_sent / (1024 * i), cfg.global_recv / (1024 * i));
            cfg.global_sent = cfg.global_recv = 0;
            now = current;
            loops_per_sec = 0;
        }
        loops_per_sec++;

        for (fast_select = 0, p = cfg.head; p; p = n)
        {
            n = p->next; /* (p) may be freed, ensure we have the next pointer. */
            if (p->state == ST_CLEAR)
            {
                if (p->error != ERROR_FREE)
                    send_http_error(p->client.sock, p->error);

                clear_connection(p);

                /* Remove the connection from the double linked list. */
                if (p->next)
                    p->next->prev = p->prev;
                if (p->prev)
                    p->prev->next = p->next;
                if (!p->next && !p->prev)
                    cfg.head = NULL;
                else if (p == cfg.head)
                    cfg.head = p->next;

                free(p);
                continue;
            }

            /* This is a state machine on purpose, don't remove the ELSEs or
             * the server will behave poorly because it will spend too much
             * time when a client first connects. */
            if (p->state == ST_BRIDGE)
            {
                /* If this is not a tunnel and the client started sending data again
                 * after the previous request was replied it means this is a new
                 * request. Reset the state and start over. */
                if (!p->tunnel && p->request_end && p->client.data.used)
                {
                    fast_select++; /* We need to get to the next state fast! */
                    p->state = ST_CLIENT_CONNECTED;
                    p->request_end = p->header_sz = 0;
                    /* Reset the connection marker for the header waiting timeout. */
                    p->client.connection = now;
                }
                else
                {
                    if (p->client.writable)
                    {
                        /* Send any buffered data to client. */
                        res = send_buffer(p->client.sock, &p->server.data);
                        if (res > 0)
                            fast_select++;
                        /* If we can't send the data we will wait for select() write signal. */
                        else if (res < 0)
                            p->client.writable = 0;
                    }

                    if (p->server.sock != INVALID_SOCK)
                    {
                        /* Only forward buffer data before the request is over or this
                         * is a tunnel (look for RELAY_COMMENT in the code). */
                        if (p->tunnel || !p->request_end)
                        {
                            if (p->server.writable)
                            {
                                res = send_buffer(p->server.sock, &p->client.data);
                                if (res > 0)
                                    fast_select++;
                                /* If we can't send the data we will wait for select() write signal. */
                                else if (res < 0)
                                    p->server.writable = 0;
                            }
                        }
                    }
                    else if (!p->server.data.used)
                    {
                        /* If the server socket is closed and all buffered data has
                         * been sent to the client we can close this connection. */
                        p->state = ST_CLEAR;
                        dprintf1("#%d Whole buffer sent, closing...\n", p->unique_id);
                    }
                }
            }
            else if (p->state == ST_CLIENT_CONNECTED)
            {
                /* If we have data check if the HTTP header is complete. */
                if (p->client.data.used)
                {
                    res = full_header((char*) p->client.data.buffer, p->client.data.used);
                    if (res)
                    {
                        fast_select++; /* We need to get to the next state fast! */
                        p->header_sz = res;
                        p->state = ST_FIND_HOST;
                    }
                }
            }
            else if (p->state == ST_FIND_HOST)
            {
                char host[MAX_HOST_NAME + 1], verb[16], new_addr[SOCK_ADDR_SZ];
                unsigned short port;
                int discarded;

                res = extract_host((char*) p->client.data.buffer,
                                   verb, host, &port, &discarded);
                if (res == STATUS_OK)
                {
                    res = resolve_address(host, port, &new_addr);
                    if (res == STATUS_OK)
                    {
                        /* Smart people may try to bring the proxy down by making us loop
                         * connecting to the same port the service is provided on. */
                        if (port == cfg.port_v4 || port == cfg.port_v6)
                        {
                            /* Ideally this would check for all IP address we have, but to
                             * simplify our approach we will only match localhost and current
                             * sock bound interface and target address.
                             * To avoid this happening for every connection remember not
                             * to set your proxy to ports like 80 or 443.
                             * Even if the user starts an IPV4 and attempts an IPV6 connection
                             * we will be able to get it in the first loop recursion because
                             * to connect to the IPV6 the sock name will be the IPV6. Also
                             * works for the vice-versa case. */
                            if (is_local_address(new_addr) ||
                                match_local_address(p->client.sock, new_addr))
                            {
                                dprintf1("#%d Loop detected.\n", p->unique_id);
                                res = !STATUS_OK;
                                p->error = FORBIDDEN;
                            }
                        }
                    }
                    else
                        p->error = RESOLVE_FAILED;
                }
                else
                    p->error = BAD_REQUEST;

                fast_select++; /* We need to get to the next state fast! Good or bad. */
                if (res == STATUS_OK)
                {
                    /* SSL tunnel? If yes discard the HTTP header. */
                    if (!strcmp(verb, "CONNECT"))
                    {
                        p->tunnel = 1;
                        skip_data(&p->client.data, p->header_sz);
                    }
                    /* If we changed the header (remove the http:// URI prefix)
                     * fix things now. */
                    else if (discarded)
                    {
                        p->header_sz -= discarded;
                        skip_data(&p->client.data, discarded);
                    }
                    p->requests++; /* Statistics. */

                    /* If we are not connected to a server or if the current request is for
                     * a different host. */
                    if (p->server.sock == INVALID_SOCK ||
                        memcmp(new_addr, p->server.addr, sizeof(new_addr)))
                    {
                        memcpy (p->server.addr, new_addr, sizeof(new_addr));
                        p->state = ST_CONNECT_SERVER;
                    }
                    else
                    {
                        p->state = ST_BRIDGE;
                        p->reuses++; /* Statistics. */
                        /* Assume OK to send. */
                        p->server.writable = 1;
                    }
                    p->last_operation = now;
                }
                else
                    p->state = ST_CLEAR;
            }
            else if (p->state == ST_CONNECT_SERVER)
            {
                /* If socket exists it means the client is reusing the connection but
                 * it's targeting a different host, so close old server. */
                if (p->server.sock != INVALID_SOCK)
                    sock_close(p->server.sock);

                p->server.sock = sock_connect(p->server.addr, SOCK_ASYNC);
                if (p->server.sock != INVALID_SOCK)
                {
                    p->state = ST_WAIT_CONNECTION;
                    p->last_operation = now;
                }
                else
                {
                    p->state = ST_CLEAR;
                    p->error = CONNECT_FAILED;
                    dprintf1("#%d Connection attempt failed.\n", p->unique_id);
                }
            }

            if (p->state != ST_CLEAR)
            {
                /* Check the client socket for reading. */
                FD_ADD_POLL(p->client.sock, &set[0]);
                if (!p->client.writable)
                    FD_ADD_POLL(p->client.sock, &set[1]);

                if (p->server.sock != INVALID_SOCK)
                {
                    /* Check the server socket for writing if we are not connected yet. */
                    if (p->state == ST_WAIT_CONNECTION)
                    {
                        FD_SET(p->server.sock, &set[1]);
                        FD_SET(p->server.sock, &set[2]); /* Also check for exception. */
                        if (p->server.sock > maxsd)
                            maxsd = p->server.sock;
                    }
                    /* Only check for reading in the server socket if we can write
                     * to the client socket. This reduces the amount of loops because
                     * there is no point in trying to receive more data from the server
                     * if the client is not draining. */
                    if (p->client.writable)
                        FD_ADD_POLL(p->server.sock, &set[0]); /* Read. */

                    if (!p->server.writable && p->state != ST_WAIT_CONNECTION)
                        FD_ADD_POLL(p->server.sock, &set[1]); /* Write. */
                }
            }

            /* If no data is received/sent after the request is in process => abort. */
            if (now - p->last_operation >= MAX_TIMEOUT_BRIDGE)
            {
                /* If the server didn't reply with anything give an error to user. */
                if (!p->tunnel && !p->request_end)
                    p->error = GATEWAY_TIMEOUT;
                p->state = ST_CLEAR;
                dprintf1("#%d Timeout.\n", p->unique_id);
            }
            /* If the full request header can't be received in MAX_TIMEOUT_HEADER => abort. */
            else if (!p->header_sz && !p->request_end &&
                    (now - p->client.connection >= MAX_TIMEOUT_HEADER))
            {
                /* We can't reply here as the client didn't send us the header, just abort. */
                p->state = ST_CLEAR;
                dprintf1("#%d Wait for header timeout.\n", p->unique_id);
            }
        }
        /* If we are not doing anything wait for 4 seconds and 10ms in the select(). */
        timeout.tv_sec = fast_select ? 0 : 4;
        timeout.tv_usec = 10000;
        do
        {
            changes = select(maxsd + 1, &set[0], &set[1], &set[2], &timeout);
        }
        while (changes == -1 && CHECK_EINTR);

        /* Everything after this point requires changes to socket events. */
        if (changes <= 0)
            continue;

        for (i = 0; i < sizeof(cfg.master_sock) / sizeof(cfg.master_sock[0]); i++)
        {
            if (cfg.master_sock[i] == INVALID_SOCK)
                continue;

            /* If the READ bit is set it means a new connection was received. */
            if (FD_ISSET(cfg.master_sock[i], &set[0]))
            {
                new = new_connection(cfg.master_sock[i]);
                if (new)
                {
                    if (cfg.head)
                        cfg.head->prev = new;
                    new->next = cfg.head;
                    new->prev = NULL;
                    cfg.head = new;

                    cfg.head->client.connection = cfg.head->last_operation = now;
                }
                changes--;
            }
            /* Check for errors in the listening socket. */
            else if(FD_ISSET(cfg.master_sock[i], &set[2]))
            {
                cfg.running = 0;
                dprintf1("Master socket error, quitting...\n");
                changes--;
            }
        }

        for (p = cfg.head; changes && p; p = p->next)
        {
            int ok;

            ok = 0;
            /* Receive data. */
            if (p->state == ST_BRIDGE || p->state == ST_CLIENT_CONNECTED)
            {
                if (FD_ISSET(p->client.sock, &set[0]))
                {
                    int relay;

                    /* Only relay data before the request is over, after that if new
                     * data arrives it means this is a new request and we have to check
                     * the header to see if the destination is the same [RELAY_COMMENT].
                     * If it's a tunnel, always relay the data. */
                    relay = (p->tunnel || !p->request_end) ? p->server.sock : INVALID_SOCK;
                    res = recv_buffer(p->client.sock, &p->client.data, relay);
                    if (res > 0 || res == -2)
                        ok += res;
                    /* Was this side disconnected? Since this is the client just abort. */
                    else if(!res)
                        p->state = ST_CLEAR;
                    changes--;
                }
                /* Are we testing if the socket is available for writing? */
                if (!p->client.writable && FD_ISSET(p->client.sock, &set[1]))
                {
                    p->client.writable = 1;
                    changes--;
                }
            }

            if (p->server.sock != INVALID_SOCK)
            {
                if (p->state == ST_BRIDGE)
                {
                    if (FD_ISSET(p->server.sock, &set[0]))
                    {
                        /* Always relay from server to client if possible. */
                        res = recv_buffer(p->server.sock, &p->server.data, p->client.sock);
                        /* Was this side disconnected? */
                        if (!res)
                        {
                            /* If there is no buffered data to relay close now. */
                            if (!p->server.data.used)
                                p->state = ST_CLEAR;
                            else
                            {
                                /* Ok, there is still data to send to client in
                                 * the buffer. Close the server side to reduce
                                 * the number of sockets to poll. */
                                sock_close(p->server.sock);
                                p->server.sock = INVALID_SOCK;
                            }
                            dprintf1("#%d Remote closed.\n", p->unique_id);
                            /* If the server knocked out the connection without
                             * saying anything tell the user. Only if this is not
                             * a tunnel. */
                            if (!p->tunnel && !p->request_end)
                                p->error = CONNECT_FAILED;
                        }
                        else if (!p->tunnel)
                        {
                            /* The request is considered over when the server starts replying.
                             * Tunnel connections are simply transparent, we can't have that
                             * logic for them. */
                            if (res > 0)
                                p->request_end = 1;
                        }
                        ok += res;
                        changes--;
                    }
                    /* Are we testing if the socket is available for writing? */
                    if (!p->server.writable && FD_ISSET(p->server.sock, &set[1]))
                    {
                        p->server.writable = 1;
                        changes--;
                    }
                }
                else if (p->state == ST_WAIT_CONNECTION)
                {
                    /* If the exception bit is set during connection state
                     * it means connection was refused. */
                    if (FD_ISSET(p->server.sock, &set[2]))
                    {
                        dprintf1("#%d Connection refused type 1.\n", p->unique_id);
                        p->state = ST_CLEAR;
                        p->error = CONNECT_FAILED;
                        changes--;
                    }
                    /* Received WRITE event? So we are connected. */
                    else if (FD_ISSET(p->server.sock, &set[1]))
                    {
                        /* There is a bug in the kernel or the library or maybe
                         * it works like that as supposed... The problem is that
                         * the WRITE bit is set but the connection is not ready.
                         * It was actually refused! So to ensure we don't fall
                         * into that trap try sending data now and if we get
                         * the error we abort the connection as if it was not
                         * connected. This happens only with IPV6.
                         * For tunnels we can't do this because there is no data
                         * to send to the server yet, so in this case try reading
                         * the socket with PEEK so we don't remove the data from
                         * queue, if recv returns == 0 it means the connection
                         * is closed. */
                        if (!p->tunnel)
                            res = send_buffer(p->server.sock, &p->client.data);
                        else
                        {
                            char buffer[4];

                            res = sock_peek(p->server.sock, buffer, sizeof(buffer));
                        }
                        if (res > 0 || !(res == -1 && CHECK_BROKEN))
                        {
                            dprintf1("#%d Connected.\n", p->unique_id);
                            p->state = ST_BRIDGE;
                            p->server.connection = now;
                            /* Assume OK to send. */
                            p->client.writable = p->server.writable = 1;

                            /* If this is a tunnel connection tell the client we are connected. */
                            if (p->tunnel)
                                append_data(&p->server.data,
                                            (unsigned char*) DEFAULT_TUNNEL_RESPONSE,
                                            DEFAULT_TUNNEL_RESPONSE_SZ);
                        }
                        else
                        {
                            dprintf1("#%d Connection refused type 2.\n", p->unique_id);
                            p->state = ST_CLEAR;
                            p->error = CONNECT_FAILED;
                        }
                        changes--;
                        ok++;
                    }
                }
            }

            /* If data was sent/received or we got connected update the timeout variable. */
            if (ok > 0)
                p->last_operation = now;
        }
    }
}
#undef FD_SETS_RE

int start_proxy(char *bind_v4, unsigned short p_v4,
                char *bind_v6, unsigned short p_v6,
                enum SOCK_FAMILY preferred_family, int debug_enable)
{
    if (!p_v4 && !p_v6)
    {
        printf("Port parameters not found.\n");
        return -2;
    }

    /* We need the ports to test connection loops later. */
    cfg.port_v4 = p_v4;
    cfg.port_v6 = p_v6;
    cfg.preferred_family = preferred_family;

    if (!sock_init())
        return -1;

    cfg.debug = debug_enable;

    if (cfg.port_v4)
    {
        cfg.master_sock[0] = sock_create(IPV4, TCP_SOCK, bind_v4,
                                         cfg.port_v4, SOCK_ASYNC | SOCK_LISTEN);
        if (cfg.master_sock[0] == INVALID_SOCK)
        {
            printf("Failed to create and bind listener socket for IPV4\n");
            cfg.port_v4 = 0;
        }
    }
    else
        cfg.master_sock[0] = INVALID_SOCK;

    if (cfg.port_v6)
    {
        cfg.master_sock[1] = sock_create(IPV6, TCP_SOCK, bind_v6,
                                         cfg.port_v6, SOCK_ASYNC | SOCK_LISTEN);
        if (cfg.master_sock[1] == INVALID_SOCK)
        {
            printf("Failed to create and bind listener socket for IPV6\n");
            cfg.port_v6 = 0;
        }
    }
    else
        cfg.master_sock[1] = INVALID_SOCK;

    return (!p_v4 || cfg.master_sock[0] != INVALID_SOCK) &&
           (!p_v6 || cfg.master_sock[1] != INVALID_SOCK);
}

void end_proxy(void)
{
    struct CONNECTION *p, *n;

    sock_close(cfg.master_sock[0]);
    sock_close(cfg.master_sock[1]);

    for (p = cfg.head; p; p = n)
    {
        n = p->next;
        /* Warn the users we are disabling the server. But only if they are not
         * in the middle of something else. */
        if (!p->tunnel && !p->request_end && p->header_sz)
            send_http_error(p->client.sock, PROXY_DOWN);
        clear_connection(p);
        free(p);
    }
    cfg.head = NULL;

    if (!sock_end())
        dprintf1("We leaked socket descriptors.\n");
}

void stop_proxy(void)
{
    dprintf1("Stopping server...\n");
    cfg.running = 0;
}

#define MAX_SOCK_TESTS 100

enum TEST_STATES
{
    ST_FREE,
    ST_WAIT,
    ST_SEND,
    ST_RECV,
    ST_CLOSE,
    ST_NOTHING
};

void multi_test(int remote, char *str, unsigned short port)
{
    char address[SOCK_ADDR_SZ];
    static const char *hosts[] = {
        "www.google.com",
        "www.microsoft.com",
        "php.net",
        "kernel.org",
        "stackoverflow.com",
        "www.apple.com"
    };
    int i, tests, tests_ok, test_silence, incomplete_opens, incomplete_sends, test_resets,
        total = sizeof(hosts) / sizeof(char *);
    struct TEST_DATA
    {
        enum TEST_STATES state;
        int sock;
        time_t connection;
    } conn[MAX_SOCK_TESTS];

    tests = tests_ok = test_silence = incomplete_opens = incomplete_sends = test_resets = 0;

    /* This function is to test the proxy server, the idea is to
     * make a lot of connections fast to see if all of them are
     * properly serviced. */
    if (!port)
    {
        printf("Invalid test port\n");
        return;
    }
    sock_init();
    if (resolve_address(str, port, address) != STATUS_OK)
    {
        printf("Failed to resolve address %s\n", str);
        sock_end();
        return;
    }

    memset(conn, 0, sizeof(conn));
    for (i = 0; i < MAX_SOCK_TESTS; i++)
        conn[i].state = ST_FREE;

    /* To test our skills with something else than the select call we will employ
     * a different programming technique here. We will rely on getpeername to
     * check for connected sockets and FIONREAD to check when we have something
     * to read. */
    printf("Running...\n");
    while(tests < MAX_SOCK_TESTS)
    {
        time_t now;

        os_sleep(5);
        now = time(NULL);

        for (i = 0; i < MAX_SOCK_TESTS; i++)
        {
            switch (conn[i].state)
            {
                case ST_FREE:
                {
                    conn[i].sock = sock_connect(address, SOCK_ASYNC);
                    if (conn[i].sock == INVALID_SOCK)
                    {
                        incomplete_opens++;
                        conn[i].state = ST_CLOSE;
                    }
                    else
                    {
                        conn[i].state = ST_WAIT;
                        conn[i].connection = now;
                    }
                    break;
                }
                case ST_WAIT:
                {
                    if (sock_connected(conn[i].sock))
                    {
                        conn[i].connection = now;
                        conn[i].state = ST_SEND;
                    }
                    else if (now - conn[i].connection >= 5)
                    {
                        incomplete_opens++;
                        conn[i].state = ST_CLOSE;
                    }
                    break;
                }
                case ST_SEND:
                {
                    char packet[MAX_HOST_NAME * 2];
                    int sz;

                    sz = sprintf(packet, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n",
                            remote ? hosts[i % total] : "127.0.0.1");

                    /* Far away from the best approach but it's ok for this test. */
                    if (sock_send(conn[i].sock, packet, sz) != sz)
                    {
                        if (now - conn[i].connection >= 5)
                        {
                            incomplete_sends++;
                            conn[i].state = ST_CLOSE;
                        }
                    }
                    else
                    {
                        conn[i].connection = now;
                        conn[i].state = ST_RECV;
                    }
                    break;
                }
                case ST_RECV:
                {
                    /* Whatever amount of bytes is OK, we are not checking the data. */
                    if (sock_pending_data(conn[i].sock) > 0)
                    {
                        tests_ok++;
                        conn[i].state = ST_CLOSE;
                    }
                    else if(!sock_connected(conn[i].sock))
                    {
                        test_resets++;
                        conn[i].state = ST_CLOSE;
                    }
                    else if (now - conn[i].connection >= 10)
                    {
                        test_silence++;
                        conn[i].state = ST_CLOSE;
                    }
                    break;
                }
                case ST_CLOSE:
                {
                    tests++;
                    sock_close(conn[i].sock);
                    conn[i].state = ST_NOTHING;
                    break;
                }
                case ST_NOTHING:
                {
                    /* Wait patiently for the tests end. */
                }
            }
        }
    }

    printf("================ Test Summary ================\n"
           "Total tests  : %d\n"
           "Good tests   : %d\n"
           "Resets       : %d\n"
           "No reply     : %d\n"
           "No connects  : %d\n"
           "Failed sends : %d\n"
           "==============================================\n"
           "To be OK total tests = good tests, any other number is bad.\n",
           tests, tests_ok, test_resets, test_silence, incomplete_opens, incomplete_sends);

    sock_end();
}
#undef MAX_SOCK_TESTS
