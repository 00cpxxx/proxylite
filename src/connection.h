/* Proxylite - Function definitions
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

#ifndef CONNECTION_H
#define CONNECTION_H

int start_proxy(char *bind_v4, unsigned short port_v4,
                char *bind_v6, unsigned short port_v6,
                enum SOCK_FAMILY efamily,
                char *forward_addr, unsigned short forward_port,
                int debug_enable);
void app_loop(void);
void stop_proxy(void);
void end_proxy(void);

void multi_test(int remote, char *addr, unsigned short port);

#endif
