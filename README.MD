proxylite
=========

About the Project
-----------------
An HTTP proxy with support for most common methods including CONNECT (mainly used for https).
It's entirely written in C from scratch and compiles and runs in different OS like GNU/Linux,
PC-BSD and Windows. This is a very simple application used as a tool to learn and apply some
network concepts. It's meant to be lightweight and single-threaded, thus the name proxy lite.

Features
--------
 - Supports both IPv4 and IPv6 connections, an IPv4 client can access IPv6 servers and vice-versa;
 - Very simple with a lot of comments to help people understand the code flow;
 - Minimal to no changes to the HTTP header meaning that the server does not know this is a proxy;
 - Almost stateless operation that does not rely on analyzing the data from/to client/server;
 - Suppots HTTPS through the CONNECT method (FTP applications and even Skype can use that);
 - Reports errors to users when possible instead of silently shutting down the connection;
 - Single thread, no messing with semaphores, mutexes or other synchronization functions.

Compiling
---------
The project (shamefully) does not have a Makefile, in my defence I say that the project
is too simple for that (lol). A compile.sh is provided but any gcc *.c -o proxylite will
do. A few binaries are available in the "bin/" folder.

To compile in Windows I used MinGW: gcc -O2 src\*.c -o bin\windows\proxylite.exe -lws2_32
It may or may not compile in Visual Studio.

Usage
-----
Copied directly from the application running with -h parameter:

	-h|--help    Show this help and quit
	-f|--fork    Run in background (does not work in Windows)
	-d|--debug   Print some debug messages while running
	-4|--ipv4    Prefer IPV4 while resolving names
	-6|--ipv6    Prefer IPV6 while resolving names
	-p4 <port>   Port to bind the IPV4 socket
	-p6 <port>   Port to bind the IPV6 socket
	-b4 <ipv4>   Local IP to bind the IPV4 socket
	-b6 <ipv6>   Local IP to bind the IPV6 socket

	 --test <name> <port> Do 100 connections to the specified proxy
	                       and request the '/' URI from 5 well known
	                       sites, quit after the test.
	--ltest <name> <port> Same as previous but connects to 127.0.0.1:80

	If -b4|-b6 is not set they will bind to all available addresses.
	To disable IPV4 don't set -p4 or set to 0 (zero), same for IPV6.
	If -4 and -6 are used as argument the last used will be preferred.
	Using -f|--fork disables -d|--debug.

Examples:

`./proxylite -p4 3000 -p6 3001 -f`

Runs the application in the background listening for IPv4 connections in port 3000 and 3001 for IPv6.

`./proxylite -p4 3000 -b4 192.168.0.10 -d`

Listen for IPv4 connections on port 3000 in the interface with address 192.168.0.10 only, also display
some debug information about the connections. In this case listening for IPv6 is disabled.

In order to bind the same port for the IPv4 and IPv6 you have to specify the bind address.

About the Code
--------------
All code is written in C with no external libraries required. The application runs in a single
thread by using select() and non-blocking socket operations. It's a console based application
that by default does not output anything. The code indent is based on Allman's style and the
column limit is around 100 (please don't print the code). 

Approach
--------
The motivation to make this project was to combine different skills and build an application
that would be portable and requiring no external libraries. To learn more about networking
only BSD/POSIX socket functions were used so the code should run in any system that implements
the standards (includes Windows).

The code was written in C because it's the language I know better than others and also because
the target computer was an Atmel ARM G20 processor with 64Mb of RAM. Later I switched to another
more powerful computer (ARM Cortex A5 with 512Mb of RAM) but the project still runs in the G20.

When a client connects it is added to a double linked-list, the application loop runs through
this list and checks the state of the connection making the appropriate operations. The first
state is to wait for the client to send us an HTTP header, then the header is parsed and the
target server name is resolved and the socket connected. After connected the client header is
forwarded to the server and anything that comes from the server is relayed back to the client.

To simplify and make this operation faster we only change the header if necessary, we never
add or remove anything from the header, except the server prefix from the URL.

We don't care about what is being transmitted between client and server and we violate RFC 2068
deliberately by not adding a "Via" header in the HTTP request; to tell the server that the request
is being routed through a proxy application. Also we do not support the non-standard header
field called "Proxy-Connection". That field was invented as an attempt to speedup the proxy calls
by leaving the connection between the client and proxy open even if the remote side disconnects,
see more in the HTTP sub chapter below.

When we can't resolve the requested host name, can't connect to it or have a timeout waiting
for its answer we abort the connection but sending a message to the client (when possible).

The application supports keep-alive connections by checking when the client makes a new request,
and it also supports new requests to different hosts over the same connection.

The application loop uses select() to check for socket changes, mainly for read on the listener
sockets (a read bit set in a listening socket means a new connection is pending and accept()
can receive it) and client/server sockets (a read bit in a connected socket means there is
new data to receive). When we are in the process to connect to the server we also check for
write and except changes (a write bit during a connect() call can mean a connection was
established and a exception bit means the connect() failed). One may argue that the select call
is outdated and does not perform well, stating that some sort of poll variant should be used.
That may be true but the aim of this project was to be portable, so select was chosen because
it's present everywhere.

The option SO_REUSEADDR is not used on purpose so you can experience a TIME_WAIT status
when killing and trying to restar the application. Also remember that SO_REUSEADDR in Windows
versions <= XP has a dangerous semantic of allowing multiple different applications to bind
to the same door (allowing to an old problem called port hijacking).

Name resolution was implemented with getaddrinfo() and we trust it completely to give us the
best address because we always use the first returned instead of looping the list or giving it
hints, this works very well in all platforms tested. Some hosts advertise support for IPv6 but
the connect() call fails later or connects but never receives a reply, but that is not really
our problem, we can't fix their side...

A small function to test the server was also implemented, it does 100 connections divided in
5 different major well-known sites through the proxy to test if it can handle all connections
at the same time. This test is select() free, it uses other approaches to check if the server
is connected and if there is data pending, useful to learn something different.

A well-known way to take down a proxy server is to make it connect to itself, this generates a
loop of requests that ends up consuming all proxy resources leading to a DoS (Denial of Service).
We take care of that by checking if the client is asking us to connect to ourselves.

Each connection can have 2 buffers, one to receive the header (which is always present) and
pottentially posted data and another from the server data that can't be relayed directly to
the client. For example, the client can be using a very slow internet, in this case the proxy
will receive data from the server much faster than the client can receive the data. This will
make the proxy store the data to the client so it can drain slowly. When the limit of this
buffer size is reached the proxy will stop reading data from the server (stalling the TCP
connection) until the client is able to get the whole buffer. The use of the buffer is useful
when the file being served is smaller than the proxy buffer size, when this happens the proxy
can cache the whole data for the client to drain and the connection to the server may be closed.

The application does not generate any file logs by default and the information it can output
when using the -d flag is mostly used for debugging purposes.

All connections are subject to a general 60 seconds timeout after the server starts replying.
And after receiving a client connection it has 10 seconds to send at least the full HTTP header.
The timings are based in the time() function, that means a computer date/time change will affect
all timeout measures. To solve this a monotonic clock measure could be used but for simplicity
and compatibility between all OS we are not doing that.

The command line parsing is very simple and will ignore errors, for example "-p4 -d 3000" is the
same as "-p4 0" because the -d will be used as atoi() for the port and the 3000 will be ignored
because it's not an option.

Last but not least, the server can be gracefully stopped by SIGINT and SIGTERM and the proxy
will refuse to run as root, there is no need for it and it could be dangerous if some issue
was found that caused arbitraty code execution.

General HTTP Information
------------------------
When you open a URL in your browser it creates an HTTP request header and send it to the server.
for example let's take this URL:

`http://alexa.pro.br/~bruno`

When a proxy server is enabled in the client browser it could request this in at least three
different ways:

	GET http://alexa.pro.br/~bruno HTTP/1.0\r\n
	\r\n

	GET /~bruno HTTP/1.1\r\n
	Host: alexa.pro.br\r\n
	\r\n

	GET http://alexa.pro.br/~bruno HTTP/1.1\r\n
	Host: alexa.pro.br\r\n
	\r\n

When the proxy server receives that it has to parse the line to extract the requested method (GET)
and the host part (alexa.pro.br). The double line end (\r\n\r\n) tells that the header ended.

The usefulness of the "Proxy-Connection" field is usually misunderstood and implemented in broken
ways in the proxy servers, since it's not standard we are not implementing it even when well known
applications like wget use it. I think the field is a good idea because it can help keeping the
connection between the client and the proxy open even when the server replies with a header field
"Connection: close". But implementing this would make we have to change the header and we can't
afford loosing that time.

Drawbacks
---------
The whole code runs in a single thread meaning that if something takes too much time the whole
program performance is affected. Most socket operations are really fast and the non-blocking IO
works very well, but unfortunately the name resolution used to find the IP of the servers is
a blocking call so if the address is not already cached by the OS and the name server takes to
long to respond the application will have to wait.

The limit of sockets possible to take care at the same time is 128 in Windows and 1024 in Unix
systems. This happens due to the difference between the implementations of the "FD_" operations
between the different operating systems.

To ensure compatibility with Windows versions <= XP it's not possible to print IPv6 addresses
due to the lack of inet_ntop function. It's also not possible to bind to an IPv6 in <= XP for
the same reason.

Final Considerations
--------------------
Our goals were achieved so I'm happy with the result, it was tested x86, x86_64 and ARM using
GNU/Linux and x86 using PC-BSD. It also was tested in Windows XP, 7 and 8. To make it work in
previous Windows versions I dropped the IPv6 stuff and changed the name resolution to use
gethostbyname, this way it was able to run from Windows 95 to 8, these changes are not added
in the present code to eliminate the use of #ifdef to compile different versions. The Windows
version also runs fine in Wine.

Certainly many improvements could be made to the software and a load of features could be added,
some of them are listed below:
 - Making a restrictive list of valid clients and implementing basic realm authentication for them;
 - Making a restrictive list of target servers and denying access for them;
 - Caching the resolved address in an ordered list (to use binary search) or a hash-table;
 - Implement Socks 4 and 5 (without authentication);
 - Adding a log to file adding the date, client IP address and the target URL;
 - Turn it into an HTTP server by removing the bridging stuff and adding file reading;
 - Making the application multi-threaded and using some nice skills to deal with the C10k problem.

I have been using the application for some time now and everything seems stable, never crashed
so far.

Contact Information
------
My name is Bruno Jesus and I'm a brazilian living in Sao Paulo. To contact me send me an email at
00cpxxx@gmail.com

Feel free to send suggestions, comments or a hello. Spam is welcome too since gmail filters it all.
