//----------------------------------------------------------------------------------------------------------------------
#include <assert.h>
#include <limits.h>
static_assert(CHAR_BIT == 8, "ERROR: This code requires [char] to be exactly 8 bits.");
//----------------------------------------------------------------------------------------------------------------------
#include <stdint.h>
typedef   unsigned int    ui;   typedef   int            si;
typedef   unsigned char   u8;   typedef   char           s8;
typedef   uint16_t       u16;   typedef   int16_t       s16;
typedef   uint32_t       u32;   typedef   int32_t       s32;
typedef   uint64_t       u64;   typedef   int64_t       s64;
typedef   __uint128_t   u128;   typedef   __int128_t   s128;
typedef   float          r32;   typedef   double        r64;
//----------------------------------------------------------------------------------------------------------------------
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
//----------------------------------------------------------------------------------------------------------------------
#define ENABLE_OUTPUT     1
#define MAX_LISTEN      100
#define BUFSIZE       65536
//----------------------------------------------------------------------------------------------------------------------
void pump(struct sockaddr_in * const restrict, const si);          // network pump
void * map_file(s8 const * const restrict, u64 * restrict const);  // utility
void o(s8 const * const restrict, ... );                           // utility
//----------------------------------------------------------------------------------------------------------------------
void pump(struct sockaddr_in * const restrict addr, const si sock)
{
    errno = 0;
    char * const buf = malloc(BUFSIZE);

    if (errno || !buf)
    {
        o("memory could not be allocated!\n");
        exit(EXIT_FAILURE);
    }

    u64 filesize;
    s8 const * const restrict webpage = map_file("page.htm", &filesize);

    if (!filesize || !webpage)
    {
        o("page.htm could not be found!\n");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        o("socket accepting\n");

        socklen_t socklen = sizeof(struct sockaddr_in);

        errno = 0;
        si client_sock = accept(sock, (struct sockaddr*)addr, &socklen);

        if (errno || client_sock == -1)
        {
            o("accept error: %d (%s)\n", errno, inet_ntoa(addr->sin_addr));
            continue;
        }

        errno = 0;
        pid_t pid = fork();

        if (errno || pid == -1)
        {
            o("fork error: %d\n", errno);
            close(client_sock);
            continue;
        }

        if (!pid) // child
        {
            close(sock);

            o("client with IP %s connected\n", inet_ntoa(addr->sin_addr));

            memset(buf, 0, 12);

            errno = 0;
            const ssize_t len = recv(client_sock, buf, BUFSIZE, 0);

            if (errno || len == -1)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    o("recv timeout: %s\n", inet_ntoa(addr->sin_addr));
                }
                else
                {
                    o("recv error: %d (%s)\n", errno, inet_ntoa(addr->sin_addr));
                }
            }
            else if (!len)
            {
                o("orderly close: %s\n", inet_ntoa(addr->sin_addr));
            }
            else
            {
                o("recv %u bytes from %s\n", len, inet_ntoa(addr->sin_addr));

                if (len < 16384)
                {
                    if (ENABLE_OUTPUT)
                    {
                        fwrite(buf, 1, len, stdout);
                        o("\n");
                    }

                    if (!strncasecmp(buf, "get ", 4) && strncasecmp(buf, "get /favicon", 12))
                    {
                        o("valid request from %s\n", inet_ntoa(addr->sin_addr));

                        const u64 header_length = sprintf(buf, "HTTP/1.1 200 OK\nServer: tinypage/1.0\nContent-Length: %"PRIu64"\nConnection: close\nContent-Type: text/html; charset=us-ascii\n\n", filesize);
                        memcpy(&buf[header_length], webpage, filesize);
                        const u64 packet_size = header_length + filesize;

                        errno = 0;
                        ssize_t sent = send(client_sock, buf, packet_size, 0);

                        if (errno || sent == -1)
                        {
                            o("send error: %d (%s)\n", errno, inet_ntoa(addr->sin_addr));
                        }
                        else if (sent == packet_size)
                        {
                            o("sent %d bytes to %s\n", sent, inet_ntoa(addr->sin_addr));
                        }
                        else
                        {
                            o("unkown send error: %s\n", inet_ntoa(addr->sin_addr));
                        }
                    }
                }
            }

            close(client_sock);

            exit(EXIT_SUCCESS);
        }

        close(client_sock);
    }
}
//----------------------------------------------------------------------------------------------------------------------
si main(si argc, s8 ** argv)
{
    o("tinypage v1.0\n");

    if (argc != 3)
    {
        o("example: %s 127.0.0.1 80\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr = { 0 };

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = inet_addr(argv[1]);

    errno = 0;
    const si sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (errno || sock == -1)
    {
        o("socket error: %d\n", errno);
        return EXIT_FAILURE;
    }

    o("socket open\n");

    // socket & TCP options: You may want to change them!

    const si off = 0, on = 1;
    const struct linger li = { 1, 5 }; // enabled, 5 seconds before timeout
    const struct timeval tv = { 5, 0 }; // send/recv 5 second timeout

    // Pack all of our options into structured arrays so we can loop over them:

    #define options 5

    const si p[options][3] =
    {
        { SOL_SOCKET,  SO_KEEPALIVE, sizeof(off) },
        { SOL_SOCKET,  SO_LINGER,    sizeof(li)  },
        { IPPROTO_TCP, TCP_NODELAY,  sizeof(on)  },
        { SOL_SOCKET,  SO_RCVTIMEO,  sizeof(tv)  },
        { SOL_SOCKET,  SO_SNDTIMEO,  sizeof(tv)  },
    };

    void const * const restrict v[options] = { &off, &li, &on, &tv, &tv };

    for (si i=0;i<options;i++)
    {
        errno = 0;
        const si res = setsockopt(sock, p[i][0], p[i][1], v[i], p[i][2]);

        if (errno || res == -1)
        {
            o("setsockopt error: %d\n", errno);
            return EXIT_FAILURE;
        }
    }

    #undef options

    errno = 0;
    si res = bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    if (errno || res == -1)
    {
        o("bind error: %d", errno);
        return EXIT_FAILURE;
    }

    o("socket bound\n");

    errno = 0;
    res = listen(sock, MAX_LISTEN);

    if (errno || res == -1)
    {
        o("listen error: %d\n", errno);
        return EXIT_FAILURE;
    }

    o("socket listening\n");

    pump(&addr, sock);

    __builtin_unreachable();
}
//----------------------------------------------------------------------------------------------------------------------
void o(s8 const * const restrict format, ... )
{
    if (ENABLE_OUTPUT)
    {
        va_list t;
        va_start(t, format);
        vprintf(format, t);
        va_end(t);
        fflush(stdout);
    }
}
//----------------------------------------------------------------------------------------------------------------------
void * map_file(s8 const * const restrict filename, u64 * const restrict filesize)
{
    *filesize = 0;
    void * p = 0;

    si fd = open(filename, O_RDONLY | O_BINARY);

    if (fd >= 0)
    {
        struct stat s;

        if (!fstat(fd, &s))
        {
            const u64 file_size = s.st_size;
            p = mmap(0, file_size, PROT_READ, MAP_PRIVATE, fd, 0);

            if (p == MAP_FAILED)
            {
                p = 0;
            }
            else
            {
                *filesize = file_size;
            }
        }

        close(fd);
    }

    return p;
}
//----------------------------------------------------------------------------------------------------------------------