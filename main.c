//----------------------------------------------------------------------------------------------------------------------
#include <assert.h>
#include <limits.h>
static_assert(CHAR_BIT == 8, "ERROR: This code requires [char] to be exactly 8 bits.");
//----------------------------------------------------------------------------------------------------------------------
#include <stdint.h>
typedef   unsigned char        u8     ;   typedef   char         s8     ;
typedef   uint16_t             u16    ;   typedef   int16_t      s16    ;
typedef   uint32_t             u32    ;   typedef   int32_t      s32    ;
typedef   uint64_t             u64    ;   typedef   int64_t      s64    ;
typedef   __uint128_t          u128   ;   typedef   __int128_t   s128   ;
typedef   unsigned int         ui     ;   typedef   int          si     ;
typedef   unsigned long        ul     ;   typedef   long         sl     ;
typedef   unsigned long long   ull    ;   typedef   long long    sll    ;
typedef   float                r32    ;   typedef   double       r64    ;
//----------------------------------------------------------------------------------------------------------------------
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <inttypes.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
//----------------------------------------------------------------------------------------------------------------------
#define ENABLE_OUTPUT     1
#define MAX_LISTEN      100
#define BUFSIZE       16384
//----------------------------------------------------------------------------------------------------------------------
void pump(struct sockaddr_in * const restrict, const si);          // network pump
void * map_file(s8 const * const restrict, u64 * restrict const);  // utility
void o(s8 const * const restrict, ... );                           // utility
s8 * datetime(s8 * const restrict);                                // utility
sem_t * csoutput;                                                  // critical section
//----------------------------------------------------------------------------------------------------------------------
void pump(struct sockaddr_in * const restrict addr, const si sock)
{
    s8 * const restrict buf = malloc(BUFSIZE);

    if (!buf)
    {
        o("memory could not be allocated\n");
        exit(EXIT_FAILURE);
    }

    u64 filesize;
    s8 * const restrict webpage = map_file("page.htm", &filesize);

    if (!filesize || !webpage)
    {
        o("page.htm could not be found\n");
        exit(EXIT_FAILURE);
    }
    else if ((filesize + 256) > BUFSIZE)
    {
        o("page.htm is too large for BUFSIZE\n");
        exit(EXIT_FAILURE);
    }

    const u64 header_length = sprintf(buf, "HTTP/1.1 200 OK\nServer: tinypage/1.0\nContent-Length: %"PRIu64"\nConnection: close\nContent-Type: text/html; charset=us-ascii\n\n", filesize);
    const u64 packet_size = header_length + filesize;

    s8 * const restrict packet = malloc(packet_size);

    if (!packet)
    {
        o("memory could not be allocated\n");
        exit(EXIT_FAILURE);
    }

    memcpy(packet, buf, header_length);
    memcpy(&packet[header_length], webpage, filesize);

    si res = munmap(webpage, filesize);

    if (res == -1)
    {
        o("memory could not be unmapped\n");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        s8 dtbuf[64];
        o("%s > socket accepting\n", datetime(dtbuf));

        socklen_t socklen = sizeof(struct sockaddr_in);

        errno = 0;
        const si client_sock = accept(sock, (void *)addr, &socklen);

        if (client_sock == -1)
        {
            o("%s > accept error: %d\n", datetime(dtbuf), errno);
        }
        else
        {
            errno = 0;
            const pid_t pid = fork();

            if (pid == -1) // error
            {
                o("%s > fork error: %d\n", datetime(dtbuf), errno);

                errno = 0;
                res = close(client_sock);

                if (res == -1)
                {
                    o("%s > close(client_sock) error: %d\n", datetime(dtbuf), errno);
                    exit(EXIT_FAILURE);
                }
            }
            else if (!pid) // child
            {
                s8 const * const restrict ip = inet_ntoa(addr->sin_addr);

                if (!ip || strnlen(ip, 16) == 16)
                {
                    o("%s > inet_ntoa() failed\n", datetime(dtbuf));
                    exit(EXIT_FAILURE);
                }

                errno = 0;
                res = close(sock);

                if (res == -1)
                {
                    o("%s > close(sock) error: %d (%s)\n", datetime(dtbuf), errno, ip);
                    exit(EXIT_FAILURE);
                }

                o("%s > client with IP %s connected\n", datetime(dtbuf), ip);

                memset(buf, 0, 16);

                errno = 0;
                const ssize_t len = recv(client_sock, buf, BUFSIZE, 0);

                if (len == -1)
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        o("%s > recv timeout: %s\n", datetime(dtbuf), ip);
                    }
                    else
                    {
                        o("%s > recv error: %d (%s)\n", datetime(dtbuf), errno, ip);
                    }
                }
                else if (!len)
                {
                    o("%s > orderly close: %s\n", datetime(dtbuf), ip);
                }
                else
                {
                    o("%s > recv %zu bytes from %s\n", datetime(dtbuf), len, ip);

                    if (ENABLE_OUTPUT)
                    {
                        errno = 0;
                        res = sem_wait(csoutput);

                        if (res == -1)
                        {
                            perror("sem_wait error");
                            exit(EXIT_FAILURE);
                        }

                        if (fwrite(buf, 1, len, stdout) != len)
                        {
                            puts("fwrite error");
                            exit(EXIT_FAILURE);
                        }

                        putchar('\n');

                        errno = 0;
                        res = sem_post(csoutput);

                        if (res == -1)
                        {
                            perror("sem_post error");
                            exit(EXIT_FAILURE);
                        }
                    }

                    if ((!strncasecmp(buf, "get ", 4) && strncasecmp(buf, "get /favicon.ico", 16)) || !strncasecmp(buf, "post ", 5) || !strncasecmp(buf, "head ", 5))
                    {
                        o("valid request from %s\n", ip);

                        errno = 0;
                        const ssize_t sent = send(client_sock, packet, packet_size, 0);

                        if (sent == -1)
                        {
                            o("%s > send error: %d (%s)\n", datetime(dtbuf), errno, ip);
                        }
                        else if (sent == packet_size)
                        {
                            o("sent %zu bytes to %s\n", sent, ip);
                        }
                        else
                        {
                            o("%s > unkown send error: %s\n", datetime(dtbuf), ip);
                        }
                    }
                }

                errno = 0;
                res = close(client_sock);

                if (res == -1)
                {
                    o("%s > close(client_sock) error: %d (%s)\n", datetime(dtbuf), errno, ip);
                    exit(EXIT_FAILURE);
                }

                exit(EXIT_SUCCESS);
            }
            else // parent
            {
                errno = 0;
                res = close(client_sock);

                if (res == -1)
                {
                    o("%s > close(client_sock) error: %d\n", datetime(dtbuf), errno);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
si main(si argc, s8 ** argv)
{
    errno = 0;
    if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
    {
        perror("signal error");
        return EXIT_FAILURE;
    }

    errno = 0;
    if ((csoutput = mmap(0, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)
    {
        perror("mmap error");
        return EXIT_FAILURE;
    }

    errno = 0;
    if (sem_init(csoutput, 1, 1) == -1)
    {
        perror("sem_init error");
        return EXIT_FAILURE;
    }

    s8 dtbuf[64];
    o("%s > tinypage v1.0\n", datetime(dtbuf));

    if (argc != 3)
    {
        o("%s <local bind ip> <local port>\n", argv[0]);
        o("example: %s 127.0.0.1 80 > httpout.txt\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr = { 0 };

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = inet_addr(argv[1]);

    errno = 0;
    const si sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock == -1)
    {
        perror("socket error");
        return EXIT_FAILURE;
    }

    o("socket open\n");

    // socket & TCP options: You may want to change them!

    const si off = 0, on = 1;
    const struct linger li =  {  1, 15 }; // linger on close enabled, 15 seconds before timeout
    const struct timeval tv = { 15,  0 }; // send/recv 15 second timeout

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

        if (res == -1)
        {
            perror("setsockopt error");
            return EXIT_FAILURE;
        }
    }

    #undef options

    errno = 0;
    si res = bind(sock, (void *)&addr, sizeof(struct sockaddr_in));

    if (res == -1)
    {
        perror("bind error");
        return EXIT_FAILURE;
    }

    o("socket bound\n");

    errno = 0;
    res = listen(sock, MAX_LISTEN);

    if (res == -1)
    {
        perror("listen error");
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
        errno = 0;
        si res = sem_wait(csoutput);

        if (res == -1)
        {
            perror("sem_wait error");
            exit(EXIT_FAILURE);
        }

        va_list t;
        va_start(t, format);
        res = vprintf(format, t);
        va_end(t);

        if (res < 0)
        {
            fputs("vprintf error\n", stderr);
            exit(EXIT_FAILURE);
        }

        fflush(stdout);

        errno = 0;
        res = sem_post(csoutput);

        if (res == -1)
        {
            perror("sem_post error");
            exit(EXIT_FAILURE);
        }
    }
}
//----------------------------------------------------------------------------------------------------------------------
s8 * datetime(s8 * const restrict buf)
{
    struct tm l;

    errno = 0;
    const time_t t = time(0);

    if (t == -1)
    {
        perror("time error");
        exit(EXIT_FAILURE);
    }

    if (localtime_r(&t, &l) != &l)
    {
        fputs("localtime_r error\n", stderr);
        exit(EXIT_FAILURE);
    }

    if (asctime_r(&l, buf) != buf)
    {
        fputs("asctime_r error\n", stderr);
        exit(EXIT_FAILURE);
    }

    buf[strlen(buf) - 1] = 0;

    return buf;
}
//----------------------------------------------------------------------------------------------------------------------
void * map_file(s8 const * const restrict filename, u64 * const restrict filesize)
{
    *filesize = 0;
    void * p = 0;

    const si fd = open(filename, O_RDONLY | O_BINARY);

    if (fd >= 0)
    {
        struct stat s;
        const si res = fstat(fd, &s);

        if (!res)
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