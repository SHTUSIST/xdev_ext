// SPDX-License-Identifier: GPL-2.0
/* UDP endpoint for an existing guest NIC. Captures every NXP2 payload byte;
 * it has no NVMe slot formula and is not a provider/completion simulator. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static uint32_t be32(const unsigned char *p)
{
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static unsigned be16(const unsigned char *p) { return (unsigned)p[0]<<8 | p[1]; }
static uint32_t checksum(const unsigned char *p, size_t n)
{
    uint32_t c = ~0U;
    size_t i;
    unsigned bit;
    for (i = 0; i < n; i++) {
        c ^= i >= 36 && i < 40 ? 0 : p[i];
        for (bit = 0; bit < 8; bit++)
            c = (c >> 1) ^ ((c & 1) ? 0x82f63b78U : 0);
    }
    return ~c;
}
int main(int argc, char **argv)
{
    struct sockaddr_in addr = { .sin_family = AF_INET };
    unsigned char capture[16*4096], buf[65536];
    unsigned generation = 1, index = 0, offset = 0, count = 0;
    int fd, ret = 1;
    char *end;
    unsigned long port;
    FILE *out;

    if (argc != 4 || !inet_pton(AF_INET, argv[1], &addr.sin_addr))
        return 2;
    port = strtoul(argv[2], &end, 10);
    if (!*argv[2] || *end || !port || port > 65535)
        return 2;
    addr.sin_port = htons((uint16_t)port);
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("E2 sink bind");
        return 1;
    }
    puts("E2_SINK_READY"); fflush(stdout);
    while (generation <= 16) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        ssize_t n;
        unsigned bytes, nr;
        if (poll(&pfd, 1, 60000) <= 0)
            goto bad;
        n = recv(fd, buf, sizeof(buf), 0);
        if (n < 40 || memcmp(buf, "NXP2\2\50\2\0", 8) ||
            be32(buf + 8) || be32(buf + 12) != 270019 ||
            be32(buf + 16) != generation || be16(buf + 20) != index ||
            be32(buf + 24) != 4096 || be32(buf + 28) != offset)
            goto bad;
        nr = be16(buf + 22); bytes = be32(buf + 32);
        if (!nr || nr > 32 || index >= nr || (index && nr != count) ||
            !bytes || bytes > 4096 - offset || n != (ssize_t)(40 + bytes) ||
            be32(buf + 36) != checksum(buf, (size_t)n))
            goto bad;
        count = nr;
        memcpy(capture + (generation - 1)*4096 + offset, buf + 40, bytes);
        offset += bytes; index++;
        if (index == count) {
            if (offset != 4096)
                goto bad;
            generation++; index = offset = count = 0;
        } else if (offset >= 4096) {
            goto bad;
        }
    }
    /* Publish only a complete validated capture; refuse overwrite. */
    out = fopen(argv[3], "wbx");
    if (!out) {
        perror("E2 sink output");
        goto done;
    }
    if (fwrite(capture, 1, sizeof(capture), out) != sizeof(capture)) {
        fclose(out); unlink(argv[3]); goto bad;
    }
    if (fclose(out)) { unlink(argv[3]); goto bad; }
    puts("E2_SINK_CAPTURE=PASS bytes=65536 performance_claim=none");
    ret = 0;
    goto done;
bad:
    fputs("E2 sink: malformed, incomplete, reordered or corrupt NXP2 payload\n", stderr);
done:
    close(fd);
    return ret;
}
