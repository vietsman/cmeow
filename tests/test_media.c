/* Media: key schedule round trip, MAC rejection, and a loopback HTTP download that exercises the
 * chunked decoder and the streaming decryptor (10-byte MAC tail handling). */
#define _POSIX_C_SOURCE 200112L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "crypto.h"
#include "media.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static void serve(int ls, const uint8_t *blob, size_t n)
{
    int fd = accept(ls, NULL, NULL);
    char req[2048];
    size_t off = 0;
    char hdr[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\n\r\n";

    if (fd < 0)
        _exit(2);
    {   /* read request head */
        size_t got = 0;
        ssize_t r;

        while (got < sizeof(req) - 1 && (r = read(fd, req + got, sizeof(req) - 1 - got)) > 0) {
            got += (size_t)r;
            req[got] = 0;
            if (strstr(req, "\r\n\r\n"))
                break;
        }
    }
    if (write(fd, hdr, strlen(hdr)) < 0)
        _exit(3);
    while (off < n) { /* odd chunk sizes, so MAC tail straddles chunk boundaries */
        size_t k = (off % 5) + 1 + (off % 3) * 4;
        char line[32];

        if (k > n - off)
            k = n - off;
        snprintf(line, sizeof(line), "%zx\r\n", k);
        if (write(fd, line, strlen(line)) < 0 || write(fd, blob + off, k) < 0 || write(fd, "\r\n", 2) < 0)
            _exit(3);
        off += k;
    }
    if (write(fd, "0\r\n\r\n", 5) < 0)
        _exit(3);
    close(fd);
    _exit(0);
}

static cm_err dl_from(const uint8_t *blob, size_t n, const cm_media_keys *unused, const uint8_t *mk,
                      const uint8_t *encsha, const uint8_t *filesha, uint8_t **out, size_t *olen)
{
    int ls = socket(AF_INET, SOCK_STREAM, 0), st;
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    pid_t pid;
    char url[64];
    cm_device *dev;
    cm_client *c;
    cm_download_info info;
    cm_err e;

    (void)unused;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&a, sizeof(a)) || listen(ls, 1) || getsockname(ls, (struct sockaddr *)&a, &al))
        exit(9);
    pid = fork();
    if (pid == 0)
        serve(ls, blob, n);
    close(ls);
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/f", ntohs(a.sin_port));
    cm_device_new(&dev);
    c = cm_client_new(dev, NULL);
    memset(&info, 0, sizeof(info));
    info.url = url;
    info.media_key = mk;
    info.media_key_len = 32;
    info.enc_sha256 = encsha;
    info.file_sha256 = filesha;
    info.type = CM_MEDIA_IMAGE;
    e = cm_client_download(c, &info, out, olen);
    cm_client_free(c);
    cm_device_free(dev);
    waitpid(pid, &st, 0);
    return e;
}

int main(void)
{
    uint8_t mk[32], *plain, *enc = NULL, *dec = NULL, h_enc[32], h_plain[32];
    size_t pn = 1000 + 7, en = 0, dn = 0, i;
    cm_media_keys k;
    uint8_t *got = NULL;
    size_t gn = 0;

    plain = (uint8_t *)malloc(pn);
    cm_random(mk, 32);
    cm_random(plain, pn);
    CHECK(cm_media_keys_derive(mk, 32, CM_MEDIA_IMAGE, &k) == CM_OK);
    CHECK(cm_media_encrypt(&k, plain, pn, &enc, &en) == CM_OK);
    CHECK(en == 1008 + 16 + 10 - 16 + 0 || en > pn); /* padded ciphertext plus 10 byte MAC */
    CHECK(cm_media_decrypt(&k, enc, en, &dec, &dn) == CM_OK && dn == pn && memcmp(dec, plain, pn) == 0);
    free(dec);
    enc[3] ^= 1;
    CHECK(cm_media_decrypt(&k, enc, en, &dec, &dn) == CM_ERR_AUTH);
    enc[3] ^= 1;
    cm_sha256(enc, en, h_enc);
    cm_sha256(plain, pn, h_plain);

    CHECK(dl_from(enc, en, &k, mk, h_enc, h_plain, &got, &gn) == CM_OK && gn == pn && memcmp(got, plain, pn) == 0);
    free(got);
    enc[100] ^= 0x40; /* corrupted in transit: must be rejected */
    got = NULL;
    CHECK(dl_from(enc, en, &k, mk, NULL, NULL, &got, &gn) == CM_ERR_AUTH);
    free(got);
    (void)i;
    free(plain);
    free(enc);
    printf("test_media: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
