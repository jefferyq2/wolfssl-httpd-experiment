#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 11111

#define CERT_FILE "certs/server.crt"
#define KEY_FILE  "certs/server.key"

extern int server_socket(int port);
extern WOLFSSL_CTX *tls_setup(void);
extern WOLFSSL *tls_attach(WOLFSSL_CTX *ctx, int connd);

int main() {
    const char reply[] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 38\r\n\r\n<!doctype html>\r\n<p>hello, world!</p>\n";

    int sockfd = server_socket(DEFAULT_PORT);

    wolfSSL_Init();
    WOLFSSL_CTX *ctx = tls_setup();

    bool done = ctx == NULL;
    while (!done) {
        int connd = accept(sockfd, NULL, NULL);
        if (connd == -1) {
            perror("accept");
            continue;
        }

        WOLFSSL *ssl = tls_attach(ctx, connd);
        if (!ssl) {
            close(connd);
            continue;
        }

        printf("Client connected successfully\n");

        char recvbuf[256] = {0};
        int count = wolfSSL_read(ssl, recvbuf, sizeof(recvbuf) - 1);
        if (count == -1) {
            fprintf(stderr, "ERROR: failed to read\n");
            wolfSSL_free(ssl);
            close(connd);
            break;
        }

        printf("Client: %s\n", recvbuf);

        char sendbuf[256] = {0};
        stpncpy(sendbuf, reply, sizeof(reply));
        sendbuf[sizeof(sendbuf) - 1] = 0;
        size_t len = strlen(sendbuf);

        if ((size_t)wolfSSL_write(ssl, sendbuf, len) != len)
            fprintf(stderr, "ERROR: failed to write\n");

        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(connd);
    }

    close(sockfd);

    if (ctx)
        wolfSSL_CTX_free(ctx);

    wolfSSL_Cleanup();

    return EXIT_SUCCESS;
}
