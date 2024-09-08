#include "existing.h"

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

WOLFSSL_CTX *tls_setup(void) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return NULL;
    }

    /* Load server certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        return NULL;
    }

    /* Load server key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                KEY_FILE);
        return NULL;
    }

    return ctx;
}


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

        // Create new wolfSSL session.
        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            close(connd);
            continue;
        }

        // Attach wolfSSL session to the socket
        wolfSSL_set_fd(ssl, connd);

        // Establish TLS connection
        int err = wolfSSL_accept(ssl);
        if (err != WOLFSSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_accept error = %d\n",
                wolfSSL_get_error(ssl, err));
            wolfSSL_free(ssl);
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
