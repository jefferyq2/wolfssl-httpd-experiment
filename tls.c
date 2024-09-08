#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

WOLFSSL_CTX *tls_setup(const char *cert_file, const char *key_file) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return NULL;
    }

    /* Load server certificates into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_file(ctx, cert_file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", cert_file);
        return NULL;
    }

    /* Load server key into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", key_file);
        return NULL;
    }

    return ctx;
}

WOLFSSL *tls_attach(WOLFSSL_CTX *ctx, int connd) {
    // Create new wolfSSL session.
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        return NULL;
    }

    // Attach wolfSSL session to the socket
    wolfSSL_set_fd(ssl, connd);

    // Establish TLS connection
    int err = wolfSSL_accept(ssl);
    if (err != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_accept error = %d\n",
                wolfSSL_get_error(ssl, err));
        wolfSSL_free(ssl);
        return NULL;
    }

    return ssl;
}
