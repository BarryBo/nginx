
/*
 * Copyright (C) Microsoft Corp
 */
 
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#undef d2i_SSL_SESSION
#undef i2d_SSL_SESSION
#include <openssl/ssl.h>
#include "mitls_opensslcompat.h"

#define max(a, b)  (((a) > (b)) ? (a) : (b)) 

static int mitls_context_data_length;
static int mitls_ssl_data_length;

int mitls_CTX_get_ex_new_index(void)
{
    return mitls_context_data_length++;
}

int mitls_get_ex_new_index(void)
{
    return mitls_ssl_data_length++;
}

int mitls_CTX_set_ex_data(mitls_context *ctx, int idx, void *data)
{
    if (idx < 0 || idx >= mitls_context_data_length) {
        return 0; // index is out of range
    }
    if (idx >= ctx->context_data_length) { // index is past the end of what we have locally allocated
        size_t numbytes = mitls_context_data_length*sizeof(void*);
        void** new_context_data = (void**)malloc(numbytes);
        if (new_context_data == NULL) {
            return 0; // out of memory
        }
        // Zero-fill the entire buffer
        memset(new_context_data, 0, numbytes);
        // Copy in the old data
        memcpy(new_context_data, ctx->context_data, ctx->context_data_length*sizeof(void*));
        free(ctx->context_data);
        ctx->context_data = new_context_data;
        ctx->context_data_length = mitls_context_data_length;
    }
    ctx->context_data[idx] = data;
    return 1; // success
}

void *mitls_CTX_get_ex_data(const mitls_context *ctx, int idx)
{
    if (idx < 0 || idx >= mitls_context_data_length) {
        return NULL; // index is out of range
    }
    else if (idx >= ctx->context_data_length) { // index is past the end of what we have locally allocated
        return NULL;
    } else {
        return ctx->context_data[idx];
    }
}

// The equivalent of SSL_CTX_new(SSLv23_method());
mitls_context * mitls_create_CTX(void)
{
    size_t numbytes;
    
    mitls_context * ctx = malloc(sizeof(mitls_context));
    if (ctx == NULL) {
        return NULL;
    }
    memset(ctx, 0, sizeof(*ctx)); // zero-fill to begin with
    ctx->context_data_length = max(mitls_context_data_length, 2); // preallocate space for at least two slots
    numbytes = ctx->context_data_length*sizeof(void*);
    ctx->context_data = (void**)malloc(numbytes);
    if (ctx->context_data == NULL) {
        free(ctx);
        return NULL;
    }
    memset(ctx->context_data, 0, numbytes);
    ctx->session_cache_size = 1024*20;
    ctx->timeout = 300; // default to 300 seconds for a timeout
    return ctx;
}

void mitls_CTX_free(mitls_context *ctx)
{
    // bugbug: release other data, like the X509 pointer
    free(ctx->context_data);
    free(ctx);
}

void mitls_CTX_set_info_callback(mitls_context *ctx, mitls_info_callback cb)
{
    ctx->cb = cb;
}

int mitls_CTX_use_certificate(mitls_context *ctx, X509 *x509)
{
    if (ctx->x509) {
        X509_free(ctx->x509);
        ctx->x509 = NULL;
    }
    // bugbug: should this make a copy of the cert?
    ctx->x509 = x509;
    return 1;
}

long mitls_CTX_add0_chain_cert(mitls_context *ctx, X509 *x509)
{
    X509_CHAIN *c = malloc(sizeof(X509_CHAIN));
    if (c == NULL) {
        return 0;
    }
    c->x509 = x509;
    c->next = ctx->x509_chain_head;
    ctx->x509_chain_head = c;
    return 0;
}

int mitls_CTX_use_PrivateKey(mitls_context *ctx, EVP_PKEY *pkey)
{
    if (ctx->privatekey) {
        EVP_PKEY_free(ctx->privatekey);
        ctx->privatekey = NULL;
    }
    ctx->privatekey = pkey;
    return 1;
}

void mitls_CTX_set_default_passwd_cb(mitls_context *ctx, mitls_pem_password_cb cb)
{
    ctx->default_password_cb = cb;
}

void mitls_CTX_set_default_passwd_cb_userdata(mitls_context *ctx, void *u)
{
    ctx->default_password_userdata = u;
}

int mitls_CTX_use_PrivateKey_file(mitls_context *ctx, const char *file, int type)
{
    // bugbug: should this greedily open the file and read the key out?  Or delay until first use?
    ctx->privatekey_file = file;
    ctx->privatekey_type = type;
    return 1;
}

int mitls_CTX_set_cipher_list(mitls_context *ctx, const char *str)
{
    // bugbug: parse the cipher list immediately.
    return 1;
}

long mitls_CTX_set_options(mitls_context *ctx, long options)
{
    ctx->options |= options;
    return ctx->options; // return the new options
}

void mitls_CTX_set_verify(mitls_context *ctx, int mode, mitls_verify_callback verify_callback)
{
    ctx->verify_callback = verify_callback;
}

void mitls_CTX_set_verify_depth(mitls_context *ctx,int depth)
{
    ctx->verify_depth = depth;
}
 
int mitls_CTX_load_verify_locations(mitls_context *ctx, const char *CAfile,
                                   const char *CApath)
{
    // bugbug: implement
    return 1;
}

void mitls_CTX_set_client_CA_list(mitls_context *ctx, STACK_OF(X509_NAME) *list)
{
    // bugbug: implement
}

X509_STORE *mitls_CTX_get_cert_store(const mitls_context *ctx)
{
    // bugbug: implement
    return NULL;
}

long mitls_CTX_set_session_cache_mode(mitls_context *ctx, long mode)
{
    long oldmode = ctx->session_cache_mode;
    ctx->session_cache_mode = mode;
    return oldmode;
}

long mitls_CTX_sess_set_cache_size(mitls_context *ctx, long t)
{
    long oldsize = ctx->session_cache_size;
    ctx->session_cache_size = t;
    return oldsize;
}

void mitls_CTX_sess_set_new_cb(mitls_context *ctx,
                              mitls_new_session_cb new_session_cb)
{
    ctx->session_new_cb = new_session_cb;
}

void mitls_CTX_sess_set_get_cb(mitls_context *ctx,
           mitls_get_session_cb get_session_cb)
{
    ctx->session_get_cb = get_session_cb;
}

void mitls_CTX_sess_set_remove_cb(mitls_context *ctx,
           mitls_remove_session_cb remove_session_cb)
{
    ctx->session_remove_cb = remove_session_cb;
}
 
STACK_OF(X509_NAME) *mitls_CTX_get_client_CA_list(const mitls_context *ctx)
{
    // bugbug: implement
    return NULL;
}
 
int mitls_CTX_set_session_id_context(mitls_context *ctx, const unsigned char *sid_ctx,
                                    unsigned int sid_ctx_len)
{
    // bugbug: implement
    return 0;
}

int mitls_CTX_remove_session(mitls_context *ctx, mitls_session *c)
{
    // bugbug: implement
    return 0;
}

long mitls_CTX_set_tmp_dh(mitls_context *ctx, DH *dh)
{
    // bugbug: free the old DH
    ctx->dh = dh;
    return 1;
}

int mitls_CTX_set1_curves_list(mitls_context *ctx, char *list)
{
    // bugbug: parse the curves list up-front
    return 1;
}

 // In OpenSSL, this is a macro on top of SSL_ctrl()
long mitls_get1_curves(mitls_connection *ssl, int*s)
{
    // bugbug: implement
    return 0;
}

int mitls_CTX_set_ecdh_auto(mitls_context *ctx, int onoff)
{
    ctx->ecdh_auto = onoff;
    return 1;
}

long mitls_CTX_set_timeout(mitls_context *ctx, long t)
{
    long previous = ctx->timeout;
    ctx->timeout = t;
    return previous;
}

long mitls_CTX_get_timeout(mitls_context *ctx)
{
    return ctx->timeout;
}

mitls_connection * mitls_new(mitls_context *ctx)
{
    int numbytes;
    
    mitls_connection *c = (mitls_connection*)malloc(sizeof(mitls_connection));
    if (c == NULL) {
        return NULL;
    }
    memset(c, 0, sizeof(*c)); // zero-initialize all fields by default
    
    c->ssl_data_length = max(mitls_ssl_data_length, 1); // preallocate space for at least one slot
    numbytes = c->ssl_data_length*sizeof(void*);
    c->ssl_data = (void**)malloc(numbytes);
    if (c->ssl_data == NULL) {
        free(c);
        return NULL;
    }
    memset(c->ssl_data, 0, numbytes);
    // bugbug: SSL_new inherits the ctx settings.  We are simply holding a pointer to them.  Is that safe/correct?
    c->ctx = ctx;
    return c;
}

void mitls_free(mitls_connection *ssl)
{
    // bugbug: clean up the other fields
    if (ssl->state) {
        FFI_mitls_close(ssl->state);
    }
    free(ssl->ssl_data);
    free(ssl);
}
 
int mitls_set_fd(mitls_connection *ssl, int fd)
{
    ssl->fd = fd;
    return 1;
}

int mitls_set_ex_data(mitls_connection *ssl, int idx, void *arg)
{
    if (idx < 0 || idx >= mitls_ssl_data_length) {
        return 0; // index is out of range
    }
    if (idx >= ssl->ssl_data_length) { // index is past the end of what we have locally allocated
        size_t numbytes = mitls_ssl_data_length*sizeof(void*);
        void** new_ssl_data = (void**)malloc(numbytes);
        if (new_ssl_data == NULL) {
            return 0; // out of memory
        }
        // Zero-fill the entire buffer
        memset(new_ssl_data, 0, numbytes);
        // Copy in the old data
        memcpy(new_ssl_data, ssl->ssl_data, ssl->ssl_data_length*sizeof(void*));
        free(ssl->ssl_data);
        ssl->ssl_data = new_ssl_data;
        ssl->ssl_data_length = mitls_ssl_data_length;
    }
    ssl->ssl_data[idx] = arg;
    return 1; // success
}

void mitls_set_connect_state(mitls_connection *ssl)
{
    ssl->is_connect_state = 1;
}

void mitls_set_accept_state(mitls_connection *ssl)
{
    ssl->is_connect_state = 0;
}

int mitls_set_session(mitls_connection *ssl, mitls_session *session)
{
    ssl->session = session;
    return 1;
}

int mitls_do_handshake(mitls_connection *ssl)
{
    // bugbug: implement
    ssl->error = SSL_ERROR_SSL;
    return -1;
}

SSL_CIPHER *mitls_get_current_cipher(mitls_connection *ssl)
{
    // bugbug: implement
    return NULL;
}

const SSL_CIPHER *mitls_CIPHER_find(mitls_connection *ssl, const unsigned char *ptr)
{
    // bugbug: implement
    return NULL;
}

const char *mitls_get_cipher_name(const mitls_connection *s)
{
    // bugbug: implement
    return NULL;
}

const char *mitls_CIPHER_get_name(const SSL_CIPHER *cipher)
{
    // bugbug: implement
    return NULL;
}

char *mitls_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int size)
{
    if (size < 128) {
        return "Buffer too small";
    }
    if (buf == NULL) {
        size = 128;
        buf = OPENSSL_malloc(size);
        if (buf == NULL) {
            return "OPENSSL_malloc Error";
        }
    }
    memset(buf, 0, size);
    // bugbug: fill in with data
    return buf;
}

int mitls_get_error(const mitls_connection *ssl, int ret)
{
    // ret is the last return from a call to a mitls_*() API
    if (ret > 0) {
        return SSL_ERROR_NONE;
    }
    return ssl->error;
}

const char *mitls_get_version(const mitls_connection *ssl)
{
    // bugbug: add TLS 1.3 support and "unknown" return
    return "TLSv1.2";
}

// Note: This is only called from debugging code.
int mitls_session_reused(mitls_connection *ssl)
{
    // bugbug: report whether a reused session was negotiated during the handshake
    return 0;
}

int mitls_read(mitls_connection *ssl, void *buf, int num)
{
    // bugbug: implement
    ssl->error = SSL_ERROR_SSL;
    return -1;
}

int mitls_write(mitls_connection *ssl, const void *buf, int num)
{
    // bugbug: implement
    ssl->error = SSL_ERROR_SSL;
    return -1;
}

int mitls_in_init(mitls_connection *ssl)
{
    // bugbug: implement
    return 0;
}

void mitls_set_quiet_shutdown(mitls_connection *ssl, int mode)
{
    ssl->quiet_shutdown_mode = mode;
}

void mitls_set_shutdown(mitls_connection *ssl, int mode)
{
    ssl->shutdown = mode;
}

int mitls_get_shutdown(const mitls_connection *ssl)
{
    return ssl->shutdown;
}

int mitls_shutdown(mitls_connection *ssl)
{
    // bugbug: implement
    return 1;
}

int mitls_i2d_SSL_SESSION(mitls_session *in, unsigned char **pp)
{
    // bugbug: implement.  Serialize the session in ASN1 format.
    if (pp) {
        *pp = NULL;
    }
    return 0;
}

mitls_session *mitls_d2i_SSL_SESSION(mitls_session **a, const unsigned char **pp, long length)
{
    // bugbug: implement.  Deserialize from ASN1 format
    return NULL;
}
 

const unsigned char *mitls_SESSION_get_id(const mitls_session *s,
                                        unsigned int *len)
{
    // bugbug: implement
    *len = 0;
    return NULL;
}

long mitls_CTX_set_tlsext_ticket_key_cb(mitls_context *sslctx, mitls_tlsext_ticket_key_cb cb)
{
    sslctx->tlsext_ticket_key_cb = cb;
    return 0;
}

X509 *mitls_get_peer_certificate(const mitls_connection *ssl)
{
    // bugbug: implement
    return NULL;
}

// In OpenSSL, this is a macro on top of SSL_ctrl()
long mitls_get0_raw_cipherlist(mitls_connection *ssl, unsigned char **plst)
{
    // bugbug: implement
    return 0;
}

mitls_session *mitls_get_session(const mitls_connection *ssl)
{
    // bugbug: implement
    return NULL;
}

mitls_session *mitls_get0_session(const mitls_connection *ssl)
{
    return mitls_get_session(ssl);
}

mitls_session *mitls_get1_session(mitls_connection *ssl)
{
    // bugbug: implement
    return NULL;
}

const char  *mitls_get_servername(const mitls_connection *ssl, const int type)
{
    // bugbug: implement
    return NULL;
}

long mitls_get_verify_result(const mitls_connection *ssl)
{
    // bugbug: implement
    return X509_V_OK;
}

int mitls_get_ex_data_X509_STORE_CTX_idx(void)
{
    // bugbug: implement
    return 0;
}
