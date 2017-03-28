
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
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (idx < 0 || idx >= mitls_context_data_length) {
        ngx_log_stderr(EINVAL, "Leave: %s", __FUNCTION__);
        return 0; // index is out of range
    }
    if (idx >= ctx->context_data_length) { // index is past the end of what we have locally allocated
        size_t numbytes = mitls_context_data_length*sizeof(void*);
        void** new_context_data = (void**)malloc(numbytes);
        if (new_context_data == NULL) {
            ngx_log_stderr(ENOMEM, "Leave: %s", __FUNCTION__);
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
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1; // success
}

void *mitls_CTX_get_ex_data(const mitls_context *ctx, int idx)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (idx < 0 || idx >= mitls_context_data_length) {
        ngx_log_stderr(EINVAL, "Leave: %s", __FUNCTION__);
        return NULL; // index is out of range
    }
    else if (idx >= ctx->context_data_length) { // index is past the end of what we have locally allocated
        ngx_log_stderr(0, "Leave: %s slot is empty", __FUNCTION__);
        return NULL;
    } else {
        ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
        return ctx->context_data[idx];
    }
}

// The equivalent of SSL_CTX_new(SSLv23_method());
mitls_context * mitls_create_CTX(void)
{
    size_t numbytes;
    
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    mitls_context * ctx = malloc(sizeof(mitls_context));
    if (ctx == NULL) {
        ngx_log_stderr(ENOMEM, "Leave: %s", __FUNCTION__);
        return NULL;
    }
    memset(ctx, 0, sizeof(*ctx)); // zero-fill to begin with
    ctx->context_data_length = max(mitls_context_data_length, 2); // preallocate space for at least two slots
    numbytes = ctx->context_data_length*sizeof(void*);
    ctx->context_data = (void**)malloc(numbytes);
    if (ctx->context_data == NULL) {
        free(ctx);
        ngx_log_stderr(ENOMEM, "Leave: %s", __FUNCTION__);
        return NULL;
    }
    memset(ctx->context_data, 0, numbytes);
    ctx->session_cache_size = 1024*20;
    ctx->timeout = 300; // default to 300 seconds for a timeout
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return ctx;
}

void mitls_CTX_free(mitls_context *ctx)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    
    // bugbug: release other data, like the X509 pointer
    free(ctx->context_data);
    free(ctx);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

void mitls_CTX_set_info_callback(mitls_context *ctx, mitls_info_callback cb)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->cb = cb;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

int mitls_CTX_use_certificate(mitls_context *ctx, X509 *x509)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (ctx->x509) {
        X509_free(ctx->x509);
        ctx->x509 = NULL;
    }
    // bugbug: should this make a copy of the cert?
    ctx->x509 = x509;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

long mitls_CTX_add0_chain_cert(mitls_context *ctx, X509 *x509)
{
    X509_CHAIN *c = malloc(sizeof(X509_CHAIN));
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (c == NULL) {
        ngx_log_stderr(0, "Leave: %s out of memory", __FUNCTION__);
        return 0;
    }
    c->x509 = x509;
    c->next = ctx->x509_chain_head;
    ctx->x509_chain_head = c;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

int mitls_CTX_use_PrivateKey(mitls_context *ctx, EVP_PKEY *pkey)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (ctx->privatekey) {
        EVP_PKEY_free(ctx->privatekey);
        ctx->privatekey = NULL;
    }
    ctx->privatekey = pkey;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

void mitls_CTX_set_default_passwd_cb(mitls_context *ctx, mitls_pem_password_cb cb)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->default_password_cb = cb;
}

void mitls_CTX_set_default_passwd_cb_userdata(mitls_context *ctx, void *u)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->default_password_userdata = u;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

int mitls_CTX_use_PrivateKey_file(mitls_context *ctx, const char *file, int type)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: should this greedily open the file and read the key out?  Or delay until first use?
    ctx->privatekey_file = file;
    ctx->privatekey_type = type;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

int mitls_CTX_set_cipher_list(mitls_context *ctx, const char *str)
{
    // https://www.openssl.org/docs/man1.0.1/apps/ciphers.html documents the cipher list
    // format.  Strings separated by colons.  nginx passes "HIGH:!aNULL:!MD5" by default.
    ngx_log_stderr(0, "Enter: %s: list=%s", __FUNCTION__, str);
    // bugbug: parse the cipher list immediately and communicate the choices to miTLS.
    //               for now, doing nothing is OK.
    ngx_log_stderr(0, "%s not implemented but OK", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

long mitls_CTX_set_options(mitls_context *ctx, long options)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->options |= options;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return ctx->options; // return the new options
}

void mitls_CTX_set_verify(mitls_context *ctx, int mode, mitls_verify_callback verify_callback)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->verify_callback = verify_callback;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

void mitls_CTX_set_verify_depth(mitls_context *ctx,int depth)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->verify_depth = depth;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}
 
int mitls_CTX_load_verify_locations(mitls_context *ctx, const char *CAfile,
                                   const char *CApath)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

void mitls_CTX_set_client_CA_list(mitls_context *ctx, STACK_OF(X509_NAME) *list)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

X509_STORE *mitls_CTX_get_cert_store(const mitls_context *ctx)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

long mitls_CTX_set_session_cache_mode(mitls_context *ctx, long mode)
{
    long oldmode = ctx->session_cache_mode;
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->session_cache_mode = mode;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return oldmode;
}

long mitls_CTX_sess_set_cache_size(mitls_context *ctx, long t)
{
    long oldsize = ctx->session_cache_size;
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->session_cache_size = t;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return oldsize;
}

void mitls_CTX_sess_set_new_cb(mitls_context *ctx,
                              mitls_new_session_cb new_session_cb)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->session_new_cb = new_session_cb;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

void mitls_CTX_sess_set_get_cb(mitls_context *ctx,
           mitls_get_session_cb get_session_cb)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->session_get_cb = get_session_cb;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

void mitls_CTX_sess_set_remove_cb(mitls_context *ctx,
           mitls_remove_session_cb remove_session_cb)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->session_remove_cb = remove_session_cb;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}
 
STACK_OF(X509_NAME) *mitls_CTX_get_client_CA_list(const mitls_context *ctx)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(0, "%s not implemented but OK", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

STACK_OF(X509_NAME) *mitls_load_client_CA_file(const char *file)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

int mitls_CTX_set_session_id_context(mitls_context *ctx, const unsigned char *sid_ctx,
                                    unsigned int sid_ctx_len)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (sid_ctx_len >= SSL_MAX_SSL_SESSION_ID_LENGTH) {
        ngx_log_stderr(EINVAL, "Leave: %s", __FUNCTION__);
        return 0;
    }
    ctx->sid_ctx_len = sid_ctx_len;
    memcpy(ctx->sid_ctx, sid_ctx, sid_ctx_len);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

int mitls_CTX_remove_session(mitls_context *ctx, mitls_session *c)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

long mitls_CTX_set_tmp_dh(mitls_context *ctx, DH *dh)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: free the old DH
    ctx->dh = dh;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

int mitls_CTX_set1_curves_list(mitls_context *ctx, char *list)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: parse the curves list up-front
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

 // In OpenSSL, this is a macro on top of SSL_ctrl()
long mitls_get1_curves(mitls_connection *ssl, int*s)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

int mitls_CTX_set_ecdh_auto(mitls_context *ctx, int onoff)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ctx->ecdh_auto = onoff;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

long mitls_CTX_set_timeout(mitls_context *ctx, long t)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    long previous = ctx->timeout;
    ctx->timeout = t;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return previous;
}

long mitls_CTX_get_timeout(mitls_context *ctx)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return ctx->timeout;
}

mitls_connection * mitls_new(mitls_context *ctx)
{
    int numbytes;
    
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    mitls_connection *c = (mitls_connection*)malloc(sizeof(mitls_connection));
    if (c == NULL) {
        ngx_log_stderr(0, "Leave: %s out of memory", __FUNCTION__);
        return NULL;
    }
    memset(c, 0, sizeof(*c)); // zero-initialize all fields by default
    
    c->ssl_data_length = max(mitls_ssl_data_length, 1); // preallocate space for at least one slot
    numbytes = c->ssl_data_length*sizeof(void*);
    c->ssl_data = (void**)malloc(numbytes);
    if (c->ssl_data == NULL) {
        free(c);
        ngx_log_stderr(0, "Leave: %s out of memory", __FUNCTION__);
        return NULL;
    }
    memset(c->ssl_data, 0, numbytes);
    // bugbug: SSL_new inherits the ctx settings.  We are simply holding a pointer to them.  Is that safe/correct?
    c->ctx = ctx;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return c;
}

void mitls_free(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: clean up the other fields
    if (ssl->state) {
        FFI_mitls_close(ssl->state);
    }
    free(ssl->ssl_data);
    free(ssl);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}
 
int mitls_set_fd(mitls_connection *ssl, int fd)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ssl->fd = fd;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

int mitls_set_ex_data(mitls_connection *ssl, int idx, void *arg)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (idx < 0 || idx >= mitls_ssl_data_length) {
        ngx_log_stderr(0, "Leave: %s bad idx", __FUNCTION__);
        return 0; // index is out of range
    }
    if (idx >= ssl->ssl_data_length) { // index is past the end of what we have locally allocated
        size_t numbytes = mitls_ssl_data_length*sizeof(void*);
        void** new_ssl_data = (void**)malloc(numbytes);
        if (new_ssl_data == NULL) {
            ngx_log_stderr(0, "Leave: %s out of memory", __FUNCTION__);
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
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1; // success
}

void mitls_set_connect_state(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ssl->is_connect_state = 1;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

void mitls_set_accept_state(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ssl->is_connect_state = 0;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

int mitls_set_session(mitls_connection *ssl, mitls_session *session)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ssl->session = session;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

int mitls_do_handshake(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ssl->error = SSL_ERROR_SSL;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return -1;
}

SSL_CIPHER *mitls_get_current_cipher(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

const SSL_CIPHER *mitls_CIPHER_find(mitls_connection *ssl, const unsigned char *ptr)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

const char *mitls_get_cipher_name(const mitls_connection *s)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

const char *mitls_CIPHER_get_name(const SSL_CIPHER *cipher)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

char *mitls_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int size)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    if (size < 128) {
        ngx_log_stderr(0, "Leave: %s buffer too small", __FUNCTION__);
        return "Buffer too small";
    }
    if (buf == NULL) {
        size = 128;
        buf = OPENSSL_malloc(size);
        if (buf == NULL) {
            ngx_log_stderr(0, "Leave: %s out of memory", __FUNCTION__);
            return "OPENSSL_malloc Error";
        }
    }
    memset(buf, 0, size);
    // bugbug: fill in with data
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return buf;
}

int mitls_get_error(const mitls_connection *ssl, int ret)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // ret is the last return from a call to a mitls_*() API
    if (ret > 0) {
        ngx_log_stderr(0, "Leave: %s no error", __FUNCTION__);
        return SSL_ERROR_NONE;
    }
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return ssl->error;
}

const char *mitls_get_version(const mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: add TLS 1.3 support and "unknown" return
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return "TLSv1.2";
}

// Note: This is only called from debugging code.
int mitls_session_reused(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: report whether a reused session was negotiated during the handshake
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

int mitls_read(mitls_connection *ssl, void *buf, int num)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ssl->error = SSL_ERROR_SSL;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return -1;
}

int mitls_write(mitls_connection *ssl, const void *buf, int num)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ssl->error = SSL_ERROR_SSL;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return -1;
}

int mitls_in_init(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

void mitls_set_quiet_shutdown(mitls_connection *ssl, int mode)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ssl->quiet_shutdown_mode = mode;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

void mitls_set_shutdown(mitls_connection *ssl, int mode)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ssl->shutdown = mode;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
}

int mitls_get_shutdown(const mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return ssl->shutdown;
}

int mitls_shutdown(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 1;
}

int mitls_i2d_SSL_SESSION(mitls_session *in, unsigned char **pp)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement.  Serialize the session in ASN1 format.
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    if (pp) {
        *pp = NULL;
    }
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

mitls_session *mitls_d2i_SSL_SESSION(mitls_session **a, const unsigned char **pp, long length)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement.  Deserialize from ASN1 format
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}
 
const unsigned char *mitls_SESSION_get_id(const mitls_session *s,
                                        unsigned int *len)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    *len = 0;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

long mitls_CTX_set_tlsext_ticket_key_cb(mitls_context *sslctx, mitls_tlsext_ticket_key_cb cb)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    sslctx->tlsext_ticket_key_cb = cb;
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

X509 *mitls_get_peer_certificate(const mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

// In OpenSSL, this is a macro on top of SSL_ctrl()
long mitls_get0_raw_cipherlist(mitls_connection *ssl, unsigned char **plst)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}

mitls_session *mitls_get_session(const mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

mitls_session *mitls_get0_session(const mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return mitls_get_session(ssl);
}

mitls_session *mitls_get1_session(mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

const char  *mitls_get_servername(const mitls_connection *ssl, const int type)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return NULL;
}

long mitls_get_verify_result(const mitls_connection *ssl)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return X509_V_OK;
}

int mitls_get_ex_data_X509_STORE_CTX_idx(void)
{
    ngx_log_stderr(0, "Enter: %s", __FUNCTION__);
    // bugbug: implement
    ngx_log_stderr(ENOSYS, "%s not implemented", __FUNCTION__);
    ngx_log_stderr(0, "Leave: %s", __FUNCTION__);
    return 0;
}
