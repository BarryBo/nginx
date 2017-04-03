/*
 * Copyright (C) Microsoft Corp
 */

#ifndef _MITLS_OPENSSLCOMPAT_H_INCLUDED_
#define _MITLS_OPENSSLCOMPAT_H_INCLUDED_

typedef void (*mitls_info_callback)(const ngx_ssl_conn_t *ssl, int type, int val);
typedef int (*mitls_verify_callback)(int, X509_STORE_CTX *);
typedef int (*mitls_pem_password_cb)(char *buf, int size, int rwflag, void *u);
typedef int (*mitls_new_session_cb)(ngx_ssl_conn_t *ssl, mitls_session *sess);
typedef void (*mitls_remove_session_cb)(mitls_context *ctx, mitls_session *sess);
typedef mitls_session *(*mitls_get_session_cb)(ngx_ssl_conn_t *ssl, unsigned char *data,
               int len, int *copy);
typedef int (*mitls_tlsext_ticket_key_cb)(ngx_ssl_conn_t *s, unsigned char key_name[16],
                  unsigned char iv[EVP_MAX_IV_LENGTH],
                  EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc);

typedef struct _mitls_X509_NAME_stack {
    struct _mitls_X509_NAME_stack *next;
    X509_NAME *x509_name;
} mitls_X509_NAME_stack;

// The miTLS FFI doesn't have a concept of a session yet.
typedef struct _mitls_session {
    int refcount;

    // number of elements in session_data
    size_t session_data_length;

    // dense array of session data.
    struct mitls_session_data *session_data;
} mitls_session;

// Per client connection data
typedef struct _mitls_connection {
    mitls_state *state;  // pointer to the miTLS connection state, managed by the FFI layer
    struct _FFI_mitls_callbacks ffi_callbacks; // callbacks from mitls into this code
    struct _mitls_context *ctx;
    mitls_session *session;
    void **ssl_data;
    int ssl_data_length; // number of elements in the data[] array
    int fd;
    int is_connect_state;
    int error;
    int quiet_shutdown_mode;
    int shutdown;
} mitls_connection;

typedef struct _X509_CHAIN {
    struct _X509_CHAIN  *next;
    X509* x509;
} X509_CHAIN;

typedef struct  _mitls_context {
    int context_data_length; // number of elements in the data[] array
    void **context_data;
    mitls_info_callback cb;
    
    char * cert_chain_file; // name of the .pem file.  Allocated via strdup()
    X509_CHAIN * x509_chain_head; // extra chain certs, newest at the head
    
    EVP_PKEY *privatekey;
    mitls_pem_password_cb default_password_cb;
    void* default_password_userdata;
    char * privatekey_file; // name of the .pem file.  Allocated via strdup()
    int privatekey_type;

    long options; // see mitls_CTX_set_options

    mitls_verify_callback verify_callback;
    int verify_depth;

    int session_cache_mode;
    long session_cache_size;
    mitls_new_session_cb session_new_cb;
    mitls_get_session_cb session_get_cb;
    mitls_remove_session_cb session_remove_cb;
    mitls_tlsext_ticket_key_cb tlsext_ticket_key_cb;

    DH *dh;
    int ecdh_auto;

    long timeout;

    unsigned char sid_ctx[SSL_MAX_SSL_SESSION_ID_LENGTH];
    unsigned int sid_ctx_len;

    const char *tls_version; // a version string compatible with FFI_mitls_configure()
} mitls_context; // equivalent to SSL_CTX


int mitls_CTX_get_ex_new_index(void);
int mitls_get_ex_new_index(void);
int mitls_CTX_set_ex_data(mitls_context *ctx, int idx, void *data);
void *mitls_CTX_get_ex_data(const mitls_context *ctx, int idx);
mitls_context * mitls_create_CTX(const char *tls_version); // The equivalent of SSL_CTX_new(SSLv23_method());
void mitls_CTX_free(mitls_context *ctx);
void mitls_CTX_set_info_callback(mitls_context *ctx, mitls_info_callback cb);
int mitls_CTX_use_certificate_chain_file(mitls_context *ctx, const char *file);
long mitls_CTX_add0_chain_cert(mitls_context *ctx, X509 *x509);
int mitls_CTX_use_PrivateKey(mitls_context *ctx, EVP_PKEY *pkey);
void mitls_CTX_set_default_passwd_cb(mitls_context *ctx, mitls_pem_password_cb cb);
void mitls_CTX_set_default_passwd_cb_userdata(mitls_context *ctx, void *u);
int mitls_CTX_use_PrivateKey_file(mitls_context *ctx, const char *file, int type);
int mitls_CTX_set_cipher_list(mitls_context *ctx, const char *str);
long mitls_CTX_set_options(mitls_context *ctx, long options);
void mitls_CTX_set_verify(mitls_context *ctx, int mode, mitls_verify_callback verify_callback);
void mitls_CTX_set_verify_depth(mitls_context *ctx,int depth);
int mitls_CTX_load_verify_locations(mitls_context *ctx, const char *CAfile,
                                   const char *CApath);
void mitls_CTX_set_client_CA_list(mitls_context *ctx, mitls_X509_NAME_stack *list);
X509_STORE *mitls_CTX_get_cert_store(const mitls_context *ctx);
long mitls_CTX_set_session_cache_mode(mitls_context *ctx, long mode);
long mitls_CTX_sess_set_cache_size(mitls_context *ctx, long t);
void mitls_CTX_sess_set_new_cb(mitls_context *ctx,
                              mitls_new_session_cb new_session_cb);
void mitls_CTX_sess_set_get_cb(mitls_context *ctx,
           mitls_get_session_cb get_session_cb);
void mitls_CTX_sess_set_remove_cb(mitls_context *ctx,
           mitls_remove_session_cb remove_session_cb);
mitls_X509_NAME_stack *mitls_CTX_get_client_CA_list(const mitls_context *ctx);
mitls_X509_NAME_stack *mitls_load_client_CA_file(const char *file);
int mitls_CTX_set_session_id_context(mitls_context *ctx, const unsigned char *sid_ctx,
                                    unsigned int sid_ctx_len);
int mitls_CTX_remove_session(mitls_context *ctx, mitls_session *c);
long mitls_CTX_set_tmp_dh(mitls_context *ctx, DH *dh);
int mitls_CTX_set1_curves_list(mitls_context *ctx, char *list);
int mitls_CTX_set_ecdh_auto(mitls_context *ctx, int onoff);
long mitls_CTX_set_timeout(mitls_context *ctx, long t);
long mitls_CTX_get_timeout(mitls_context *ctx);
mitls_connection * mitls_new(mitls_context *ctx);
void mitls_free(mitls_connection *ssl);
int mitls_set_fd(mitls_connection *ssl, int fd);
int mitls_set_ex_data(mitls_connection *ssl, int idx, void *arg);
void mitls_set_connect_state(mitls_connection *ssl);
void mitls_set_accept_state(mitls_connection *ssl);
int mitls_set_session(mitls_connection *ssl, mitls_session *session);
int mitls_do_handshake(mitls_connection *ssl);
SSL_CIPHER *mitls_get_current_cipher(mitls_connection *ssl);
const SSL_CIPHER *mitls_CIPHER_find(mitls_connection *ssl, const unsigned char *ptr);
const char *mitls_get_cipher_name(const mitls_connection *s);
const char *mitls_CIPHER_get_name(const SSL_CIPHER *cipher);
char *mitls_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int size);
int mitls_get_error(const mitls_connection *ssl, int ret);
const char *mitls_get_version(const mitls_connection *ssl); 
int mitls_session_reused(mitls_connection *ssl);  // Note: This is only called from debugging code.
int mitls_read(mitls_connection *ssl, void *buf, int num);
int mitls_write(mitls_connection *ssl, const void *buf, int num);
void mitls_set_quiet_shutdown(mitls_connection *ssl, int mode);
void mitls_set_shutdown(mitls_connection *ssl, int mode);
int mitls_get_shutdown(const mitls_connection *ssl);
int mitls_shutdown(mitls_connection *ssl);
int mitls_i2d_SSL_SESSION(mitls_session *in, unsigned char **pp);
mitls_session *mitls_d2i_SSL_SESSION(mitls_session **a, const unsigned char **pp, long length);
const unsigned char *mitls_SESSION_get_id(const mitls_session *s,
                                        unsigned int *len);
long mitls_CTX_set_tlsext_ticket_key_cb(mitls_context *sslctx, mitls_tlsext_ticket_key_cb cb);
X509 *mitls_get_peer_certificate(const mitls_connection *ssl);
long mitls_get0_raw_cipherlist(mitls_connection *ssl, unsigned char **plst); // In OpenSSL, this is a macro on top of SSL_ctrl()
long mitls_get1_curves(mitls_connection *ssl, int*s); // In OpenSSL, this is a macro on top of SSL_ctrl()
mitls_session *mitls_get_session(const mitls_connection *ssl);
mitls_session *mitls_get0_session(const mitls_connection *ssl);
mitls_session *mitls_get1_session(mitls_connection *ssl);
const char  *mitls_get_servername(const mitls_connection *ssl, const int type);
long mitls_get_verify_result(const mitls_connection *ssl);
int mitls_get_ex_data_X509_STORE_CTX_idx(void);

#endif // _MITLS_OPENSSLCOMPAT_H_INCLUDED_
