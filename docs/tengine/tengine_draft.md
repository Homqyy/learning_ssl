# Draft of Tengine

initialize process:

```text
```

initialize vitual server

```text
ngx_http_ssl_merge_srv_conf
    ngx_ssl_create              # init conf->ssl->ctx and conf->ssl->buffer and so on
        SSL_CTX_new
        SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_server_conf_index, conf)
        SSL_CTX_set_ex_data(ssl->ctx, ngx_ssl_certificate_index, NULL)

        set client side options
        set server side options

        SSL_CTX_set_min_proto_version
        SSL_CTX_set_max_proto_version

        SSL_CTX_set_mode

        # 1. impact SSL_pending
        # 2. if the application wants to continue to use the underlying transport (e.g. TCP connection) after the SSL connection is finished using SSL_shutdown() reading ahead should be turned off.
        # 3. if read ahead is turned on, then SSL_MODE_AUTO_RETRY should also be turned on.
        SSL_CTX_set_read_ahead(ssl->ctx, 1) # impact SSL_pending, and 

        set callback of ssl

        set cleanup to cf->pool         # ngx_ssl_cleanup_ctx

        SSL_CTX_set_tlsext_servername_callback  # set servername callback
        SSL_CTX_set_alpn_select_cb              # set alpn select callback

        ngx_ssl_ciphers

        if (variable certificates)
            SSL_CTX_set_cert_cb                 # lookup certificates for variable certicates
        else if (static certificates)
            ngx_ssl_certificates
        
        if (enc certificate)
            ngx_ssl_certificate(enc)

        if (verify)
            ngx_ssl_client_certificate          # verify

        ngx_ssl_trusted_certificate             # CA
        ngx_ssl_crl                             # crl

        if (ocsp)
            ngx_ssl_ocsp

        ngx_ssl_dhparam                         # init dh param
        ngx_ssl_ecdh_curve                      # init ecdh curve
        ngx_ssl_session_cache
        ngx_ssl_session_ticket_keys

        if (stapling)
            ngx_ssl_stapling

        ngx_ssl_early_data
        ngx_ssl_conf_commands
```

process:

```text
ngx_http_init_connection
    ngx_http_ssl_handshake
        ngx_ssl_handshake
            SSL_do_handshake
            if (rc = 1) 
                ngx_ssl_async_process_fds
                c->recv = ngx_ssl_recv
                c->send = ngx_ssl_write
                c->recv_chain = ngx_ssl_recv_chain
                c->send_chain = ngx_ssl_send_chain
            else if (sslerr == SSL_ERROR_WANT_READ)
                ngx_ssl_async_process_fds

                c->read->handler = ngx_ssl_handshake_handler
                c->write->handler = ngx_ssl_handshake_handler
            else if (sslerr == SSL_ERROR_WANT_WRITE)
                ngx_ssl_async_process_fds

                c->read->handler = ngx_ssl_handshake_handler
                c->write->handler = ngx_ssl_handshake_handler
            else if (sslerr == SSL_ERROR_WANT_ASYNC)
                c->async->handler = ngx_ssl_handshake_async_handler
                c->read->save_handler = c->read->handler
                c->read->handler = ngx_ssl_empty_handler
                ngx_ssl_async_process_fds
            else
                error handler

    ngx_http_ssl_handshake_handler      # c->ssl->handler
        ngx_http_wait_request_handler
```

`c->async` as a async event, `c->async->handler` is a event handler that will be called when `c->async_fd` is ready.

`ngx_ssl_async_process_fds` will add `c->async_fd` to epoll or delete `c->async_fd` from epoll.

have a alone async process in `ngx_epoll_process_events`, in other words, only running one of normal event branch and async event branch.

i known `ngx_ssl_handshake_async_handler` is a async event handler, so we can look at `ngx_ssl_handshake_async_handler`:

```c
static void
ngx_ssl_handshake_async_handler(ngx_event_t *aev)
{
    ngx_connection_t  *c;

    c = aev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL handshake async handler");

    aev->ready = 0;
    aev->handler = ngx_ssl_empty_handler;
    c->read->handler = c->read->saved_handler;

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
        return;
    }

    c->ssl->handler(c);
}
```

Again invoke `ngx_ssl_handshake`, and `ngx_ssl_handshake` will invoke `SSL_do_handshake` again.

This is different, `aev->handler = ngx_ssl_empty_handler`. Has some comment in code(ngx_event_openssl.c: 25532,2558):

```c
    /*
     * empty the handler of async event to avoid
     * going back to previous ssl handshake state
     */
    c->async->handler = ngx_ssl_empty_handler;
```

My understanded is:

    - The `async->handler` is waiting that async engine is complete. If `c->async->hadler` was be callback, then should be set `c->aev->handler` to `ngx_ssl_empty_handler` to avoid going back to previous ssl handshake state, because other async fd may be ready and should go normal event handler.

Next, we can look at `ngx_ssl_recv` and `ngx_ssl_write`:

## Problems

<!-- 何时返回 SSL_ERROR_WANT_ASYNC，并且该如何处理它？这里需要深入展开 -->
- When to return SSL_ERROR_WANT_ASYNC, and how to deal with it? This needs to be expanded in depth.
