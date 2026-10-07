
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_module.h>
#include <ngx_http_proxy_v2_session.h>


typedef struct {
    ngx_http_proxy_ctx_t           ctx;

    ngx_http_proxy_v2_session_t   *session;
    ngx_http_proxy_v2_stream_t     stream;

    ngx_event_free_peer_pt         free;
    ngx_event_get_peer_pt          get;

} ngx_http_proxy_v2_ctx_t;


static ngx_int_t ngx_http_proxy_v2_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_body_output_filter(void *data,
    ngx_chain_t *in);
static ngx_int_t ngx_http_proxy_v2_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_process_header_run(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_filter_init(void *data);
static ngx_int_t ngx_http_proxy_v2_body_filter_run(ngx_event_pipe_t *p,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
static ngx_int_t ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_ctx_t *ctx,
    ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_process_frames(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);

static ngx_int_t ngx_http_proxy_v2_parse_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_fragment(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_validate_header_name(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_validate_header_value(ngx_http_request_t *r,
    ngx_str_t *s);
static ngx_int_t ngx_http_proxy_v2_parse_rst_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_send_stream_window_update(
    ngx_http_proxy_v2_stream_t *stream);
static void ngx_http_proxy_v2_resume_read(ngx_http_proxy_v2_ctx_t *ctx);
static ngx_chain_t *ngx_http_proxy_v2_get_buf(
    ngx_http_proxy_v2_stream_t *stream);
static ngx_http_proxy_v2_ctx_t *
    ngx_http_proxy_v2_get_ctx(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_v2_join_session(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_http_proxy_v2_session_t *session);
static ngx_int_t ngx_http_proxy_v2_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_t *u);
static ngx_int_t ngx_http_proxy_v2_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_proxy_v2_restore(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx);
static void ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);

static void ngx_http_proxy_v2_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_v2_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);


static ngx_http_module_t  ngx_http_proxy_v2_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_v2_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_v2_module_ctx,         /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char  ngx_http_proxy_v2_connection_start[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"         /* connection preface */

    "\x00\x00\x12\x04\x00\x00\x00\x00\x00"     /* settings frame */
    "\x00\x01\x00\x00\x00\x00"                 /* header table size */
    "\x00\x02\x00\x00\x00\x00"                 /* disable push */
    "\x00\x04\x7f\xff\xff\xff"                 /* initial window */

    "\x00\x00\x04\x08\x00\x00\x00\x00\x00"     /* window update frame */
    "\x7f\xff\x00\x00";


ngx_int_t
ngx_http_proxy_v2_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_upstream_t         *u;
    ngx_http_upstream_conf_t    *ucf;
    ngx_http_proxy_v2_ctx_t     *ctx;
    ngx_http_proxy_loc_conf_t   *plcf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_proxy_v2_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_proxy_v2_module);

    ngx_http_set_ctx(r, &ctx->ctx, ngx_http_proxy_module);

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
        ctx->ctx.vars = plcf->vars;
        u->schema = plcf->vars.schema;
#if (NGX_HTTP_SSL)
        u->ssl = plcf->ssl;
#endif

    } else {
        if (ngx_http_proxy_eval(r, &ctx->ctx, plcf) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

#if (NGX_HTTP_SSL)
    ngx_str_set(&u->ssl_alpn_protocol, NGX_HTTP_V2_ALPN_PROTO);
#endif

    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_module;

    ucf = ngx_palloc(r->pool, sizeof(ngx_http_upstream_conf_t));
    if (ucf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *ucf = plcf->upstream;

    ucf->limit_rate = NULL;
    ucf->buffering = 1;
    ucf->change_buffering = 0;
    ucf->preserve_output = 1;

#if (NGX_HTTP_CACHE)
    ucf->cache = 0;
#endif

    u->conf = ucf;

    u->create_request = ngx_http_proxy_v2_create_request;
    u->reinit_request = ngx_http_proxy_v2_reinit_request;
    u->process_header = ngx_http_proxy_v2_process_header;
    u->abort_request = ngx_http_proxy_v2_abort_request;
    u->finalize_request = ngx_http_proxy_v2_finalize_request;
    u->init_peer = ngx_http_proxy_v2_init_peer;

    if (plcf->redirects) {
        u->rewrite_redirect = ngx_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths || plcf->cookie_flags) {
        u->rewrite_cookie = ngx_http_proxy_rewrite_cookie;
    }

    u->buffering = 1;

    u->pipe = ngx_pcalloc(r->pool, sizeof(ngx_event_pipe_t));
    if (u->pipe == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = ngx_http_proxy_v2_body_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = ngx_http_proxy_v2_filter_init;

    u->accel = 1;

    /*
     * Stream the client request body straight into DATA frames as it
     * arrives, instead of buffering the whole thing first, when the
     * operator has not disabled it (proxy_request_buffering off) and
     * there is a real body to forward at all -- mirrors the same
     * decision ngx_http_proxy_module.c and ngx_http_grpc_module.c
     * already make for their own non-buffered paths.  Unlike the
     * HTTP/1.x proxy, there is no HTTP/1.1-only restriction here for a
     * chunked client body: HTTP/2 DATA framing has no equivalent of
     * chunked transfer-encoding to represent, an unknown-length body
     * is simply DATA frames terminated by END_STREAM, which this
     * module already builds (see ngx_http_proxy_v2_create_request()'s
     * r->headers_in.chunked && r->reading_body branch, and
     * ngx_http_proxy_v2_body_output_filter()'s incremental
     * accumulation into ctx->stream.in) regardless of how the body
     * arrived.
     */

    if (!plcf->upstream.request_buffering
        && plcf->body_values == NULL
        && plcf->upstream.pass_request_body)
    {
        r->request_body_no_buffering = 1;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_create_request(ngx_http_request_t *r)
{
    u_char                       *p, *tmp, *key_tmp, *val_tmp, *headers_frame,
                                 *headers_end;
    size_t                        len, headers_len, tmp_len,
                                  key_len, val_len, uri_len,
                                  loc_len, body_len;
    uintptr_t                     escape;
    ngx_buf_t                    *b;
    ngx_str_t                     method, host;
    ngx_uint_t                    i, next, unparsed_uri;
    ngx_chain_t                  *cl, *body;
    ngx_list_part_t              *part;
    ngx_table_elt_t              *header;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_script_code_pt       code;
    ngx_http_script_engine_t      e, le;
    ngx_http_proxy_headers_t     *headers;
    ngx_http_proxy_v2_frame_t    *f;
    ngx_http_proxy_loc_conf_t    *plcf;
    ngx_http_script_len_code_pt   lcode;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);

    headers = &plcf->headers;

    if (u->method.len) {
        /* HEAD was changed to GET to cache response */
        method = u->method;

    } else if (plcf->method) {
        if (ngx_http_complex_value(r, plcf->method, &method) != NGX_OK) {
            return NGX_ERROR;
        }

    } else {
        method = r->method_name;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (method.len == 4
        && ngx_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        ctx->ctx.head = 1;
    }

    len = sizeof(ngx_http_proxy_v2_connection_start) - 1
          + sizeof(ngx_http_proxy_v2_frame_t);             /* headers frame */

    headers_len = 0;

    /* :method header */

    if ((method.len == 3 && ngx_strncmp(method.data, "GET", 3) == 0)
        || (method.len == 4 && ngx_strncmp(method.data, "POST", 4) == 0))
    {
        len += 1;
        tmp_len = 0;

    } else {
        if (method.len > NGX_HTTP_V2_MAX_FIELD) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "too long http2 method: \"%V\"", &method);
            return NGX_ERROR;
        }

        len += 1 + NGX_HTTP_V2_INT_OCTETS + method.len;
        tmp_len = method.len;
    }

    /* :scheme header */

    len += 1;

    /* :path header */

    escape = 0;
    loc_len = 0;
    unparsed_uri = 0;

    if (plcf->proxy_lengths && ctx->ctx.vars.uri.len) {
        uri_len = ctx->ctx.vars.uri.len;

    } else if (ctx->ctx.vars.uri.len == 0 && r->valid_unparsed_uri) {
        unparsed_uri = 1;
        uri_len = r->unparsed_uri.len;

    } else {
        loc_len = (r->valid_location && ctx->ctx.vars.uri.len)
                  ? ngx_min(plcf->location.len, r->uri.len) : 0;

        if (r->quoted_uri || r->internal) {
            escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, NGX_ESCAPE_URI);
        }

        uri_len = ctx->ctx.vars.uri.len + r->uri.len - loc_len + escape
                  + sizeof("?") - 1 + r->args.len;
    }

    if (uri_len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "zero length URI to proxy");
        return NGX_ERROR;
    }

    if (uri_len > NGX_HTTP_V2_MAX_FIELD) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "too long http2 URI");
        return NGX_ERROR;
    }

    len += 1 + NGX_HTTP_V2_INT_OCTETS + uri_len;

    if (tmp_len < uri_len) {
        tmp_len = uri_len;
    }

    /* :authority header */

    host.len = 0;
#if (NGX_SUPPRESS_WARN)
    host.data = NULL;
#endif

    if (plcf->host_value
        && ngx_http_complex_value(r, plcf->host_value, &host) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (host.len == 0) {
        host = ctx->ctx.vars.host_header;
    }

    if (host.len > NGX_HTTP_V2_MAX_FIELD) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "too long http2 host: \"%V\"", &host);
        return NGX_ERROR;
    }

    len += 1 + NGX_HTTP_V2_INT_OCTETS + host.len;

    if (tmp_len < host.len) {
        tmp_len = host.len;
    }

    /* other headers */

    ngx_memzero(&le, sizeof(ngx_http_script_engine_t));

    ngx_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    ngx_http_script_flush_no_cacheable_variables(r, headers->flushes);

    body_len = 0;

    if (plcf->body_lengths) {
        le.ip = plcf->body_lengths->elts;
        le.request = r;
        le.flushed = 1;

        while (*(uintptr_t *) le.ip) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
            body_len += lcode(&le);
        }

        ctx->ctx.internal_body_length = body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->ctx.internal_body_length = -1;

    } else {
        ctx->ctx.internal_body_length = r->headers_in.content_length_n;
    }

    le.ip = headers->lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        if (key_len > NGX_HTTP_V2_MAX_FIELD) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "too long http2 header name");
            return NGX_ERROR;
        }

        if (val_len > NGX_HTTP_V2_MAX_FIELD) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "too long http2 header value");
            return NGX_ERROR;
        }

        headers_len += 1 + NGX_HTTP_V2_INT_OCTETS + key_len
                         + NGX_HTTP_V2_INT_OCTETS + val_len;

        if (tmp_len < key_len) {
            tmp_len = key_len;
        }

        if (tmp_len < val_len) {
            tmp_len = val_len;
        }
    }

    len += headers_len;

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            if (header[i].key.len > NGX_HTTP_V2_MAX_FIELD) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "too long http2 header name: \"%V\"",
                              &header[i].key);
                return NGX_ERROR;
            }

            if (header[i].value.len > NGX_HTTP_V2_MAX_FIELD) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "too long http2 header value: \"%V: %V\"",
                              &header[i].key, &header[i].value);
                return NGX_ERROR;
            }

            len += 1 + NGX_HTTP_V2_INT_OCTETS + header[i].key.len
                     + NGX_HTTP_V2_INT_OCTETS + header[i].value.len;

            if (tmp_len < header[i].key.len) {
                tmp_len = header[i].key.len;
            }

            if (tmp_len < header[i].value.len) {
                tmp_len = header[i].value.len;
            }
        }
    }

    /* continuation frames */

    len += sizeof(ngx_http_proxy_v2_frame_t)
           * (len / NGX_HTTP_V2_DEFAULT_FRAME_SIZE);


    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    tmp = ngx_palloc(r->pool, tmp_len * 3);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    key_tmp = tmp + tmp_len;
    val_tmp = tmp + 2 * tmp_len;

    /* connection preface */

    b->last = ngx_copy(b->last, ngx_http_proxy_v2_connection_start,
                       sizeof(ngx_http_proxy_v2_connection_start) - 1);

    /* headers frame */

    headers_frame = b->last;

    f = (ngx_http_proxy_v2_frame_t *) b->last;
    b->last += sizeof(ngx_http_proxy_v2_frame_t);

    f->length_0 = 0;
    f->length_1 = 0;
    f->length_2 = 0;
    f->type = NGX_HTTP_V2_HEADERS_FRAME;
    f->flags = 0;
    f->stream_id_0 = 0;
    f->stream_id_1 = 0;
    f->stream_id_2 = 0;
    f->stream_id_3 = 1;

    if (method.len == 3 && ngx_strncmp(method.data, "GET", 3) == 0) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_GET_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: GET\"");

    } else if (method.len == 4 && ngx_strncmp(method.data, "POST", 4) == 0) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_METHOD_POST_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: POST\"");

    } else {
        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_METHOD_INDEX);
        b->last = ngx_http_v2_write_value(b->last, method.data,
                                          method.len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":method: %V\"", &method);
    }

#if (NGX_HTTP_SSL)
    if (u->ssl) {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTPS_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":scheme: https\"");
    } else
#endif
    {
        *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_SCHEME_HTTP_INDEX);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":scheme: http\"");
    }

    if (plcf->proxy_lengths && ctx->ctx.vars.uri.len) {

        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
        b->last = ngx_http_v2_write_value(b->last, ctx->ctx.vars.uri.data,
                                          ctx->ctx.vars.uri.len, tmp);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":path: %V\"", &ctx->ctx.vars.uri);

    } else if (unparsed_uri) {

        if (r->unparsed_uri.len == 1 && r->unparsed_uri.data[0] == '/') {
            *b->last++ = ngx_http_v2_indexed(NGX_HTTP_V2_PATH_ROOT_INDEX);

        } else {
            *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
            b->last = ngx_http_v2_write_value(b->last, r->unparsed_uri.data,
                                              r->unparsed_uri.len, tmp);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":path: %V\"", &r->unparsed_uri);

    } else {
        p = val_tmp;

        if (r->valid_location) {
            p = ngx_copy(p, ctx->ctx.vars.uri.data, ctx->ctx.vars.uri.len);
        }

        if (escape) {
            ngx_escape_uri(p, r->uri.data + loc_len,
                           r->uri.len - loc_len, NGX_ESCAPE_URI);
            p += r->uri.len - loc_len + escape;

        } else {
            p = ngx_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *p++ = '?';
            p = ngx_copy(p, r->args.data, r->args.len);
        }

        *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_PATH_INDEX);
        b->last = ngx_http_v2_write_value(b->last, val_tmp, p - val_tmp, tmp);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header: \":path: %*s\"", p - val_tmp,
                       val_tmp);
    }

    *b->last++ = ngx_http_v2_inc_indexed(NGX_HTTP_V2_AUTHORITY_INDEX);
    b->last = ngx_http_v2_write_value(b->last, host.data, host.len, tmp);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header: \":authority: %V\"", &host);

    ngx_memzero(&e, sizeof(ngx_http_script_engine_t));

    e.ip = headers->values->elts;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

    headers_end = b->last + headers_len;

    while (*(uintptr_t *) le.ip) {

        lcode = *(ngx_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(ngx_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(ngx_http_script_code_pt *) e.ip;
                code((ngx_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        if (headers_end - b->last < 1) {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "no buffer space in HTTP/2 create request");
            return NGX_ERROR;
        }

        *b->last++ = 0;

        e.pos = key_tmp;
        e.end = key_tmp + tmp_len;

        code = *(ngx_http_script_code_pt *) e.ip;
        code((ngx_http_script_engine_t *) &e);

        if (e.status) {
            return NGX_ERROR;
        }

        key_len = e.pos - key_tmp;

        if (headers_end - b->last
            < (ssize_t) (NGX_HTTP_V2_INT_OCTETS + key_len))
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "no buffer space in HTTP/2 create request");
            return NGX_ERROR;
        }

        b->last = ngx_http_v2_write_name(b->last, key_tmp, key_len, tmp);

        e.pos = val_tmp;
        e.end = val_tmp + tmp_len;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        if (e.status) {
            return NGX_ERROR;
        }

        val_len = e.pos - val_tmp;

        if (headers_end - b->last
            < (ssize_t) (NGX_HTTP_V2_INT_OCTETS + val_len))
        {
            ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                          "no buffer space in HTTP/2 create request");
            return NGX_ERROR;
        }

        b->last = ngx_http_v2_write_value(b->last, val_tmp, val_len, tmp);

#if (NGX_DEBUG)
        if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
            ngx_strlow(key_tmp, key_tmp, key_len);

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%*s: %*s\"",
                           key_len, key_tmp, val_len, val_tmp);
        }
#endif
    }

    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (ngx_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            *b->last++ = 0;

            b->last = ngx_http_v2_write_name(b->last, header[i].key.data,
                                             header[i].key.len, tmp);

            b->last = ngx_http_v2_write_value(b->last, header[i].value.data,
                                              header[i].value.len, tmp);

#if (NGX_DEBUG)
            if (r->connection->log->log_level & NGX_LOG_DEBUG_HTTP) {
                ngx_strlow(tmp, header[i].key.data, header[i].key.len);

                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header: \"%*s: %V\"",
                               header[i].key.len, tmp, &header[i].value);
            }
#endif
        }
    }

    /* update headers frame length */

    len = b->last - headers_frame - sizeof(ngx_http_proxy_v2_frame_t);

    if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
        len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
        next = 1;

    } else {
        next = 0;
    }

    f = (ngx_http_proxy_v2_frame_t *) headers_frame;

    f->length_0 = (u_char) ((len >> 16) & 0xff);
    f->length_1 = (u_char) ((len >> 8) & 0xff);
    f->length_2 = (u_char) (len & 0xff);

    /* create additional continuation frames */

    p = headers_frame;

    while (next) {
        p += sizeof(ngx_http_proxy_v2_frame_t) + NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
        len = b->last - p;

        ngx_memmove(p + sizeof(ngx_http_proxy_v2_frame_t), p, len);
        b->last += sizeof(ngx_http_proxy_v2_frame_t);

        if (len > NGX_HTTP_V2_DEFAULT_FRAME_SIZE) {
            len = NGX_HTTP_V2_DEFAULT_FRAME_SIZE;
            next = 1;

        } else {
            next = 0;
        }

        f = (ngx_http_proxy_v2_frame_t *) p;

        f->length_0 = (u_char) ((len >> 16) & 0xff);
        f->length_1 = (u_char) ((len >> 8) & 0xff);
        f->length_2 = (u_char) (len & 0xff);
        f->type = NGX_HTTP_V2_CONTINUATION_FRAME;
        f->flags = 0;
        f->stream_id_0 = 0;
        f->stream_id_1 = 0;
        f->stream_id_2 = 0;
        f->stream_id_3 = 1;
    }

    f->flags |= NGX_HTTP_V2_END_HEADERS_FLAG;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header: %*xs%s, len: %uz",
                   (size_t) ngx_min(b->last - b->pos, 256), b->pos,
                   b->last - b->pos > 256 ? "..." : "",
                   b->last - b->pos);

    if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        if (body == NULL) {

            /*
             * No request body at all: END_STREAM rides on the HEADERS
             * frame, and "b" still names the headers buffer built
             * above, which is therefore the last (and only) buffer of
             * this request -- it must carry last_buf, exactly as the
             * trailing else branch below does.  Without it
             * ngx_http_proxy_v2_body_output_filter() never sets
             * stream.output_closed, which every keepalive-eligibility
             * check in this module requires, so the connection would
             * be closed instead of being cached after every bodiless
             * request.
             */

            f = (ngx_http_proxy_v2_frame_t *) headers_frame;
            f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;

            b->last_buf = 1;
        }

        while (body) {
            b = ngx_alloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(b, body->buf, sizeof(ngx_buf_t));

            cl->next = ngx_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return NGX_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

        /*
         * b->last_buf, copied above from the real u->request_bufs
         * chain, already tells the truth about whether the client's
         * body actually finished:
         *
         *  - buffered mode (r->request_body_no_buffering == 0): the
         *    whole body is always present in one call, so the last
         *    buffer copied here already has last_buf set;
         *
         *  - non-buffered/streaming mode
         *    (r->request_body_no_buffering == 1): this filter's
         *    counterpart, ngx_http_proxy_v2_body_output_filter(),
         *    runs once per chunk as it arrives from the client, and
         *    u->request_bufs on any call before the last one holds a
         *    chunk whose trailing buffer's last_buf is correctly 0.
         *
         * There must be no unconditional "b->last_buf = 1" here (the
         * previous bug): forcing it on every call would emit
         * END_STREAM on the first chunk and truncate every streamed
         * request body.
         */

    } else if (body_len) {

        u->request_bufs = cl;

        b = ngx_create_temp_buf(r->pool, body_len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        cl->next = ngx_alloc_chain_link(r->pool);
        if (cl->next == NULL) {
            return NGX_ERROR;
        }

        cl = cl->next;
        cl->buf = b;

        e.ip = plcf->body_values->elts;
        e.pos = b->last;
        e.end = b->last + body_len;
        e.request = r;
        e.flushed = 1;
        e.skip = 0;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code((ngx_http_script_engine_t *) &e);
        }

        if (e.status) {
            return NGX_ERROR;
        }

        b->last = e.pos;
        b->last_buf = 1;

    } else {
        u->request_bufs = cl;

        f = (ngx_http_proxy_v2_frame_t *) headers_frame;
        f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;

        b->last_buf = 1;
    }

    u->output.output_filter = ngx_http_proxy_v2_body_output_filter;
    u->output.filter_ctx = r;

    b->flush = 1;
    cl->next = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_reinit_request(ngx_http_request_t *r)
{
    ngx_chain_t              *free;
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_OK;
    }

    ngx_http_proxy_v2_restore(r, ctx);

    free = ctx->stream.free;

    ngx_memzero(&ctx->stream, sizeof(ngx_http_proxy_v2_stream_t));
    ctx->stream.request = r;
    ctx->stream.free = free;

    ctx->session = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_body_output_filter(void *data, ngx_chain_t *in)
{
    ngx_http_request_t  *r = data;

    off_t                          file_pos;
    u_char                        *p, *pos, *start;
    size_t                         len, limit;
    ngx_buf_t                     *b;
    ngx_int_t                      rc;
    ngx_uint_t                     next, last;
    ngx_queue_t                   *q;
    ngx_chain_t                   *cl, *out, *ln, *session_out, **ll;
    ngx_chain_t                  **session_ll, **stream_ll;
    ngx_http_upstream_t           *u;
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_proxy_v2_frame_t     *f;
    ngx_http_proxy_v2_stream_t    *waiter;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output filter");

    ctx = ngx_http_proxy_v2_get_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->stream.in, in) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /*
     * Write-turn gate: at most one stream may build into and hand a
     * frame to the socket at a time, since TCP is one ordered byte
     * stream and two concurrent partial writes on it would
     * interleave mid-frame.  Checked here, before any frame is built
     * (not just before ngx_chain_writer()), so that a stream denied
     * its turn does not build frames into "out" that would then have
     * nowhere to go -- ctx->stream.in (just updated above) is the
     * only place unsent input waits, and it is left completely
     * untouched below when this branch is taken; the next call, once
     * it is this stream's turn, resumes building from it exactly as
     * if this call had never run.
     *
     * No frame is ever queued by this gate -- a denied stream links
     * only its own stream pointer (never bytes) onto session->waiting
     * (a FIFO), and is woken by whichever stream currently holds the
     * turn once it releases it (see the rc != NGX_AGAIN branch,
     * below the ngx_chain_writer() call further down).
     */

    if ((ctx->session->writer != NULL && ctx->session->writer != &ctx->stream)
        || ctx->session->orphan != NULL)
    {
        if (!ctx->stream.waiting) {
            ctx->stream.waiting = 1;
            ngx_queue_insert_tail(&ctx->session->waiting,
                                  &ctx->stream.wait_link);
        }

        ctx->stream.output_blocked = 1;

        return NGX_AGAIN;
    }

    if (ctx->stream.waiting) {
        ngx_queue_remove(&ctx->stream.wait_link);
        ctx->stream.waiting = 0;
    }

    ctx->session->writer = &ctx->stream;

    /*
     * A real (not posted) socket-level write-ready event on the
     * physical connection resolves the request to drive via
     * c->data -- see ngx_http_proxy_v2_session_write_handler(), "r =
     * c->data".  Point it at this stream for as long as this stream
     * holds the write turn, so that if the socket becomes writable
     * again before this stream's own partial write finishes (see
     * ctx->stream.busy / rc == NGX_AGAIN from ngx_chain_writer(),
     * further down), the physical event reaches the stream that
     * actually owns the in-flight write, not whichever stream
     * attached last.
     */

    ctx->session->connection->data = r;

    out = NULL;
    ll = &out;

    if (!ctx->stream.header_sent) {
        /* first buffer contains headers */

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy output header");

        ctx->stream.header_sent = 1;

        /*
         * the headers buffer is built once for stream 1 and, after a
         * retry (a connection that went away, GOAWAY), sent again: the
         * identifiers have to be set every time, also back to 1, and the
         * connection preface is only for a new connection
         */

        b = ctx->stream.in->buf;
        p = b->pos + sizeof(ngx_http_proxy_v2_connection_start) - 1;

        if (ctx->stream.id != 1) {
            /* keepalive connection: skip connection preface */
            b->pos = p;
        }

        while (p < b->last) {
            f = (ngx_http_proxy_v2_frame_t *) p;
            p += sizeof(ngx_http_proxy_v2_frame_t);

            f->stream_id_0 = (u_char) ((ctx->stream.id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->stream.id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->stream.id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->stream.id & 0xff);

            p += (f->length_0 << 16) + (f->length_1 << 8) + f->length_2;
        }

        if (ctx->stream.in->buf->last_buf) {
            ctx->stream.output_closed = 1;
        }

        *ll = ctx->stream.in;
        ll = &ctx->stream.in->next;

        ctx->stream.in = ctx->stream.in->next;
    }

    if (ctx->session->out) {
        /* queued control frames */

        *ll = ctx->session->out;

        for (cl = ctx->session->out, ll = &cl->next; cl; cl = cl->next) {
            ll = &cl->next;
        }

        ctx->session->out = NULL;
    }

    if (ctx->stream.out) {
        *ll = ctx->stream.out;

        for (cl = ctx->stream.out, ll = &cl->next; cl; cl = cl->next) {
            ll = &cl->next;
        }

        ctx->stream.out = NULL;
    }

    f = NULL;
    last = 0;

    /*
     * Both windows are signed and may go negative after a
     * SETTINGS_INITIAL_WINDOW_SIZE decrease; clamp the smaller of the
     * two to zero rather than letting a negative value survive into
     * "limit" (size_t), which would otherwise wrap to a huge positive
     * number and let this filter build past the real window.
     */

    limit = (size_t) ngx_max((ssize_t) 0,
                 ngx_min(ctx->stream.send_window, ctx->session->send_window));

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output limit: %uz w:%z:%z",
                   limit, ctx->stream.send_window, ctx->session->send_window);

#if (NGX_SUPPRESS_WARN)
    file_pos = 0;
    pos = NULL;
    cl = NULL;
#endif

    in = ctx->stream.in;

    while (in && limit > 0) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http proxy output in  l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       in->buf->last_buf,
                       in->buf->in_file,
                       in->buf->start, in->buf->pos,
                       in->buf->last - in->buf->pos,
                       in->buf->file_pos,
                       in->buf->file_last - in->buf->file_pos);

        if (ngx_buf_special(in->buf)) {
            goto next;
        }

        if (in->buf->in_file) {
            file_pos = in->buf->file_pos;

        } else {
            pos = in->buf->pos;
        }

        next = 0;

        do {

            cl = ngx_http_proxy_v2_get_buf(&ctx->stream);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            f = (ngx_http_proxy_v2_frame_t *) b->last;
            b->last += sizeof(ngx_http_proxy_v2_frame_t);

            *ll = cl;
            ll = &cl->next;

            cl = ngx_chain_get_free_buf(r->pool, &ctx->stream.free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;
            start = b->start;

            ngx_memcpy(b, in->buf, sizeof(ngx_buf_t));

            /*
             * restore b->start to preserve memory allocated in the buffer,
             * to reuse it later for headers and control frames
             */

            b->start = start;

            if (in->buf->in_file) {
                b->file_pos = file_pos;
                file_pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (file_pos >= in->buf->file_last) {
                    file_pos = in->buf->file_last;
                    next = 1;
                }

                b->file_last = file_pos;
                len = (ngx_uint_t) (file_pos - b->file_pos);

            } else {
                b->pos = pos;
                pos += ngx_min(NGX_HTTP_V2_DEFAULT_FRAME_SIZE, limit);

                if (pos >= in->buf->last) {
                    pos = in->buf->last;
                    next = 1;
                }

                b->last = pos;
                len = (ngx_uint_t) (pos - b->pos);
            }

            b->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter;
            b->shadow = in->buf;
            b->last_shadow = next;

            b->last_buf = 0;
            b->last_in_chain = 0;

            *ll = cl;
            ll = &cl->next;

            f->length_0 = (u_char) ((len >> 16) & 0xff);
            f->length_1 = (u_char) ((len >> 8) & 0xff);
            f->length_2 = (u_char) (len & 0xff);
            f->type = NGX_HTTP_V2_DATA_FRAME;
            f->flags = 0;
            f->stream_id_0 = (u_char) ((ctx->stream.id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->stream.id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->stream.id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->stream.id & 0xff);

            limit -= len;
            ctx->stream.send_window -= len;
            ctx->session->send_window -= len;

        } while (!next && limit > 0);

        if (!next) {
            /*
             * if the buffer wasn't fully sent due to flow control limits,
             * preserve position for future use
             */

            if (in->buf->in_file) {
                in->buf->file_pos = file_pos;

            } else {
                in->buf->pos = pos;
            }

            break;
        }

    next:

        if (in->buf->last_buf) {
            last = 1;
        }

        ln = in;
        in = in->next;

        ngx_free_chain(r->pool, ln);
    }

    ctx->stream.in = in;

    if (last) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy output last");

        ctx->stream.output_closed = 1;

        if (f) {
            f->flags |= NGX_HTTP_V2_END_STREAM_FLAG;

        } else {
            cl = ngx_http_proxy_v2_get_buf(&ctx->stream);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b = cl->buf;

            f = (ngx_http_proxy_v2_frame_t *) b->last;
            b->last += sizeof(ngx_http_proxy_v2_frame_t);

            f->length_0 = 0;
            f->length_1 = 0;
            f->length_2 = 0;
            f->type = NGX_HTTP_V2_DATA_FRAME;
            f->flags = NGX_HTTP_V2_END_STREAM_FLAG;
            f->stream_id_0 = (u_char) ((ctx->stream.id >> 24) & 0xff);
            f->stream_id_1 = (u_char) ((ctx->stream.id >> 16) & 0xff);
            f->stream_id_2 = (u_char) ((ctx->stream.id >> 8) & 0xff);
            f->stream_id_3 = (u_char) (ctx->stream.id & 0xff);

            *ll = cl;
            ll = &cl->next;
        }

        cl->buf->last_buf = 1;
    }

    *ll = NULL;

#if (NGX_DEBUG)

    for (cl = out; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http proxy output out l:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->last_buf,
                       cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy output limit: %uz w:%z:%uz",
                   limit, ctx->stream.send_window, ctx->session->send_window);

#endif

    rc = ngx_chain_writer(&r->upstream->writer, out);

    if (rc != NGX_AGAIN) {

        /*
         * Release the write turn and wake the next waiter, if any.
         * See the write-turn gate comment above (near where "in" is
         * appended to ctx->stream.in) for the acquire half of this.
         */

        ctx->session->writer = NULL;

        if (!ngx_queue_empty(&ctx->session->waiting)) {
            q = ngx_queue_head(&ctx->session->waiting);
            waiter = ngx_queue_data(q, ngx_http_proxy_v2_stream_t,
                                    wait_link);

            /*
             * Do not unlink/clear waiter->waiting here: the woken
             * stream's own next body_output_filter() call is what
             * acquires the turn (above) and only then clears its own
             * waiting state -- unlinking it here, before it has
             * actually run, would let a second waiter also believe
             * the queue is empty and skip waiting entirely.
             */

            ngx_post_event(waiter->write, &ngx_posted_events);
        }
    }

    session_out = NULL;
    session_ll = &session_out;
    stream_ll = &out;

    for (cl = out; cl; cl = ln) {
        ln = cl->next;

        if (cl->buf->tag == ctx->session->output_tag) {
            *session_ll = cl;
            session_ll = &cl->next;

        } else {
            *stream_ll = cl;
            stream_ll = &cl->next;
        }
    }

    *session_ll = NULL;
    *stream_ll = NULL;

    ngx_chain_update_chains(ctx->session->connection->pool,
                            &ctx->session->free, &ctx->session->busy,
                            &session_out, ctx->session->output_tag);

    ngx_chain_update_chains(r->pool, &ctx->stream.free, &ctx->stream.busy, &out,
                          (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter);

    for (cl = ctx->stream.free; cl; cl = cl->next) {

        /* mark original buffers as sent */

        if (cl->buf->shadow) {
            if (cl->buf->last_shadow) {
                b = cl->buf->shadow;
                b->pos = b->last;
            }

            cl->buf->shadow = NULL;
        }
    }

    if (rc == NGX_OK && ctx->stream.in) {
        rc = NGX_AGAIN;
    }

    if (rc == NGX_AGAIN) {
        ctx->stream.output_blocked = 1;

    } else {
        ctx->stream.output_blocked = 0;
    }

    if (ctx->stream.done) {

        /*
         * We have already got the response and were sending some additional
         * control frames.  Even if there is still something unsent, stop
         * here anyway.
         */

        u = r->upstream;
        u->length = 0;
        u->pipe->length = 0;

        if (ctx->stream.in == NULL
            && ctx->stream.out == NULL
            && ctx->session->out == NULL
            && ctx->session->busy == NULL
            && ctx->stream.output_closed
            && !ctx->stream.output_blocked
            && !ctx->session->goaway
            && ctx->session->state == ngx_http_proxy_v2_st_start)
        {
            u->keepalive = 1;
        }

        ngx_post_event(u->peer.connection->read, &ngx_posted_events);
    }

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_process_header(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_session_t  *session;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    session = ctx ? ctx->session : NULL;

    if (session == NULL) {
        return ngx_http_proxy_v2_process_header_run(r);
    }

    ngx_http_proxy_v2_swap_scratch(session, &ctx->stream.scratch);
    rc = ngx_http_proxy_v2_process_header_run(r);
    ngx_http_proxy_v2_swap_scratch(session, &ctx->stream.scratch);

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_process_header_run(ngx_http_request_t *r)
{
    u_char                         *pos;
    ngx_str_t                      *status_line;
    ngx_int_t                       rc, status;
    ngx_buf_t                      *b;
    ngx_table_elt_t                *h;
    ngx_http_upstream_t            *u;
    ngx_http_proxy_v2_ctx_t        *ctx;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;

    u = r->upstream;
    b = &u->buffer;
    pos = b->pos;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy response: %*xs%s, len: %uz",
                   (size_t) ngx_min(b->last - b->pos, 256),
                   b->pos, b->last - b->pos > 256 ? "..." : "",
                   b->last - b->pos);

    ctx = ngx_http_proxy_v2_get_ctx(r);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for ( ;; ) {

        if (ctx->session->state < ngx_http_proxy_v2_st_payload) {

            rc = ngx_http_proxy_v2_parse_frame(ctx->session, b);

            if (rc == NGX_AGAIN) {

                /*
                 * there can be a lot of window update frames,
                 * so we reset buffer if it is empty and we haven't
                 * started parsing headers yet
                 */

                if (!ctx->stream.parsing_headers) {
                    b->pos = pos;
                    b->last = b->pos;
                }

                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            ctx->session->frame_validated = 0;

            /*
             * RFC 7540 says that implementations MUST discard frames
             * that have unknown or unsupported types.  However, extension
             * frames that appear in the middle of a header block are
             * not permitted.  Also, for obvious reasons CONTINUATION frames
             * cannot appear before headers, and DATA frames are not expected
             * to appear before all headers are parsed.
             */

            if (ctx->session->type == NGX_HTTP_V2_DATA_FRAME
                || (ctx->session->type == NGX_HTTP_V2_CONTINUATION_FRAME
                    && !ctx->stream.parsing_headers)
                || (ctx->session->type != NGX_HTTP_V2_CONTINUATION_FRAME
                    && ctx->stream.parsing_headers))
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->session->type);
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            if (ctx->stream.id && ctx->session->stream_id
                && ctx->session->stream_id != ctx->stream.id)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for unknown stream %ui",
                              ctx->session->stream_id);
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }
        }

        /* frame payload */

        if (ctx->session->type == NGX_HTTP_V2_RST_STREAM_FRAME) {
            rc = ngx_http_proxy_v2_parse_rst_stream(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_HTTP_UPSTREAM_INVALID_HEADER;
            }

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream rejected request with error %ui",
                          ctx->stream.error);

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        rc = ngx_http_proxy_v2_process_control_frame(ctx->session, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (rc == NGX_OK) {
            continue;
        }

        if (ctx->session->type != NGX_HTTP_V2_HEADERS_FRAME
            && ctx->session->type != NGX_HTTP_V2_CONTINUATION_FRAME)
        {
            /* priority, unknown frames */

            rc = ngx_http_proxy_v2_skip_frame(ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            continue;
        }

        /* headers */

        for ( ;; ) {

            rc = ngx_http_proxy_v2_parse_header(r, ctx, b);

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_OK) {

                /* a header line has been parsed successfully */

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header: \"%V: %V\"",
                               &ctx->stream.name, &ctx->stream.value);

                if (ctx->stream.name.len
                    && ctx->stream.name.data[0] == ':')
                {

                    if (ctx->stream.name.len != sizeof(":status") - 1
                        || ngx_strncmp(ctx->stream.name.data, ":status",
                                       sizeof(":status") - 1)
                           != 0)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid header \"%V: %V\"",
                                      &ctx->stream.name, &ctx->stream.value);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (ctx->stream.status) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent duplicate :status header");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status_line = &ctx->stream.value;

                    if (status_line->len != 3) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    status = ngx_atoi(status_line->data, 3);

                    if (status == NGX_ERROR) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    if (status < NGX_HTTP_OK && status != NGX_HTTP_EARLY_HINTS)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent unexpected :status \"%V\"",
                                      status_line);
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    u->headers_in.status_n = status;

                    if (u->state && u->state->status == 0) {
                        u->state->status = status;
                    }

                    ctx->stream.status = 1;

                    continue;

                } else if (!ctx->stream.status) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent no :status header");
                    return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                }

                h = ngx_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->key = ctx->stream.name;
                h->value = ctx->stream.value;
                h->lowcase_key = h->key.data;
                h->hash = ngx_hash_key(h->key.data, h->key.len);

                if (u->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
                    continue;
                }

                hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                                   h->lowcase_key, h->key.len);

                if (hh) {
                    rc = hh->handler(r, h, hh->offset);

                    if (rc != NGX_OK) {
                        return rc;
                    }
                }

                continue;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                /* a whole header has been parsed successfully */

                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy header done");

                if (u->headers_in.status_n == NGX_HTTP_EARLY_HINTS) {
                    if (ctx->stream.end_stream) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream prematurely closed stream");
                        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
                    }

                    ctx->stream.status = 0;
                    return NGX_HTTP_UPSTREAM_EARLY_HINTS;
                }

                if (ctx->stream.end_stream
                    && ctx->stream.in == NULL
                    && ctx->stream.out == NULL
                    && ctx->session->out == NULL
                    && ctx->session->busy == NULL
                    && ctx->stream.output_closed
                    && !ctx->stream.output_blocked
                    && !ctx->session->goaway
                    && b->last == b->pos)
                {
                    u->keepalive = 1;
                }

                return NGX_OK;
            }

            /* there was error while a header line parsing */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent invalid header");

            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        /* rc == NGX_AGAIN */

        if (ctx->session->rest == 0) {
            ctx->session->state = ngx_http_proxy_v2_st_start;
            continue;
        }

        return NGX_AGAIN;
    }
}


static ngx_int_t
ngx_http_proxy_v2_filter_init(void *data)
{
    ngx_http_request_t       *r = data;
    ngx_http_upstream_t      *u;
    ngx_http_proxy_v2_ctx_t  *ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (u->headers_in.status_n == NGX_HTTP_NO_CONTENT
        || u->headers_in.status_n == NGX_HTTP_NOT_MODIFIED
        || ctx->ctx.head)
    {
        ctx->stream.length = 0;

    } else {
        ctx->stream.length = u->headers_in.content_length_n;
    }

    if (ctx->stream.end_stream) {

        if (ctx->stream.length > 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream prematurely closed stream");
            return NGX_ERROR;
        }

        u->length = 0;
        u->pipe->length = 0;
        ctx->stream.done = 1;

    } else {
        u->length = 1;
        u->pipe->length = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_body_filter(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    ngx_int_t                     rc;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_session_t  *session;

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);
    session = ctx ? ctx->session : NULL;

    if (session == NULL) {
        return ngx_http_proxy_v2_body_filter_run(p, b);
    }

    ngx_http_proxy_v2_swap_scratch(session, &ctx->stream.scratch);
    rc = ngx_http_proxy_v2_body_filter_run(p, b);
    ngx_http_proxy_v2_swap_scratch(session, &ctx->stream.scratch);

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_body_filter_run(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    ngx_int_t                 rc;
    ngx_buf_t                *buf, **prev;
    ngx_chain_t              *cl;
    ngx_http_request_t       *r;
    ngx_http_proxy_v2_ctx_t  *ctx;

    if (b->pos == b->last) {
        return NGX_OK;
    }

    r = p->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    buf = NULL;
    prev = &b->shadow;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter bytes:%z", b->last - b->pos);

    for ( ;; ) {

        rc = ngx_http_proxy_v2_process_frames(r, ctx, b);

        if (rc == NGX_OK) {

            /* copy data frame payload for buffering */

            cl = ngx_chain_get_free_buf(p->pool, &p->free);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            buf = cl->buf;

            ngx_memzero(buf, sizeof(ngx_buf_t));

            buf->pos = b->pos;
            buf->start = b->start;
            buf->end = b->end;
            buf->tag = p->tag;
            buf->temporary = 1;
            buf->recycled = 1;

            *prev = buf;
            prev = &buf->shadow;

            if (p->in) {
                *p->last_in = cl;

            } else {
                p->in = cl;
            }

            p->last_in = &cl->next;

            /* STUB */ buf->num = b->num;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy copy buf %p", buf->pos);

            if (b->last - b->pos >= (ssize_t) ctx->session->rest
                                       - ctx->session->padding)
            {
                b->pos += ctx->session->rest - ctx->session->padding;
                buf->last = b->pos;
                ctx->session->rest = ctx->session->padding;

            } else {
                ctx->session->rest -= b->last - b->pos;
                b->pos = b->last;
                buf->last = b->pos;
            }

            if (ctx->stream.length != -1) {

                if (buf->last - buf->pos > ctx->stream.length) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent response body larger "
                                  "than indicated content length");
                    return NGX_ERROR;
                }

                ctx->stream.length -= buf->last - buf->pos;
            }

            continue;
        }

        if (rc == NGX_DONE) {
            p->length = 0;
            break;
        }

        if (rc == NGX_AGAIN) {
            break;
        }

        /* invalid response */

        return NGX_ERROR;
    }

    ngx_http_proxy_v2_resume_read(ctx);

    if (buf) {
        buf->shadow = b;
        buf->last_shadow = 1;

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", buf->pos, buf->last - buf->pos);

        return NGX_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (ngx_event_pipe_add_free_buf(p, b) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * The session hands a stream one frame at a time and only stages the next
 * frame once the filter has finished the previous one (session->state is
 * shared with the filter's frame parser).  The pipe, however, reads before it
 * filters, so the read that would have staged the next frame already ran and
 * returned NGX_AGAIN; if the rest of the recv() data sits in session->buffer,
 * or the socket was left readable because the buffer filled up before EAGAIN,
 * no new event will come (edge-triggered) and nothing would wake the stream
 * again.  Re-arm the read event here, at the frame boundary.
 */

static void
ngx_http_proxy_v2_resume_read(ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_http_proxy_v2_session_t  *session;

    session = ctx->session;

    if (session == NULL || !ctx->stream.connection_created) {
        return;
    }

    if (session->stream_frame
        && session->frame_rest == 0
        && session->frame_sent == sizeof(session->frame_header)
        && session->state == ngx_http_proxy_v2_st_start
        && (session->buffer.pos < session->buffer.last
            || session->connection->read->ready))
    {
        ctx->stream.read->ready = 1;
        ngx_post_event(ctx->stream.read, &ngx_posted_events);
    }
}


static ngx_int_t
ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    if (b->last - b->pos < (ssize_t) ctx->session->rest) {
        ctx->session->rest -= b->last - b->pos;
        b->pos = b->last;
        return NGX_AGAIN;
    }

    b->pos += ctx->session->rest;
    ctx->session->rest = 0;
    ctx->session->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_process_frames(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    ngx_int_t             rc;
    ngx_table_elt_t      *h;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    for ( ;; ) {

        if (ctx->session->state < ngx_http_proxy_v2_st_payload) {

            rc = ngx_http_proxy_v2_parse_frame(ctx->session, b);

            if (rc == NGX_AGAIN) {

                if (ctx->stream.done) {

                    if (ctx->stream.length > 0) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream prematurely closed stream");
                        return NGX_ERROR;
                    }

                    /*
                     * We have finished parsing the response and the
                     * remaining control frames.  If there are unsent
                     * control frames, post a write event to send them.
                     */

                    if (ctx->stream.out || ctx->session->out) {
                        ngx_post_event(ctx->session->connection->write,
                                       &ngx_posted_events);
                        return NGX_AGAIN;
                    }

                    if (ctx->stream.in == NULL
                        && ctx->stream.out == NULL
                        && ctx->session->out == NULL
                        && ctx->session->busy == NULL
                        && ctx->stream.output_closed
                        && !ctx->stream.output_blocked
                        && !ctx->session->goaway
                        && ctx->session->state == ngx_http_proxy_v2_st_start)
                    {
                        u->keepalive = 1;
                    }

                    return NGX_DONE;
                }

                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if ((ctx->session->type == NGX_HTTP_V2_CONTINUATION_FRAME
                 && !ctx->stream.parsing_headers)
                || (ctx->session->type != NGX_HTTP_V2_CONTINUATION_FRAME
                    && ctx->stream.parsing_headers))
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent unexpected http2 frame: %d",
                              ctx->session->type);
                return NGX_ERROR;
            }

            ctx->session->frame_validated = 0;

            if (ctx->session->type == NGX_HTTP_V2_DATA_FRAME) {

                if (ctx->session->stream_id != ctx->stream.id) {

                    /*
                     * Route by looking the id up in the session's
                     * stream registry rather than assuming the only
                     * legitimate target is this request's own stream.
                     * DATA for an id that
                     * was never registered at all on this connection
                     * is a genuine protocol violation; DATA for an id
                     * that was registered (a prior stream on this
                     * kept-alive session) but has already finished is
                     * a late, harmless frame that must not fail this
                     * unrelated, currently-active request -- skip its
                     * payload exactly as the existing "priority,
                     * unknown frames" path below already does, rather
                     * than returning NGX_OK, which the caller
                     * (ngx_http_proxy_v2_body_filter()) would
                     * otherwise interpret as "buffer this as response
                     * body data".
                     */

                    if (ngx_http_proxy_v2_find_stream(ctx->session,
                                                      ctx->session->stream_id)
                        == NULL)
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent data frame "
                                      "for unknown stream %ui",
                                      ctx->session->stream_id);
                        return NGX_ERROR;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http proxy data frame for inactive "
                                   "stream %ui ignored",
                                   ctx->session->stream_id);

                    rc = ngx_http_proxy_v2_skip_frame(ctx, b);

                    if (rc == NGX_AGAIN) {
                        return NGX_AGAIN;
                    }

                    continue;
                }

                if (ctx->session->rest > ctx->stream.recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated stream flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->session->rest, ctx->stream.recv_window);
                    return NGX_ERROR;
                }

                if (ctx->session->rest > ctx->session->recv_window) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream violated connection flow control, "
                                  "received %uz data frame with window %uz",
                                  ctx->session->rest,
                                  ctx->session->recv_window);
                    return NGX_ERROR;
                }

                ctx->stream.recv_window -= ctx->session->rest;
                ctx->session->recv_window -= ctx->session->rest;

                if (ctx->session->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4
                    || ctx->stream.recv_window < NGX_HTTP_V2_MAX_WINDOW / 4)
                {
                    if (ngx_http_proxy_v2_send_connection_window_update(
                        ctx->session) != NGX_OK
                        || ngx_http_proxy_v2_send_stream_window_update(
                            &ctx->stream) != NGX_OK)
                    {
                        return NGX_ERROR;
                    }

                    ngx_post_event(ctx->session->connection->write,
                                   &ngx_posted_events);
                }
            }

            if (ctx->session->stream_id
                && ctx->session->stream_id != ctx->stream.id)
            {

                /*
                 * As with the DATA-frame case above: route by looking
                 * the id up in the session's stream registry instead
                 * of assuming this request's own stream is the only
                 * legitimate target. An id
                 * never registered on this connection at all is still
                 * a genuine protocol violation.  An id that was
                 * registered but is not this request's own stream
                 * (e.g. PRIORITY, which RFC 9113 section 5.3.4 says
                 * to ignore regardless of whether the id is even
                 * known, or a late RST_STREAM/WINDOW_UPDATE for a
                 * stream that already finished) must not fail this
                 * unrelated, currently-active request.
                 */

                if (ngx_http_proxy_v2_find_stream(ctx->session,
                                                  ctx->session->stream_id)
                    == NULL)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent frame for unknown "
                                  "stream %ui", ctx->session->stream_id);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy frame for inactive stream "
                               "%ui ignored", ctx->session->stream_id);

                rc = ngx_http_proxy_v2_skip_frame(ctx, b);

                if (rc == NGX_AGAIN) {
                    return NGX_AGAIN;
                }

                continue;
            }

            if (ctx->session->stream_id && ctx->stream.done
                && ctx->session->type != NGX_HTTP_V2_RST_STREAM_FRAME
                && ctx->session->type != NGX_HTTP_V2_WINDOW_UPDATE_FRAME)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->session->stream_id);
                return NGX_ERROR;
            }

            ctx->session->padding = 0;
        }

        if (ctx->session->state == ngx_http_proxy_v2_st_padding) {

            if (b->last - b->pos < (ssize_t) ctx->session->rest) {
                ctx->session->rest -= b->last - b->pos;
                b->pos = b->last;
                return NGX_AGAIN;
            }

            b->pos += ctx->session->rest;
            ctx->session->rest = 0;
            ctx->session->state = ngx_http_proxy_v2_st_start;

            if (ctx->session->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                ctx->stream.done = 1;
            }

            continue;
        }

        /* frame payload */

        if (ctx->session->type == NGX_HTTP_V2_RST_STREAM_FRAME) {

            rc = ngx_http_proxy_v2_parse_rst_stream(r, ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            if (ctx->stream.error || !ctx->stream.done) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream rejected request with error %ui",
                              ctx->stream.error);
                return NGX_ERROR;
            }

            if (ctx->stream.rst) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent frame for closed stream %ui",
                              ctx->session->stream_id);
                return NGX_ERROR;
            }

            ctx->stream.rst = 1;

            continue;
        }

        rc = ngx_http_proxy_v2_process_control_frame(ctx->session, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            continue;
        }

        if (ctx->session->type == NGX_HTTP_V2_HEADERS_FRAME
            || ctx->session->type == NGX_HTTP_V2_CONTINUATION_FRAME)
        {
            for ( ;; ) {

                rc = ngx_http_proxy_v2_parse_header(r, ctx, b);

                if (rc == NGX_AGAIN) {
                    break;
                }

                if (rc == NGX_OK) {

                    /* a header line has been parsed successfully */

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http proxy trailer: \"%V: %V\"",
                                   &ctx->stream.name, &ctx->stream.value);

                    if (ctx->stream.name.len
                        && ctx->stream.name.data[0] == ':')
                    {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                      "upstream sent invalid "
                                      "trailer \"%V: %V\"",
                                      &ctx->stream.name, &ctx->stream.value);
                        return NGX_ERROR;
                    }

                    h = ngx_list_push(&u->headers_in.trailers);
                    if (h == NULL) {
                        return NGX_ERROR;
                    }

                    h->key = ctx->stream.name;
                    h->value = ctx->stream.value;
                    h->lowcase_key = h->key.data;
                    h->hash = ngx_hash_key(h->key.data, h->key.len);

                    continue;
                }

                if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

                    /* a whole header has been parsed successfully */

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http proxy trailer done");

                    if (ctx->stream.end_stream) {
                        ctx->stream.done = 1;
                        break;
                    }

                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent trailer without "
                                  "end stream flag");
                    return NGX_ERROR;
                }

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid trailer");

                return NGX_ERROR;
            }

            if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
                continue;
            }

            /* rc == NGX_AGAIN */

            if (ctx->session->rest == 0) {
                ctx->session->state = ngx_http_proxy_v2_st_start;
                continue;
            }

            return NGX_AGAIN;
        }

        if (ctx->session->type != NGX_HTTP_V2_DATA_FRAME) {

            /* priority, unknown frames */

            rc = ngx_http_proxy_v2_skip_frame(ctx, b);

            if (rc == NGX_AGAIN) {
                return NGX_AGAIN;
            }

            continue;
        }

        /*
         * data frame:
         *
         * +---------------+
         * |Pad Length? (8)|
         * +---------------+-----------------------------------------------+
         * |                            Data (*)                         ...
         * +---------------------------------------------------------------+
         * |                           Padding (*)                       ...
         * +---------------------------------------------------------------+
         */

        if (ctx->session->flags & NGX_HTTP_V2_PADDED_FLAG) {

            if (ctx->session->rest == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too short http2 frame");
                return NGX_ERROR;
            }

            if (b->pos == b->last) {
                return NGX_AGAIN;
            }

            ctx->session->flags &= ~NGX_HTTP_V2_PADDED_FLAG;
            ctx->session->padding = *b->pos++;
            ctx->session->rest -= 1;

            if (ctx->session->padding > ctx->session->rest) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 frame with too long "
                              "padding: %d in frame %uz",
                              ctx->session->padding, ctx->session->rest);
                return NGX_ERROR;
            }

            continue;
        }

        if (ctx->session->padding == ctx->session->rest) {

            if (ctx->session->padding) {
                ctx->session->state = ngx_http_proxy_v2_st_padding;

            } else {
                ctx->session->state = ngx_http_proxy_v2_st_start;

                if (ctx->session->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                    ctx->stream.done = 1;
                }
            }

            continue;
        }

        if (b->pos == b->last) {
            return NGX_AGAIN;
        }

        return NGX_OK;
    }
}


static ngx_int_t
ngx_http_proxy_v2_parse_header(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char     ch, *p, *last;
    size_t     min;
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_padding_length,
        sw_dependency,
        sw_dependency_2,
        sw_dependency_3,
        sw_dependency_4,
        sw_weight,
        sw_fragment,
        sw_padding
    } state;

    state = ctx->session->frame_state;

    if (state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy parse header: start");

        if (ctx->session->type == NGX_HTTP_V2_HEADERS_FRAME) {
            ctx->stream.parsing_headers = 1;
            ctx->stream.fragment_state = 0;
            ctx->stream.header_limit = r->upstream->conf->buffer_size;

            min = (ctx->session->flags & NGX_HTTP_V2_PADDED_FLAG ? 1 : 0)
                  + (ctx->session->flags & NGX_HTTP_V2_PRIORITY_FLAG ? 5 : 0);

            if (ctx->session->rest < min) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent headers frame "
                              "with invalid length: %uz",
                              ctx->session->rest);
                return NGX_ERROR;
            }

            if (ctx->session->flags & NGX_HTTP_V2_END_STREAM_FLAG) {
                ctx->stream.end_stream = 1;
            }

            if (ctx->session->flags & NGX_HTTP_V2_PADDED_FLAG) {
                state = sw_padding_length;

            } else if (ctx->session->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                state = sw_dependency;

            } else {
                state = sw_fragment;
            }

        } else if (ctx->session->type == NGX_HTTP_V2_CONTINUATION_FRAME) {
            state = sw_fragment;
        }

        ctx->session->padding = 0;
        ctx->session->frame_state = state;
    }

    if (state < sw_fragment) {

        if (b->last - b->pos < (ssize_t) ctx->session->rest) {
            last = b->last;

        } else {
            last = b->pos + ctx->session->rest;
        }

        for (p = b->pos; p < last; p++) {
            ch = *p;

#if 0
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header byte: %02Xd s:%d", ch, state);
#endif

            /*
             * headers frame:
             *
             * +---------------+
             * |Pad Length? (8)|
             * +-+-------------+----------------------------------------------+
             * |E|                 Stream Dependency? (31)                    |
             * +-+-------------+----------------------------------------------+
             * |  Weight? (8)  |
             * +-+-------------+----------------------------------------------+
             * |                   Header Block Fragment (*)                ...
             * +--------------------------------------------------------------+
             * |                           Padding (*)                      ...
             * +--------------------------------------------------------------+
             */

            switch (state) {

            case sw_padding_length:

                ctx->session->padding = ch;

                if (ctx->session->flags & NGX_HTTP_V2_PRIORITY_FLAG) {
                    state = sw_dependency;
                    break;
                }

                goto fragment;

            case sw_dependency:
                state = sw_dependency_2;
                break;

            case sw_dependency_2:
                state = sw_dependency_3;
                break;

            case sw_dependency_3:
                state = sw_dependency_4;
                break;

            case sw_dependency_4:
                state = sw_weight;
                break;

            case sw_weight:
                goto fragment;

            /* suppress warning */
            case sw_start:
            case sw_fragment:
            case sw_padding:
                break;
            }
        }

        ctx->session->rest -= p - b->pos;
        b->pos = p;

        ctx->session->frame_state = state;
        return NGX_AGAIN;

    fragment:

        p++;
        ctx->session->rest -= p - b->pos;
        b->pos = p;

        if (ctx->session->padding > ctx->session->rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent http2 frame with too long "
                          "padding: %d in frame %uz",
                          ctx->session->padding, ctx->session->rest);
            return NGX_ERROR;
        }

        state = sw_fragment;
        ctx->session->frame_state = state;
    }

    if (state == sw_fragment) {

        rc = ngx_http_proxy_v2_parse_fragment(r, ctx, b);

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            return NGX_OK;
        }

        /* rc == NGX_DONE */

        state = sw_padding;
        ctx->session->frame_state = state;
    }

    if (state == sw_padding) {

        if (b->last - b->pos < (ssize_t) ctx->session->rest) {

            ctx->session->rest -= b->last - b->pos;
            b->pos = b->last;

            return NGX_AGAIN;
        }

        b->pos += ctx->session->rest;
        ctx->session->rest = 0;

        ctx->session->state = ngx_http_proxy_v2_st_start;

        if (ctx->session->flags & NGX_HTTP_V2_END_HEADERS_FLAG) {

            if (ctx->stream.fragment_state) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent truncated http2 header");
                return NGX_ERROR;
            }

            ctx->stream.parsing_headers = 0;

            return NGX_HTTP_PARSE_HEADER_DONE;
        }

        return NGX_AGAIN;
    }

    /* unreachable */

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_proxy_v2_parse_fragment(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char      ch, *p, *last;
    size_t      len, size;
    ngx_uint_t  index, size_update;
    ngx_http_proxy_v2_stream_t  *stream;
    enum {
        sw_start = 0,
        sw_index,
        sw_name_length,
        sw_name_length_2,
        sw_name_length_3,
        sw_name_length_4,
        sw_name,
        sw_name_bytes,
        sw_value_length,
        sw_value_length_2,
        sw_value_length_3,
        sw_value_length_4,
        sw_value,
        sw_value_bytes
    } state;

    /* header block fragment */

#if 0
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header fragment %p:%p rest:%uz",
                   b->pos, b->last, ctx->session->rest);
#endif

    if (b->last - b->pos < (ssize_t) ctx->session->rest
                               - ctx->session->padding)
    {
        last = b->last;

    } else {
        last = b->pos + ctx->session->rest - ctx->session->padding;
    }

    stream = &ctx->stream;
    state = stream->fragment_state;

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy header byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            stream->index = 0;

            if ((ch & 0x80) == 0x80) {
                /*
                 * indexed header:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 1 |        Index (7+)         |
                 * +---+---------------------------+
                 */

                index = ch & ~0x80;

                if (index == 0 || index > 61) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy indexed header: %ui", index);

                stream->index = index;
                stream->literal = 0;

                goto done;

            } else if ((ch & 0xc0) == 0x40) {
                /*
                 * literal header with incremental indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |      Index (6+)       |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 1 |           0           |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xc0;

                if (index > 61) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "table index: %ui", index);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy literal header: %ui", index);

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                stream->index = index;
                stream->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xe0) == 0x20) {
                /*
                 * dynamic table size update:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 1 |   Max size (5+)   |
                 * +---+---------------------------+
                 */

                size_update = ch & ~0xe0;

                if (size_update > 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid http2 "
                                  "dynamic table size update: %ui",
                                  size_update);
                    return NGX_ERROR;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy table size update: %ui",
                               size_update);

                break;

            } else if ((ch & 0xf0) == 0x10) {
                /*
                 *  literal header field never indexed:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 1 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    stream->index = index;
                    stream->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                               "http proxy literal header never indexed: %ui",
                               index);

                stream->index = index;
                stream->literal = 1;

                state = sw_value_length;
                break;

            } else if ((ch & 0xf0) == 0x00) {
                /*
                 * literal header field without indexing:
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |  Index (4+)   |
                 * +---+---+-----------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 *
                 *   0   1   2   3   4   5   6   7
                 * +---+---+---+---+---+---+---+---+
                 * | 0 | 0 | 0 | 0 |       0       |
                 * +---+---+-----------------------+
                 * | H |     Name Length (7+)      |
                 * +---+---------------------------+
                 * |  Name String (Length octets)  |
                 * +---+---------------------------+
                 * | H |     Value Length (7+)     |
                 * +---+---------------------------+
                 * | Value String (Length octets)  |
                 * +-------------------------------+
                 */

                index = ch & ~0xf0;

                if (index == 0x0f) {
                    stream->index = index;
                    stream->literal = 1;
                    state = sw_index;
                    break;
                }

                if (index == 0) {
                    state = sw_name_length;
                    break;
                }

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                             "http proxy literal header without indexing: %ui",
                               index);

                stream->index = index;
                stream->literal = 1;

                state = sw_value_length;
                break;
            }

            /* not reached */

            return NGX_ERROR;

        case sw_index:
            stream->index = stream->index + (ch & ~0x80);

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent http2 table index "
                              "with continuation flag");
                return NGX_ERROR;
            }

            if (stream->index > 61) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid http2 "
                              "table index: %ui", stream->index);
                return NGX_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header index: %ui", stream->index);

            state = sw_value_length;
            break;

        case sw_name_length:
            stream->field_huffman = ch & 0x80 ? 1 : 0;
            stream->field_length = ch & ~0x80;

            if (stream->field_length == 0x7f) {
                state = sw_name_length_2;
                break;
            }

            if (stream->field_length == 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent zero http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name_length_2:
            stream->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_name_length_3;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_3:
            stream->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_name_length_4;
                break;
            }

            state = sw_name;
            break;

        case sw_name_length_4:
            stream->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length");
                return NGX_ERROR;
            }

            state = sw_name;
            break;

        case sw_name:
            stream->name.len = stream->field_huffman ?
                               stream->field_length * 8 / 5
                               : stream->field_length;

            if (stream->name.len > stream->header_limit) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header name length: %uz",
                              stream->name.len);
                return NGX_ERROR;
            }

            stream->name.data = ngx_pnalloc(r->pool, stream->name.len + 1);
            if (stream->name.data == NULL) {
                return NGX_ERROR;
            }

            stream->field_end = stream->name.data;
            stream->field_rest = stream->field_length;
            stream->field_state = 0;

            state = sw_name_bytes;

            /* fall through */

        case sw_name_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy name: len:%uz h:%d last:%uz, rest:%uz",
                           stream->field_length,
                           stream->field_huffman,
                           last - p,
                           ctx->session->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) stream->field_rest);
            stream->field_rest -= size;

            if (stream->field_huffman) {
                if (ngx_http_huff_decode(&stream->field_state, p, size,
                                         &stream->field_end,
                                         stream->field_rest == 0,
                                         r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                stream->name.len = stream->field_end - stream->name.data;
                stream->name.data[stream->name.len] = '\0';

            } else {
                stream->field_end = ngx_cpymem(stream->field_end, p, size);
                stream->name.data[stream->name.len] = '\0';
            }

            p += size - 1;

            if (stream->field_rest == 0) {
                state = sw_value_length;
            }

            break;

        case sw_value_length:
            stream->field_huffman = ch & 0x80 ? 1 : 0;
            stream->field_length = ch & ~0x80;

            if (stream->field_length == 0x7f) {
                state = sw_value_length_2;
                break;
            }

            if (stream->field_length == 0) {
                ngx_str_set(&stream->value, "");
                goto done;
            }

            state = sw_value;
            break;

        case sw_value_length_2:
            stream->field_length += ch & ~0x80;

            if (ch & 0x80) {
                state = sw_value_length_3;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_3:
            stream->field_length += (ch & ~0x80) << 7;

            if (ch & 0x80) {
                state = sw_value_length_4;
                break;
            }

            state = sw_value;
            break;

        case sw_value_length_4:
            stream->field_length += (ch & ~0x80) << 14;

            if (ch & 0x80) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length");
                return NGX_ERROR;
            }

            state = sw_value;
            break;

        case sw_value:
            stream->value.len = stream->field_huffman ?
                                stream->field_length * 8 / 5
                                : stream->field_length;

            if (stream->value.len > stream->header_limit) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent too large http2 "
                              "header value length: %uz",
                              stream->value.len);
                return NGX_ERROR;
            }

            stream->value.data = ngx_pnalloc(r->pool, stream->value.len + 1);
            if (stream->value.data == NULL) {
                return NGX_ERROR;
            }

            stream->field_end = stream->value.data;
            stream->field_rest = stream->field_length;
            stream->field_state = 0;

            state = sw_value_bytes;

            /* fall through */

        case sw_value_bytes:

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy value: len:%uz h:%d last:%uz, rest:%uz",
                           stream->field_length,
                           stream->field_huffman,
                           last - p,
                           ctx->session->rest - (p - b->pos));

            size = ngx_min(last - p, (ssize_t) stream->field_rest);
            stream->field_rest -= size;

            if (stream->field_huffman) {
                if (ngx_http_huff_decode(&stream->field_state, p, size,
                                         &stream->field_end,
                                         stream->field_rest == 0,
                                         r->connection->log)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid encoded header");
                    return NGX_ERROR;
                }

                stream->value.len = stream->field_end - stream->value.data;
                stream->value.data[stream->value.len] = '\0';

            } else {
                stream->field_end = ngx_cpymem(stream->field_end, p, size);
                stream->value.data[stream->value.len] = '\0';
            }

            p += size - 1;

            if (stream->field_rest == 0) {
                goto done;
            }

            break;
        }

        continue;

    done:

        p++;
        ctx->session->rest -= p - b->pos;
        stream->fragment_state = sw_start;
        b->pos = p;

        if (stream->index) {
            stream->name = *ngx_http_v2_get_static_name(stream->index);
        }

        if (stream->index && !stream->literal) {
            stream->value = *ngx_http_v2_get_static_value(stream->index);
        }

        if (!stream->index) {
            if (ngx_http_proxy_v2_validate_header_name(r, &stream->name)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &stream->name, &stream->value);
                return NGX_ERROR;
            }
        }

        if (!stream->index || stream->literal) {
            if (ngx_http_proxy_v2_validate_header_value(r, &stream->value)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "upstream sent invalid header: \"%V: %V\"",
                              &stream->name, &stream->value);
                return NGX_ERROR;
            }
        }

        len = stream->name.len + stream->value.len;

        if (len > stream->header_limit) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent too large http2 header");
            return NGX_ERROR;
        }

        stream->header_limit -= len;

        return NGX_OK;
    }

    ctx->session->rest -= p - b->pos;
    stream->fragment_state = state;
    b->pos = p;

    if (ctx->session->rest > ctx->session->padding) {
        return NGX_AGAIN;
    }

    return NGX_DONE;
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_name(ngx_http_request_t *r, ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == ':' && i > 0) {
            return NGX_ERROR;
        }

        if (ch >= 'A' && ch <= 'Z') {
            return NGX_ERROR;
        }

        if (ch <= 0x20 || ch == 0x7f) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_validate_header_value(ngx_http_request_t *r, ngx_str_t *s)
{
    u_char      ch;
    ngx_uint_t  i;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];

        if (ch == '\0' || ch == CR || ch == LF) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_rst_stream(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_error_2,
        sw_error_3,
        sw_error_4
    } state;

    if (b->last - b->pos < (ssize_t) ctx->session->rest) {
        last = b->last;

    } else {
        last = b->pos + ctx->session->rest;
    }

    state = ctx->session->frame_state;

    if (state == sw_start) {
        if (ctx->session->rest != 4) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "upstream sent rst stream frame "
                          "with invalid length: %uz",
                          ctx->session->rest);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http proxy rst byte: %02Xd s:%d", ch, state);
#endif

        switch (state) {

        case sw_start:
            ctx->stream.error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;

        case sw_error_2:
            ctx->stream.error |= ch << 16;
            state = sw_error_3;
            break;

        case sw_error_3:
            ctx->stream.error |= ch << 8;
            state = sw_error_4;
            break;

        case sw_error_4:
            ctx->stream.error |= ch;
            state = sw_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy error: %ui", ctx->stream.error);

            break;
        }
    }

    ctx->session->rest -= p - b->pos;
    ctx->session->frame_state = state;
    b->pos = p;

    if (ctx->session->rest > 0) {
        return NGX_AGAIN;
    }

    ctx->session->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_http_proxy_v2_ctx_t *
ngx_http_proxy_v2_get_ctx(ngx_http_request_t *r)
{
    ngx_http_upstream_t           *u;
    ngx_http_proxy_v2_ctx_t       *ctx;
    ngx_http_proxy_v2_session_t   *session;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx->session == NULL) {
        u = r->upstream;
        session = NULL;

        if (ngx_http_proxy_v2_get_session(&u->peer, &session) != NGX_OK) {
            return NULL;
        }

        if (ngx_http_proxy_v2_join_session(r, ctx, session) != NGX_OK) {
            return NULL;
        }
    }

    return ctx;
}


/*
 * Makes the request a stream of the session: registers it (which assigns the
 * next odd stream id), admits it against the concurrent-stream cap, and gives
 * it its own connection.  NGX_BUSY (the session is at its cap) is not an
 * error of the request; callers that can open another connection do so, the
 * others treat it like NGX_ERROR, which sends the request through
 * ngx_http_upstream_next().
 *
 * The cap is min(local, peer); the local part comes from the first request
 * that created the session and is not changed by later ones.
 */

static ngx_int_t
ngx_http_proxy_v2_join_session(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx, ngx_http_proxy_v2_session_t *session)
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_proxy_loc_conf_t  *plcf;

    u = r->upstream;

    plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
    ngx_http_proxy_v2_set_local_concurrent_streams(session,
        plcf->http2_max_concurrent_streams);

    ctx->session = session;
    ctx->stream.request = r;

    if (ngx_http_proxy_v2_register_stream(session, &ctx->stream) != NGX_OK) {
        ctx->session = NULL;
        return NGX_ERROR;
    }

    rc = ngx_http_proxy_v2_session_admit(session, &ctx->stream);

    if (rc != NGX_OK) {
        ngx_http_proxy_v2_unregister_stream(&ctx->stream);
        ctx->session = NULL;
        return rc;
    }

    if (ngx_http_proxy_v2_create_stream_connection(&ctx->stream, u,
                                                   u->conf->buffer_size)
        != NGX_OK)
    {
        ngx_http_proxy_v2_unregister_stream(&ctx->stream);
        ctx->session = NULL;
        return NGX_ERROR;
    }

    ctx->free = u->peer.free;
    u->peer.free = ngx_http_proxy_v2_free_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_init_peer(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    ctx->get = u->peer.get;
    u->peer.get = ngx_http_proxy_v2_get_peer;

    return NGX_OK;
}


/*
 * Wraps the keepalive module's get().  When it hands out a connection that
 * carries a multiplexed session, the request joins that session right away,
 * busy or idle, instead of taking the connection over: upstream_connect()
 * would otherwise replace the handlers and c->data the live streams depend
 * on.  The request then continues on its own stream connection.
 *
 * A session that cannot take another stream (at its concurrent-stream cap,
 * going away, broken) is skipped: the slot taken in the cache is given back
 * and NGX_OK tells the caller to open a new connection to the same peer
 * the balancer already chose, so the request is not failed and no try is
 * used up.
 */

static ngx_int_t
ngx_http_proxy_v2_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_http_upstream_t          *u;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_session_t  *session;

    u = (ngx_http_upstream_t *) ((u_char *) pc
                                 - offsetof(ngx_http_upstream_t, peer));
    r = u->pipe->input_ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    rc = ctx->get(pc, data);

    if (rc != NGX_DONE) {
        return rc;
    }

    c = pc->connection;

    session = ngx_http_upstream_keepalive_get_mux(c);

    if (session == NULL) {
        return rc;
    }

    if (!session->goaway && !session->eof && !session->error_state
        && (session->concurrent_streams == 0
            || session->processing < session->concurrent_streams)
        && (session->processing != 0
            || ngx_http_proxy_v2_session_reusable(session)))
    {
        c->requests++;

        if (ngx_http_proxy_v2_join_session(r, ctx, session) == NGX_OK) {
            ngx_http_upstream_keepalive_mux_joined(pc, data);
            return NGX_DONE;
        }

        c->requests--;
    }

    pc->connection = NULL;
    pc->cached = 0;

    if (ngx_http_upstream_keepalive_mux_declined(pc, data) == 0) {

        /* an idle session that cannot be used any more */

#if (NGX_SSL)
        if (c->ssl) {
            c->ssl->no_wait_shutdown = 1;
            c->ssl->no_send_shutdown = 1;
            (void) ngx_ssl_shutdown(c);
        }
#endif

        ngx_destroy_pool(c->pool);
        ngx_close_connection(c);
    }

    return NGX_OK;
}


ngx_http_proxy_v2_stream_t *
ngx_http_proxy_v2_get_stream(ngx_http_request_t *r)
{
    ngx_http_proxy_v2_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    return ctx ? &ctx->stream : NULL;
}


static void
ngx_http_proxy_v2_restore(ngx_http_request_t *r,
    ngx_http_proxy_v2_ctx_t *ctx)
{
    ngx_http_upstream_t  *u;

    if (ctx == NULL || !ctx->stream.connection_created) {
        return;
    }

    u = r->upstream;
    ngx_http_proxy_v2_restore_connection(&ctx->stream, u);

    if (ctx->free) {
        u->peer.free = ctx->free;
        ctx->free = NULL;
    }

    ctx->session = NULL;
}


static void
ngx_http_proxy_v2_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_request_t       *r;
    ngx_http_proxy_v2_ctx_t  *ctx;
    ngx_event_free_peer_pt    free;

    r = pc->connection->data;
    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx == NULL) {
        return;
    }

    free = ctx->free;

    ngx_http_proxy_v2_restore(r, ctx);

    if (free) {
        free(pc, data, state);
    }
}


static ngx_int_t
ngx_http_proxy_v2_send_stream_window_update(
    ngx_http_proxy_v2_stream_t *stream)
{
    size_t                      n;
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                   "http proxy send stream window update: %uz",
                   stream->recv_window);

    for (cl = stream->out, ll = &stream->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_buf(stream);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;
    f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (stream->id & 0xff);

    n = NGX_HTTP_V2_MAX_WINDOW - stream->recv_window;
    stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_proxy_v2_get_buf(ngx_http_proxy_v2_stream_t *stream)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    cl = ngx_chain_get_free_buf(stream->request->pool, &stream->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {
        start = ngx_palloc(stream->request->pool,
                           2 * sizeof(ngx_http_proxy_v2_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }
    }

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8;
    b->tag = (ngx_buf_tag_t) &ngx_http_proxy_v2_body_output_filter;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


static void
ngx_http_proxy_v2_abort_request(ngx_http_request_t *r)
{
    ngx_http_proxy_v2_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort proxy http2 request");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx != NULL) {
        ngx_http_proxy_v2_restore(r, ctx);
    }

    return;
}


static void
ngx_http_proxy_v2_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_proxy_v2_ctx_t      *ctx;
    ngx_http_proxy_v2_session_t  *session;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize proxy http2 request");

    ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_v2_module);

    if (ctx != NULL) {
        session = ctx->session;

        ngx_http_proxy_v2_restore(r, ctx);

        if (session && !ngx_http_proxy_v2_session_reusable(session)) {
            r->upstream->keepalive = 0;
        }
    }

    return;
}
