
/*
 * Copyright (C) Zhidao HONG
 */


#ifndef _NGX_HTTP_UPSTREAM_KEEPALIVE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_KEEPALIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t  max_cached;
    ngx_uint_t  requests;
    ngx_msec_t  time;
    ngx_msec_t  timeout;
    ngx_uint_t  local; /* unsigned local:1; */
} ngx_http_upstream_keepalive_conf_t;

typedef struct ngx_http_upstream_keepalive_cache_s
    ngx_http_upstream_keepalive_cache_t;


const ngx_http_upstream_keepalive_conf_t *ngx_http_upstream_get_keepalive_conf(
    ngx_http_upstream_srv_conf_t *us);

/* Shared idle LRU.  Eviction must release the slot before returning. */
ngx_http_upstream_keepalive_cache_t *ngx_http_upstream_keepalive_cache(
    ngx_http_upstream_srv_conf_t *us, ngx_connection_t *c,
    ngx_connection_handler_pt evict);
void ngx_http_upstream_keepalive_release(
    ngx_http_upstream_keepalive_cache_t *item);


#endif /* _NGX_HTTP_UPSTREAM_KEEPALIVE_H_INCLUDED_ */
