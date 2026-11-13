
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


const ngx_http_upstream_keepalive_conf_t *ngx_http_upstream_get_keepalive_conf(
    ngx_http_upstream_srv_conf_t *us);


#endif /* _NGX_HTTP_UPSTREAM_KEEPALIVE_H_INCLUDED_ */
