
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t                         max_cached;
    ngx_uint_t                         requests;
    ngx_msec_t                         time;
    ngx_msec_t                         timeout;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_peer_pt     original_init_peer;

    ngx_uint_t                         local; /* unsigned  local:1; */

} ngx_http_upstream_keepalive_srv_conf_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

    ngx_http_upstream_conf_t          *tag;

    void                              *mux;     /* opaque, never dereferenced */
    ngx_uint_t                         active;  /* streams in flight on mux */

} ngx_http_upstream_keepalive_cache_t;


/* per-connection record of a multiplexed connection kept in the cache */

typedef struct {
    ngx_http_upstream_keepalive_cache_t  *item;
    ngx_connection_t                     *connection;
    ngx_event_handler_pt                  read_handler;
    ngx_event_handler_pt                  write_handler;
} ngx_http_upstream_keepalive_mux_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

    ngx_event_notify_peer_pt           original_notify;

    /* the multiplexed connection this request holds a stream on, if any */
    ngx_http_upstream_keepalive_cache_t  *item;
    ngx_connection_t                  *mux_conn;
    ngx_uint_t                         surplus; /* the balancer slot taken by
                                                 * get() is not needed: the
                                                 * connection already holds one
                                                 */

} ngx_http_upstream_keepalive_peer_data_t;


static ngx_int_t ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static ngx_uint_t ngx_http_upstream_keepalive_reusable(
    ngx_http_upstream_keepalive_peer_data_t *kp, ngx_connection_t *c,
    ngx_uint_t state);
static void ngx_http_upstream_keepalive_idle(
    ngx_http_upstream_keepalive_peer_data_t *kp, ngx_peer_connection_t *pc,
    ngx_connection_t *c, ngx_http_upstream_keepalive_cache_t *item);
static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_mux_read_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_mux_write_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close(ngx_connection_t *c);
static ngx_queue_t *ngx_http_upstream_keepalive_idle_victim(
    ngx_http_upstream_keepalive_srv_conf_t *conf);
static ngx_http_upstream_keepalive_mux_t *
    ngx_http_upstream_keepalive_find_mux(ngx_connection_t *c);
static void ngx_http_upstream_keepalive_mux_cleanup(void *data);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void ngx_http_upstream_notify_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

static void *ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_keepalive_init_main_conf(ngx_conf_t *cf,
    void *conf);
static char *ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_keepalive_commands[] = {

    { ngx_string("keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_keepalive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("keepalive_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, time),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, timeout),
      NULL },

    { ngx_string("keepalive_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, requests),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    ngx_http_upstream_keepalive_init_main_conf, /* init main configuration */

    ngx_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_keepalive_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_keepalive_module_ctx, /* module context */
    ngx_http_upstream_keepalive_commands,    /* module directives */
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


static ngx_int_t
ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_keepalive_module);

    kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    if (kcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->item = NULL;
    kp->mux_conn = NULL;
    kp->surplus = 0;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = ngx_http_upstream_free_keepalive_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_keepalive_save_session;
#endif

    if (r->upstream->peer.notify) {
        kp->original_notify = r->upstream->peer.notify;
        r->upstream->peer.notify = ngx_http_upstream_notify_keepalive_peer;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_int_t          rc;
    ngx_uint_t         busy;
    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    busy = 0;
    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (kp->conf->local && item->tag != kp->upstream->conf) {
            continue;
        }

        if (item->mux != NULL
            && (c->requests >= kp->conf->requests
                || ngx_current_msec - c->start_time > kp->conf->time))
        {
            continue;
        }

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            if (item->mux != NULL) {

                /* stays in the cache, shared by all streams */

                busy = item->active++;

                kp->item = item;
                kp->mux_conn = c;
                kp->surplus = busy != 0;

                goto found;
            }

            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->conf->free, q);

            goto found;
        }
    }

    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    if (!busy) {
        c->idle = 0;
        c->sent = 0;
        c->data = NULL;
        c->log = pc->log;
        c->read->log = pc->log;
        c->write->log = pc->log;
        c->pool->log = pc->log;

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }
    }

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}


static void
ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    u = kp->upstream;

    item = kp->item;
    c = kp->mux_conn;

    kp->item = NULL;
    kp->mux_conn = NULL;
    kp->surplus = 0;

    if (item != NULL && item->mux != NULL && item->connection == c) {

        /*
         * The request was a stream of a multiplexed connection.  While other
         * streams remain the connection stays as it is and keeps its single
         * balancer slot (round-robin conns/fails and least_conn count
         * connections, not streams): nothing to do here.  With the last
         * stream gone the usual checks decide whether the idle connection
         * is kept or closed, and the slot is given back once.
         */

        if (item->active) {
            item->active--;
        }

        if (item->active > 0) {
            return;
        }

        if (!ngx_http_upstream_keepalive_reusable(kp, c, state)) {
            pc->connection = NULL;
            ngx_http_upstream_keepalive_close(c);
            goto invalid;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "free keepalive peer: keeping connection %p", c);

        ngx_http_upstream_keepalive_idle(kp, pc, c, item);

        goto invalid;
    }

    /* cache valid connections */

    c = pc->connection;

    if (!ngx_http_upstream_keepalive_reusable(kp, c, state)) {
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (ngx_queue_empty(&kp->conf->free)) {

        q = ngx_http_upstream_keepalive_idle_victim(kp->conf);

        if (q == NULL) {

            /* every cached connection has streams in flight */

            goto invalid;
        }

        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

        ngx_http_upstream_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
    }

    ngx_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;
    item->tag = u->conf;

    ngx_http_upstream_keepalive_idle(kp, pc, c, item);

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


/* may the connection stay in the cache after the request */

static ngx_uint_t
ngx_http_upstream_keepalive_reusable(
    ngx_http_upstream_keepalive_peer_data_t *kp, ngx_connection_t *c,
    ngx_uint_t state)
{
    ngx_http_upstream_t  *u;

    u = kp->upstream;

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        return 0;
    }

    if (c->requests >= kp->conf->requests) {
        return 0;
    }

    if (ngx_current_msec - c->start_time > kp->conf->time) {
        return 0;
    }

    if (!u->keepalive) {
        return 0;
    }

    if (!u->request_body_sent) {
        return 0;
    }

    if (ngx_terminate || ngx_exiting) {
        return 0;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return 0;
    }

    return 1;
}


/* hand the connection over to the cache; the idle timer starts here */

static void
ngx_http_upstream_keepalive_idle(ngx_http_upstream_keepalive_peer_data_t *kp,
    ngx_peer_connection_t *pc, ngx_connection_t *c,
    ngx_http_upstream_keepalive_cache_t *item)
{
    ngx_http_upstream_keepalive_mux_t  *m;

    pc->connection = NULL;

    c->read->delayed = 0;
    ngx_add_timer(c->read, kp->conf->timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /*
     * An idle multiplexed connection is still a live protocol session: the
     * peer may send PING, SETTINGS or GOAWAY, which are not garbage.
     */

    m = ngx_http_upstream_keepalive_find_mux(c);

    if (m != NULL && m->item == item && m->read_handler != NULL) {
        c->read->handler = ngx_http_upstream_keepalive_mux_read_handler;

    } else {
        c->read->handler = ngx_http_upstream_keepalive_close_handler;
    }

    if (m != NULL && m->item == item && m->write_handler != NULL) {
        c->write->handler = ngx_http_upstream_keepalive_mux_write_handler;

    } else {
        c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
    }

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        c->read->handler(c->read);
    }
}


/*
 * Idle read event of a multiplexed connection: the session handler consumes
 * what the peer sent and sets c->close if the connection is of no more use
 * (GOAWAY, error, eof).  The idle timeout and c->close close it as usual.
 */

static void
ngx_http_upstream_keepalive_mux_read_handler(ngx_event_t *ev)
{
    ngx_connection_t                   *c;
    ngx_http_upstream_keepalive_mux_t  *m;

    c = ev->data;

    m = ngx_http_upstream_keepalive_find_mux(c);

    if (m != NULL && m->read_handler != NULL
        && !c->close && !c->read->timedout)
    {
        m->read_handler(ev);

        if (!c->close) {
            return;
        }
    }

    ngx_http_upstream_keepalive_close_handler(ev);
}


static void
ngx_http_upstream_keepalive_mux_write_handler(ngx_event_t *ev)
{
    ngx_connection_t                   *c;
    ngx_http_upstream_keepalive_mux_t  *m;

    c = ev->data;

    m = ngx_http_upstream_keepalive_find_mux(c);

    if (m != NULL && m->write_handler != NULL) {
        m->write_handler(ev);
    }

    if (c->close) {
        c->read->handler(c->read);
    }
}


static void
ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;
    ngx_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    ngx_http_upstream_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
}


static void
ngx_http_upstream_keepalive_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


/* the oldest cached connection that has no streams in flight, or NULL */

static ngx_queue_t *
ngx_http_upstream_keepalive_idle_victim(
    ngx_http_upstream_keepalive_srv_conf_t *conf)
{
    ngx_queue_t                          *q;
    ngx_http_upstream_keepalive_cache_t  *item;

    for (q = ngx_queue_last(&conf->cache);
         q != ngx_queue_sentinel(&conf->cache);
         q = ngx_queue_prev(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

        if (item->active == 0) {
            return q;
        }
    }

    return NULL;
}


static ngx_http_upstream_keepalive_mux_t *
ngx_http_upstream_keepalive_find_mux(ngx_connection_t *c)
{
    ngx_pool_cleanup_t  *cln;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_upstream_keepalive_mux_cleanup) {
            return cln->data;
        }
    }

    return NULL;
}


/* the connection is going away: do not leave a dangling cache entry */

static void
ngx_http_upstream_keepalive_mux_cleanup(void *data)
{
    ngx_queue_t                          *q;
    ngx_http_upstream_keepalive_mux_t    *m = data;
    ngx_http_upstream_keepalive_cache_t  *item;

    item = m->item;

    if (item == NULL || item->connection != m->connection) {

        /* the entry was already recycled for another connection */

        return;
    }

    for (q = ngx_queue_head(&item->conf->cache);
         q != ngx_queue_sentinel(&item->conf->cache);
         q = ngx_queue_next(q))
    {
        if (q == &item->queue) {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&item->conf->free, q);
            break;
        }
    }

    item->connection = NULL;
    item->mux = NULL;
    item->active = 0;
}


/*
 * Register (or update, or with mux == NULL drop) the multiplexed session of
 * connection "c" in the keepalive cache.  A new entry is created with one
 * stream in flight, so that a concurrent request can find the connection while
 * it is in use.  Must be called while c->data is still the request that owns
 * the connection.  Returns NGX_DECLINED if the connection cannot be shared
 * (keepalive is not configured, or the cache is full of busy entries).
 */

ngx_int_t
ngx_http_upstream_keepalive_set_mux(ngx_connection_t *c, void *mux,
    ngx_event_handler_pt read_handler, ngx_event_handler_pt write_handler)
{
    ngx_queue_t                              *q;
    ngx_uint_t                                cached;
    ngx_http_request_t                       *r;
    ngx_http_upstream_t                      *u;
    ngx_pool_cleanup_t                       *cln;
    ngx_http_upstream_keepalive_mux_t        *m;
    ngx_http_upstream_keepalive_cache_t      *item;
    ngx_http_upstream_keepalive_peer_data_t  *kp;

    m = ngx_http_upstream_keepalive_find_mux(c);

    if (m != NULL && m->item != NULL && m->item->connection == c) {

        if (mux != NULL) {
            m->item->mux = mux;
            m->read_handler = read_handler;
            m->write_handler = write_handler;
            return NGX_OK;
        }

        ngx_http_upstream_keepalive_mux_cleanup(m);
        m->item = NULL;

        return NGX_OK;
    }

    if (mux == NULL) {
        return NGX_OK;
    }

    r = c->data;

    if (r == NULL || r->upstream == NULL) {
        return NGX_DECLINED;
    }

    u = r->upstream;

    /* get() may be wrapped by the caller, free() is not yet */

    if (u->peer.free != ngx_http_upstream_free_keepalive_peer
        || u->peer.sockaddr == NULL)
    {
        return NGX_DECLINED;
    }

    kp = u->peer.data;

    /* pick the slot first, nothing is changed until it cannot fail */

    if (ngx_queue_empty(&kp->conf->free)) {
        q = ngx_http_upstream_keepalive_idle_victim(kp->conf);

        if (q == NULL) {
            return NGX_DECLINED;
        }

        cached = 1;

    } else {
        q = ngx_queue_head(&kp->conf->free);
        cached = 0;
    }

    if (m == NULL) {
        cln = ngx_pool_cleanup_add(c->pool,
                                   sizeof(ngx_http_upstream_keepalive_mux_t));
        if (cln == NULL) {
            return NGX_ERROR;
        }

        m = cln->data;
        m->item = NULL;
        m->connection = c;
        cln->handler = ngx_http_upstream_keepalive_mux_cleanup;
    }

    ngx_queue_remove(q);

    item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

    if (cached) {
        ngx_http_upstream_keepalive_close(item->connection);
    }

    ngx_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;
    item->tag = u->conf;
    item->socklen = u->peer.socklen;
    ngx_memcpy(&item->sockaddr, u->peer.sockaddr, u->peer.socklen);
    item->mux = mux;
    item->active = 1;

    kp->item = item;
    kp->mux_conn = c;
    kp->surplus = 0;

    m->item = item;
    m->read_handler = read_handler;
    m->write_handler = write_handler;

    return NGX_OK;
}


void *
ngx_http_upstream_keepalive_get_mux(ngx_connection_t *c)
{
    ngx_http_upstream_keepalive_mux_t  *m;

    m = ngx_http_upstream_keepalive_find_mux(c);

    if (m == NULL || m->item == NULL || m->item->connection != c) {
        return NULL;
    }

    return m->item->mux;
}


/*
 * The request joined the multiplexed connection that get() returned.  If the
 * connection was already in use it holds a balancer slot, and the one get()
 * has just taken for this request is given back right away.
 */

void
ngx_http_upstream_keepalive_mux_joined(ngx_peer_connection_t *pc, void *data)
{
    ngx_uint_t                                tries;
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    if (!kp->surplus) {
        return;
    }

    kp->surplus = 0;

    tries = pc->tries;

    kp->original_free_peer(pc, kp->data, 0);

    pc->tries = tries;
}


/*
 * The request will not use the connection get() returned after all.  Returns
 * the number of streams still on it; the slot get() took stays with the
 * request, for the new connection it is about to open.
 */

ngx_uint_t
ngx_http_upstream_keepalive_mux_declined(ngx_peer_connection_t *pc,
    void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    item = kp->item;

    kp->item = NULL;
    kp->mux_conn = NULL;
    kp->surplus = 0;

    if (item == NULL) {
        return 0;
    }

    if (item->active) {
        item->active--;
    }

    return item->active;
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void
ngx_http_upstream_notify_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_notify(pc, kp->data, type);
}


static void *
ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_peer = NULL;
     *     conf->local = 0;
     */

    conf->time = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->requests = NGX_CONF_UNSET_UINT;
    conf->max_cached = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_upstream_keepalive_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                                i, j;
    ngx_http_upstream_srv_conf_t            **uscfp;
    ngx_http_upstream_main_conf_t            *umcf;
    ngx_http_upstream_keepalive_cache_t      *cached;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        /* skip implicit upstreams */
        if (uscfp[i]->srv_conf == NULL) {
            continue;
        }

        kcf = ngx_http_conf_upstream_srv_conf(uscfp[i],
                                            ngx_http_upstream_keepalive_module);

        if (kcf->max_cached == 0) {
            continue;
        }

        ngx_conf_init_msec_value(kcf->time, 3600000);
        ngx_conf_init_msec_value(kcf->timeout, 60000);
        ngx_conf_init_uint_value(kcf->requests, 1000);

        if (kcf->max_cached == NGX_CONF_UNSET_UINT) {
            kcf->local = 1;
            kcf->max_cached = 32;
        }

        kcf->original_init_peer = uscfp[i]->peer.init;

        uscfp[i]->peer.init = ngx_http_upstream_init_keepalive_peer;

        /* allocate cache items and add to free queue */

        cached = ngx_pcalloc(cf->pool,
                 sizeof(ngx_http_upstream_keepalive_cache_t) * kcf->max_cached);
        if (cached == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_queue_init(&kcf->cache);
        ngx_queue_init(&kcf->free);

        for (j = 0; j < kcf->max_cached; j++) {
            ngx_queue_insert_head(&kcf->free, &cached[j].queue);
            cached[j].conf = kcf;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    ngx_int_t    n;
    ngx_str_t   *value;

    if (kcf->max_cached != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    kcf->max_cached = n;

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "local") == 0) {
            kcf->local = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
