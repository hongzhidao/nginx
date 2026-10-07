
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_proxy_v2_session.h>


static void ngx_http_proxy_v2_session_cleanup(void *data);
static void ngx_http_proxy_v2_session_idle_read(ngx_event_t *rev);
static void ngx_http_proxy_v2_session_idle_write(ngx_event_t *wev);
static void ngx_http_proxy_v2_refuse_streams(
    ngx_http_proxy_v2_session_t *session, ngx_rbtree_node_t *node);
static void ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev);
static void ngx_http_proxy_v2_session_write_handler(ngx_event_t *wev);
static ngx_int_t ngx_http_proxy_v2_session_dispatch(
    ngx_http_proxy_v2_session_t *session);
static ngx_int_t ngx_http_proxy_v2_dispatch_run(
    ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_wake_stream(
    ngx_http_proxy_v2_session_t *session);
static ssize_t ngx_http_proxy_v2_stream_recv(ngx_connection_t *c,
    u_char *buf, size_t size);
static ssize_t ngx_http_proxy_v2_stream_recv_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ssize_t ngx_http_proxy_v2_stream_send(ngx_connection_t *c,
    u_char *buf, size_t size);
static ngx_chain_t *ngx_http_proxy_v2_stream_send_chain(ngx_connection_t *c,
    ngx_chain_t *in, off_t limit);
static ngx_int_t ngx_http_proxy_v2_parse_goaway(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_window_update(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_parse_settings(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_validate_initial_window(
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel, ssize_t update);
static void ngx_http_proxy_v2_update_initial_window(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ssize_t update);
static ngx_int_t ngx_http_proxy_v2_parse_ping(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_skip_frame(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_discard_frame(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
static ngx_int_t ngx_http_proxy_v2_save_orphan(
    ngx_http_proxy_v2_session_t *session, ngx_http_upstream_t *u);
static void ngx_http_proxy_v2_flush_orphan(
    ngx_http_proxy_v2_session_t *session);
static ngx_int_t ngx_http_proxy_v2_send_settings_ack(
    ngx_http_proxy_v2_session_t *session);
static ngx_int_t ngx_http_proxy_v2_send_ping_ack(
    ngx_http_proxy_v2_session_t *session);
static ngx_chain_t *ngx_http_proxy_v2_get_control_buf(
    ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_send_rst_stream(
    ngx_http_proxy_v2_stream_t *stream, ngx_uint_t error_code);
static ngx_http_proxy_v2_stream_t *ngx_http_proxy_v2_any_other_stream(
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel,
    ngx_http_proxy_v2_stream_t *self);
static void ngx_http_proxy_v2_detach_stream(
    ngx_http_proxy_v2_stream_t *stream, ngx_http_proxy_v2_stream_t *sibling,
    ngx_http_upstream_t *u);
static void ngx_http_proxy_v2_queue_rst_stream(
    ngx_http_proxy_v2_stream_t *stream, ngx_uint_t error_code);
static ngx_uint_t ngx_http_proxy_v2_frame_stream_id(
    ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_wake_writer(ngx_http_proxy_v2_stream_t *stream);
static void ngx_http_proxy_v2_next_frame(ngx_http_proxy_v2_session_t *session);
static void ngx_http_proxy_v2_wake_writers(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
#if (NGX_DEBUG)
static void ngx_http_proxy_v2_check_session(
    ngx_http_proxy_v2_session_t *session);
#else
#define ngx_http_proxy_v2_check_session(session)
#endif


ngx_int_t
ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc,
    ngx_http_proxy_v2_session_t **session)
{
    ngx_connection_t    *c;
    ngx_pool_cleanup_t  *cln;

    c = pc->connection;

    if (pc->cached) {

        /* the session is stored in the real connection pool */

        for (cln = c->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_proxy_v2_session_cleanup) {
                *session = cln->data;
                break;
            }
        }

        if (*session == NULL) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "no session found for "
                          "keepalive http2 connection");
            return NGX_ERROR;
        }

        if (!ngx_http_proxy_v2_session_reusable(*session)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "keepalive http2 session is not reusable");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    cln = ngx_pool_cleanup_add(c->pool,
                               sizeof(ngx_http_proxy_v2_session_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_proxy_v2_session_cleanup;
    *session = cln->data;

    ngx_memzero(*session, sizeof(ngx_http_proxy_v2_session_t));

    (*session)->connection = c;
    ngx_rbtree_init(&(*session)->streams, &(*session)->streams_sentinel,
                    ngx_rbtree_insert_value);
    (*session)->output_tag =
                       (ngx_buf_tag_t) &ngx_http_proxy_v2_get_control_buf;
    (*session)->state = ngx_http_proxy_v2_st_start;
    (*session)->init_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    (*session)->send_window = NGX_HTTP_V2_DEFAULT_WINDOW;
    (*session)->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    (*session)->last_stream_id = 0;

    /*
     * the handlers and c->data the connection has right now are the ones
     * upstream_connect() installed for the first request; they are what the
     * connection is given back with when its last stream is gone
     */

    (*session)->connection_data = c->data;
    (*session)->read_handler = c->read->handler;
    (*session)->write_handler = c->write->handler;

    ngx_queue_init(&(*session)->waiting);

    /*
     * local_concurrent_streams/concurrent_streams are left at 0
     * (unset) here -- this function only has the peer connection, not
     * a request/config, to read the proxy_http2_max_concurrent_streams
     * directive from.  ngx_http_proxy_v2_get_ctx() sets
     * local_concurrent_streams (and derives concurrent_streams from
     * it) the first time a stream registers on this session, since
     * that call site has the request and can reach its loc_conf.
     */

    /*
     * From here on a concurrent request can find the connection in the
     * keepalive cache and join the session; DECLINED (no keepalive, or
     * the cache is full of busy connections) just means it is not shared.
     */

    if (ngx_http_upstream_keepalive_set_mux(c, *session,
                                            ngx_http_proxy_v2_session_idle_read,
                                            ngx_http_proxy_v2_session_idle_write)
        == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Sets the local half of the concurrent-stream cap
 * (proxy_http2_max_concurrent_streams) and recomputes the effective
 * cap session_admit() checks against.  Called once, the first time a
 * stream registers on a freshly created session
 * (ngx_http_proxy_v2_get_ctx()) -- ngx_http_proxy_v2_get_session()
 * itself cannot do this, since it only has the peer connection, not a
 * request, to read the directive's value from.  A no-op on a reused
 * (kept-alive) session, where local_concurrent_streams is already set
 * from whichever earlier request first created it; a later request
 * reusing the same connection is not allowed to silently lower or
 * raise a cap already in effect for streams potentially still live on
 * it.
 */

void
ngx_http_proxy_v2_set_local_concurrent_streams(
    ngx_http_proxy_v2_session_t *session, ngx_uint_t local)
{
    if (session->local_concurrent_streams != 0) {
        return;
    }

    session->local_concurrent_streams = local;

    session->concurrent_streams = session->peer_concurrent_streams
        ? ngx_min(local, session->peer_concurrent_streams)
        : local;
}


ngx_int_t
ngx_http_proxy_v2_register_stream(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (stream->registered || stream->session != NULL) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 stream is already registered");
        return NGX_ERROR;
    }

    if (session->last_stream_id > NGX_HTTP_V2_MAX_WINDOW - 2) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 session has no available stream identifiers");
        return NGX_ERROR;
    }

    if (session->last_stream_id == 0) {
        session->last_stream_id = 1;

    } else {
        session->last_stream_id += 2;
    }

    stream->session = session;
    stream->id = session->last_stream_id;
    stream->node.key = stream->id;
    stream->send_window = session->init_window;
    stream->recv_window = NGX_HTTP_V2_MAX_WINDOW;
    stream->registered = 1;

    ngx_rbtree_insert(&session->streams, &stream->node);

    return NGX_OK;
}


/*
 * Admits a registered stream for concurrent use of the connection,
 * replacing the old single-slot activate_stream() write gate.  Many
 * streams may be admitted at once, up to session->concurrent_streams
 * (min of the local cap and the peer's advertised
 * SETTINGS_MAX_CONCURRENT_STREAMS, see
 * ngx_http_proxy_v2_parse_settings()).  Admission is deliberately
 * separate from the write-turn gate (session->writer,
 * ngx_http_proxy_v2_body_output_filter()) -- an admitted stream is
 * free to build and send whenever it is its turn; it does not need
 * the physical connection right now to be admitted, only to actually
 * write.
 *
 * Returns NGX_BUSY (not NGX_ERROR) when the session is at capacity,
 * so the caller (ngx_http_proxy_v2_get_ctx()) can fall back to
 * opening a new connection instead of failing the request outright.
 */

ngx_int_t
ngx_http_proxy_v2_session_admit(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_stream_t *stream)
{
    if (!stream->registered || stream->session != session) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "cannot admit unregistered http2 stream");
        return NGX_ERROR;
    }

    if (session->goaway) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 session is going away");
        return NGX_ERROR;
    }

    if (session->concurrent_streams
        && session->processing >= session->concurrent_streams)
    {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "http2 session at concurrent stream limit: %ui",
                      session->concurrent_streams);
        return NGX_BUSY;
    }

    session->processing++;
    stream->admitted = 1;

    if (session->active_stream == NULL) {
        session->active_stream = stream;
    }

    ngx_http_proxy_v2_check_session(session);

    return NGX_OK;
}


void
ngx_http_proxy_v2_deactivate_stream(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_queue_t                  *q;
    ngx_http_proxy_v2_session_t  *session;
    ngx_http_proxy_v2_stream_t   *waiter;

    session = stream->session;

    if (session == NULL) {
        return;
    }

    if (session->active_stream == stream) {
        session->active_stream = NULL;
    }

    if (session->writer == stream) {

        /*
         * This stream held the write turn and is being torn down
         * (e.g. the client aborted mid-write) without ever releasing
         * it through ngx_http_proxy_v2_body_output_filter()'s own
         * release path -- wake the next waiter here instead, or it
         * would otherwise never be woken at all and stay parked on
         * session->waiting indefinitely.
         */

        session->writer = NULL;

        if (!ngx_queue_empty(&session->waiting)) {
            q = ngx_queue_head(&session->waiting);
            waiter = ngx_queue_data(q, ngx_http_proxy_v2_stream_t,
                                    wait_link);

            if (waiter->write != NULL) {
                ngx_post_event(waiter->write, &ngx_posted_events);
            }
        }
    }

    if (stream->waiting) {
        ngx_queue_remove(&stream->wait_link);
        stream->waiting = 0;
    }

    if (stream->admitted) {
        if (session->processing) {
            session->processing--;
        }

        stream->admitted = 0;
    }
}


void
ngx_http_proxy_v2_unregister_stream(ngx_http_proxy_v2_stream_t *stream)
{
    ngx_http_proxy_v2_session_t  *session;

    session = stream->session;

    if (session == NULL || !stream->registered) {
        return;
    }

    ngx_http_proxy_v2_deactivate_stream(stream);
    ngx_rbtree_delete(&session->streams, &stream->node);

    stream->session = NULL;
    stream->registered = 0;

    ngx_http_proxy_v2_check_session(session);
}


#if (NGX_DEBUG)

static ngx_uint_t
ngx_http_proxy_v2_count_streams(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    if (node == sentinel) {
        return 0;
    }

    return 1 + ngx_http_proxy_v2_count_streams(node->left, sentinel)
             + ngx_http_proxy_v2_count_streams(node->right, sentinel);
}


static void
ngx_http_proxy_v2_check_session(ngx_http_proxy_v2_session_t *session)
{
    ngx_uint_t  n;

    n = ngx_http_proxy_v2_count_streams(session->streams.root,
                                        session->streams.sentinel);

    if (session->processing != n) {
        ngx_log_error(NGX_LOG_ALERT, session->connection->log, 0,
                      "http2 session processing %ui != registered streams %ui",
                      session->processing, n);
        ngx_debug_point();
    }

    if (session->writer != NULL
        && ngx_http_proxy_v2_find_stream(session, session->writer->id)
           != session->writer)
    {
        ngx_log_error(NGX_LOG_ALERT, session->connection->log, 0,
                      "http2 write turn held by an unregistered stream");
        ngx_debug_point();
    }
}

#endif


/*
 * Looks up a registered stream by its HTTP/2 stream id in the session's
 * rbtree (populated by ngx_http_proxy_v2_register_stream(), keyed by
 * stream->id -- see the node.key assignment there).  This is what
 * makes inbound frame dispatch capable of telling "the currently
 * targeted stream" apart from "some other, still-registered stream"
 * and from "no such stream at all", rather
 * than assuming any non-matching id is a fatal protocol error --
 * necessary now that more than one stream may legitimately be
 * registered concurrently.  Walks the tree exactly as any other
 * rbtree consumer would (mirrors ngx_resolver_lookup_name()'s
 * rbtree-by-key idiom in src/core/ngx_resolver.c).  Returns NULL if
 * no stream with this id is currently registered on the session.
 */

ngx_http_proxy_v2_stream_t *
ngx_http_proxy_v2_find_stream(ngx_http_proxy_v2_session_t *session,
    ngx_uint_t id)
{
    ngx_rbtree_node_t  *node, *sentinel;

    node = session->streams.root;
    sentinel = session->streams.sentinel;

    while (node != sentinel) {

        if (id < node->key) {
            node = node->left;
            continue;
        }

        if (id > node->key) {
            node = node->right;
            continue;
        }

        /* id == node->key */

        return ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
    }

    return NULL;
}


/*
 * Finds any one registered stream other than "self" -- used only by
 * ngx_http_proxy_v2_restore_connection() to repoint the physical
 * connection's c->data at a still-live sibling stream when the
 * detaching stream is not the last one on the session, so that a
 * real socket-level event on the physical connection continues to
 * reach a live request rather than the one being torn down.  Which
 * sibling is chosen is arbitrary; any registered stream's request
 * shares the same session and can reach it equally well.
 */

static ngx_http_proxy_v2_stream_t *
ngx_http_proxy_v2_any_other_stream(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ngx_http_proxy_v2_stream_t *self)
{
    ngx_http_proxy_v2_stream_t  *stream, *found;

    if (node == sentinel) {
        return NULL;
    }

    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

    if (stream != self) {
        return stream;
    }

    found = ngx_http_proxy_v2_any_other_stream(node->left, sentinel, self);

    if (found != NULL) {
        return found;
    }

    return ngx_http_proxy_v2_any_other_stream(node->right, sentinel, self);
}


ngx_int_t
ngx_http_proxy_v2_create_stream_connection(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_upstream_t *u, size_t buffer_size)
{
    ngx_connection_t             *c, *sc;
    ngx_event_t                  *rev, *wev;
    ngx_http_proxy_v2_session_t  *session;

    if (stream->connection_created) {
        return NGX_OK;
    }

    session = stream->session;
    c = session->connection;

    if (session->buffer.start == NULL) {
        buffer_size = ngx_max(buffer_size,
                              2 * NGX_HTTP_V2_DEFAULT_FRAME_SIZE + 18);

        session->buffer.start = ngx_palloc(c->pool, buffer_size);
        if (session->buffer.start == NULL) {
            return NGX_ERROR;
        }

        session->buffer.pos = session->buffer.start;
        session->buffer.last = session->buffer.start;
        session->buffer.end = session->buffer.start + buffer_size;
        session->buffer.temporary = 1;
    }

    sc = ngx_pcalloc(stream->request->pool, sizeof(ngx_connection_t));
    rev = ngx_pcalloc(stream->request->pool, sizeof(ngx_event_t));
    wev = ngx_pcalloc(stream->request->pool, sizeof(ngx_event_t));
    if (sc == NULL || rev == NULL || wev == NULL) {
        return NGX_ERROR;
    }

    sc->data = stream->request;
    sc->read = rev;
    sc->write = wev;
    sc->fd = (ngx_socket_t) -1;
    sc->shared = 1;
    sc->recv = ngx_http_proxy_v2_stream_recv;
    sc->recv_chain = ngx_http_proxy_v2_stream_recv_chain;
    sc->send = ngx_http_proxy_v2_stream_send;
    sc->send_chain = ngx_http_proxy_v2_stream_send_chain;
    sc->log = c->log;
    sc->pool = stream->request->pool;
    sc->type = c->type;
    sc->sockaddr = c->sockaddr;
    sc->socklen = c->socklen;
    sc->addr_text = c->addr_text;
    sc->local_sockaddr = c->local_sockaddr;
    sc->local_socklen = c->local_socklen;
    sc->buffered = c->buffered;
#if (NGX_SSL)
    sc->ssl = c->ssl;
#endif

    /*
     * Only the first stream attached since the connection was last idle
     * takes the connection's handlers over; later ones find them taken
     * already.  The originals to give back were stashed once, when the
     * session was created (see ngx_http_proxy_v2_get_session()), because
     * a stream joining an idle or busy session never goes through
     * upstream_connect() and so the connection still carries whatever the
     * keepalive cache left on it.  c->data must name a live request: the
     * session handlers resolve the session through it.
     */

    if (!session->handlers_saved) {
        session->handlers_saved = 1;

        c->data = stream->request;
        c->read->handler = ngx_http_proxy_v2_session_read_handler;
        c->write->handler = ngx_http_proxy_v2_session_write_handler;
    }

    rev->data = sc;
    rev->handler = session->read_handler;
    rev->log = c->read->log;
    rev->active = 1;

    wev->data = sc;
    wev->handler = session->write_handler;
    wev->log = c->write->log;
    wev->write = 1;
    wev->active = 1;
    wev->ready = c->write->ready;

    stream->connection = sc;
    stream->read = rev;
    stream->write = wev;
    stream->connection_created = 1;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    u->peer.connection = sc;
    if (u->pipe) {
        u->pipe->upstream = sc;
    }

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }

    ngx_add_timer(c->read, u->conf->read_timeout);

    return NGX_OK;
}


/*
 * Reset an abandoned stream on the wire.  Called from
 * ngx_http_proxy_v2_restore_connection() at the point where the stream
 * is about to be torn down and unregistered -- there is no guarantee
 * the request's own output path
 * (ngx_http_proxy_v2_body_output_filter(), which drains stream->out
 * and session->out through ngx_chain_writer()) will ever run again for
 * this stream, so queuing the frame the way the other send_* functions
 * in this file do is not safe here: it would sit on stream->out
 * forever.  The frame is instead built into a small stack buffer and
 * written directly on the physical connection, best effort -- if the
 * socket is not ready or only accepts part of it, the RST is simply
 * not delivered; the peer's own stream idle/reset timeout is the
 * fallback, exactly as it is today without this function.
 */

static void
ngx_http_proxy_v2_send_rst_stream(ngx_http_proxy_v2_stream_t *stream,
    ngx_uint_t error_code)
{
    u_char                      buf[sizeof(ngx_http_proxy_v2_frame_t) + 4];
    ngx_connection_t           *c;
    ngx_http_proxy_v2_frame_t  *f;

    if (stream->rst_sent || !stream->registered) {
        return;
    }

    c = stream->session->connection;

    if (!c->write->ready) {
        return;
    }

    f = (ngx_http_proxy_v2_frame_t *) buf;
    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));

    f->length_2 = 4;
    f->type = NGX_HTTP_V2_RST_STREAM_FRAME;
    f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (stream->id & 0xff);

    buf[sizeof(ngx_http_proxy_v2_frame_t) + 0] =
                                        (u_char) ((error_code >> 24) & 0xff);
    buf[sizeof(ngx_http_proxy_v2_frame_t) + 1] =
                                        (u_char) ((error_code >> 16) & 0xff);
    buf[sizeof(ngx_http_proxy_v2_frame_t) + 2] =
                                        (u_char) ((error_code >> 8) & 0xff);
    buf[sizeof(ngx_http_proxy_v2_frame_t) + 3] =
                                        (u_char) (error_code & 0xff);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http proxy send rst stream: %ui, error: %ui",
                   stream->id, error_code);

    /*
     * Best effort: c->send() returning less than the whole frame, or
     * NGX_AGAIN, or NGX_ERROR, all mean the RST was not fully
     * delivered.  There is no retry path here (see the function
     * comment above), so the outcome is not distinguished any
     * further; stream->rst_sent is still set to avoid ever trying
     * again for this stream.
     */

    c->send(c, buf, sizeof(buf));

    stream->rst_sent = 1;
}


void
ngx_http_proxy_v2_restore_connection(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_upstream_t *u)
{
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *session;
    ngx_http_proxy_v2_stream_t   *sibling;

    if (!stream->connection_created) {
        return;
    }

    session = stream->session;
    c = session->connection;

    sibling = ngx_http_proxy_v2_any_other_stream(session->streams.root,
                                                 session->streams.sentinel,
                                                 stream);

    /*
     * The peer still considers this stream open unless it already
     * ended it itself (stream->rst) or we already saw it finish
     * cleanly (stream->done).  Tell it to stop; see the function
     * comment on ngx_http_proxy_v2_send_rst_stream() for why this
     * cannot simply be queued the way session->out control frames
     * are -- except when a sibling remains, see below.
     */

    if (!stream->done && !stream->rst) {

        /*
         * With a sibling still on the connection a direct c->send() may
         * land inside another stream's half-written frame, or itself be
         * cut short, either of which corrupts the shared connection; the
         * frame is queued instead and goes out with the sibling's next
         * write.
         */

        if (sibling != NULL) {
            ngx_http_proxy_v2_queue_rst_stream(stream,
                                               NGX_HTTP_PROXY_V2_CANCEL);

        } else {
            ngx_http_proxy_v2_send_rst_stream(stream,
                                              NGX_HTTP_PROXY_V2_CANCEL);
        }
    }

    if (stream->read->posted) {
        ngx_delete_posted_event(stream->read);
    }

    if (stream->write->posted) {
        ngx_delete_posted_event(stream->write);
    }

    if (stream->read->timer_set) {
        ngx_del_timer(stream->read);
    }

    if (stream->write->timer_set) {
        ngx_del_timer(stream->write);
    }

    /*
     * The physical connection's handlers/c->data are only restored to
     * their pre-hijack originals by the LAST stream to detach; while a
     * sibling remains, the connection stays hijacked and is only
     * handed over, see ngx_http_proxy_v2_detach_stream().
     */

    if (sibling != NULL) {
        ngx_http_proxy_v2_detach_stream(stream, sibling, u);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    c->data = session->connection_data;

#if (NGX_SSL)
    if (c->ssl && c->ssl->saved_read_handler
        == ngx_http_proxy_v2_session_read_handler)
    {
        c->ssl->saved_read_handler = session->read_handler;

    } else
#endif
    {
        c->read->handler = session->read_handler;
    }

#if (NGX_SSL)
    if (c->ssl && c->ssl->saved_write_handler
        == ngx_http_proxy_v2_session_write_handler)
    {
        c->ssl->saved_write_handler = session->write_handler;

    } else
#endif
    {
        c->write->handler = session->write_handler;
    }

    session->handlers_saved = 0;

    u->peer.connection = c;
    if (u->pipe) {
        u->pipe->upstream = c;
    }

    stream->connection_created = 0;
    stream->connection = NULL;
    stream->read = NULL;
    stream->write = NULL;

    ngx_http_proxy_v2_unregister_stream(stream);
}


/*
 * Detach a stream while at least one sibling stays on the connection: the
 * physical connection, its handlers and its keepalive entry are not touched,
 * only this stream's share of them is dropped.  u->peer.connection is cleared
 * so that nothing downstream (the keepalive free(), ngx_http_upstream_next(),
 * ngx_http_upstream_finalize_request()) can mistake the fake stream
 * connection or the shared connection for one this request owns; free()
 * still runs afterwards with a NULL connection, which the keepalive module
 * passes straight through to the balancer so that its per-get accounting
 * stays paired.
 */

static void
ngx_http_proxy_v2_detach_stream(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_proxy_v2_stream_t *sibling, ngx_http_upstream_t *u)
{
    ngx_connection_t             *c;
    ngx_uint_t                    owned_frame;
    ngx_http_proxy_v2_session_t  *session;

    session = stream->session;
    c = session->connection;

    /*
     * What this stream left half-written has to reach the peer anyway or
     * the framing breaks: the session takes over the unsent bytes and
     * sends them before anyone else writes (the stream is reset after).
     */

    if (session->writer == stream && u->writer.out != NULL) {
        if (ngx_http_proxy_v2_save_orphan(session, u) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "http2 stream %ui left a frame incomplete, "
                          "closing the session", stream->id);

            session->goaway = 1;
            session->error_state = 1;
        }
    }

    owned_frame = session->stream_frame
                  && ngx_http_proxy_v2_frame_stream_id(session) == stream->id;

    /*
     * The part of a frame of this stream that was not handed over yet is
     * still in the buffer and the socket; its length is known, so it is
     * dropped and the siblings' frames behind it stay readable.
     */

    if (owned_frame) {
        session->discard_rest = session->frame_rest;
        session->frame_rest = 0;
        session->frame_sent = sizeof(session->frame_header);
    }

    if (c->data == stream->request) {
        c->data = sibling->request;
    }

    /* the connection's log must not point into a request that is going */

    if (c->log == stream->request->connection->log) {
        c->log = sibling->request->connection->log;
        c->read->log = c->log;
        c->write->log = c->log;
        c->pool->log = c->log;
    }

    if (u->pipe && u->pipe->upstream == stream->connection) {
        u->pipe->upstream = NULL;
    }

    u->peer.connection = NULL;

    stream->connection_created = 0;
    stream->connection = NULL;
    stream->read = NULL;
    stream->write = NULL;

    /* releases the write turn and wakes the next waiter */

    ngx_http_proxy_v2_unregister_stream(stream);

    if (session->active_stream == NULL) {
        session->active_stream = sibling;
    }

    /*
     * The frame of the departing stream is still staged, and nothing will
     * advance past it unless someone asks for data: the frames of the
     * siblings, and the window updates the upstream is about to send, queue
     * up behind it.
     */

    if (owned_frame && !session->error_state) {
        ngx_http_proxy_v2_next_frame(session);
    }

    if (session->orphan != NULL) {
        ngx_http_proxy_v2_flush_orphan(session);
    }

    if (session->out != NULL && sibling->write != NULL) {
        ngx_post_event(sibling->write, &ngx_posted_events);
    }
}


static ngx_int_t
ngx_http_proxy_v2_save_orphan(ngx_http_proxy_v2_session_t *session,
    ngx_http_upstream_t *u)
{
    u_char       *p;
    size_t        n;
    ssize_t       rd;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    n = 0;

    for (cl = u->writer.out; cl; cl = cl->next) {
        n += ngx_buf_size(cl->buf);
    }

    if (n == 0) {
        return NGX_OK;
    }

    p = ngx_alloc(n, session->connection->log);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy orphan output: %uz", n);

    session->orphan = p;
    session->orphan_len = n;
    session->orphan_sent = 0;

    for (cl = u->writer.out; cl; cl = cl->next) {
        b = cl->buf;
        n = ngx_buf_size(b);

        if (n == 0) {
            continue;
        }

        if (ngx_buf_in_memory(b)) {
            p = ngx_cpymem(p, b->pos, n);
            b->pos = b->last;

        } else {
            rd = ngx_read_file(b->file, p, n, b->file_pos);

            if (rd != (ssize_t) n) {
                ngx_free(session->orphan);
                session->orphan = NULL;
                session->orphan_len = 0;
                return NGX_ERROR;
            }

            p += n;
            b->file_pos = b->file_last;
        }
    }

    u->writer.out = NULL;

    return NGX_OK;
}


/* the turn stays blocked while orphan is set; waiters are woken when done */

static void
ngx_http_proxy_v2_flush_orphan(ngx_http_proxy_v2_session_t *session)
{
    ssize_t                      n;
    ngx_queue_t                 *q;
    ngx_connection_t            *c;
    ngx_http_proxy_v2_stream_t  *waiter;

    c = session->connection;

    while (session->orphan_sent < session->orphan_len) {
        n = c->send(c, session->orphan + session->orphan_sent,
                    session->orphan_len - session->orphan_sent);

        if (n == NGX_AGAIN) {
            return;
        }

        if (n == NGX_ERROR) {
            session->goaway = 1;
            session->error_state = 1;
            break;
        }

        session->orphan_sent += n;
    }

    ngx_free(session->orphan);
    session->orphan = NULL;
    session->orphan_len = 0;
    session->orphan_sent = 0;

    if (!ngx_queue_empty(&session->waiting)) {
        q = ngx_queue_head(&session->waiting);
        waiter = ngx_queue_data(q, ngx_http_proxy_v2_stream_t, wait_link);

        if (waiter->write != NULL) {
            ngx_post_event(waiter->write, &ngx_posted_events);
        }
    }
}


static void
ngx_http_proxy_v2_queue_rst_stream(ngx_http_proxy_v2_stream_t *stream,
    ngx_uint_t error_code)
{
    ngx_chain_t                 *cl, **ll;
    ngx_http_proxy_v2_frame_t   *f;
    ngx_http_proxy_v2_session_t *session;

    if (stream->rst_sent || !stream->registered) {
        return;
    }

    session = stream->session;

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy queue rst stream: %ui, error: %ui",
                   stream->id, error_code);

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_RST_STREAM_FRAME;
    f->stream_id_0 = (u_char) ((stream->id >> 24) & 0xff);
    f->stream_id_1 = (u_char) ((stream->id >> 16) & 0xff);
    f->stream_id_2 = (u_char) ((stream->id >> 8) & 0xff);
    f->stream_id_3 = (u_char) (stream->id & 0xff);

    *cl->buf->last++ = (u_char) ((error_code >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((error_code >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((error_code >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (error_code & 0xff);

    *ll = cl;

    stream->rst_sent = 1;
}


ngx_uint_t
ngx_http_proxy_v2_session_reusable(ngx_http_proxy_v2_session_t *session)
{
    if (session->stream_frame
        && session->frame_sent == sizeof(session->frame_header)
        && session->frame_rest == 0)
    {
        session->stream_frame = 0;
        session->frame_validated = 0;
        session->frame_sent = 0;
    }

    return session->out == NULL
           && session->busy == NULL
           && !session->stream_frame
           && session->active_stream == NULL
           && session->writer == NULL
           && session->orphan == NULL
           && session->processing == 0
           && session->streams.root == session->streams.sentinel
           && session->buffer.pos == session->buffer.last
           && session->dispatch.state == ngx_http_proxy_v2_st_start
           && session->discard_rest == 0
           && !session->discarding
           && !session->frame_validated
           && !session->goaway
           && !session->eof
           && !session->error_state
           && !session->connection->read->eof
           && !session->connection->read->error
           && !session->connection->read->timedout
           && !session->connection->write->error
           && !session->connection->write->timedout
           && !session->connection->buffered
#if (NGX_SSL)
           && (session->connection->ssl == NULL
               || (session->connection->ssl->saved_read_handler == NULL
                   && session->connection->ssl->saved_write_handler == NULL))
#endif
           ;
}


static void
ngx_http_proxy_v2_session_read_handler(ngx_event_t *rev)
{
    ssize_t                       n;
    ngx_uint_t                    again;
    ngx_buf_t                    *b;
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_proxy_v2_session_t  *session;
    ngx_http_proxy_v2_stream_t   *stream;

    c = rev->data;
    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return;
    }

    session = stream->session;
    b = &session->buffer;

    if (session->active_stream == NULL) {
        return;
    }

    if (rev->timedout) {
        session->error_state = 1;
        if (session->active_stream) {
            session->active_stream->read->timedout = 1;
        }
        ngx_http_proxy_v2_wake_stream(session);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for ( ;; ) {
        if (b->pos != b->start && b->pos != b->last) {
            b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
            b->pos = b->start;

        } else if (b->pos == b->last) {
            b->pos = b->start;
            b->last = b->start;
        }

        again = 0;

        while (b->last < b->end) {
            n = c->recv(c, b->last, b->end - b->last);

            if (n == NGX_AGAIN) {
                again = 1;
                break;
            }

            if (n == NGX_ERROR) {
                session->error_state = 1;
                break;
            }

            if (n == 0) {
                session->eof = 1;
                break;
            }

            b->last += n;
        }

        if (ngx_http_proxy_v2_session_dispatch(session) != NGX_OK) {
            session->error_state = 1;
        }

        if (session->stream_frame || session->eof || session->error_state
            || again || !rev->ready)
        {
            break;
        }

        if (b->last == b->end && b->pos == b->start) {
            session->error_state = 1;
            break;
        }
    }

    ngx_http_proxy_v2_wake_stream(session);

    if (!session->eof && !session->error_state) {
        ngx_add_timer(rev, session->active_stream->request->upstream->conf
                                                   ->read_timeout);
    }
}


static void
ngx_http_proxy_v2_session_write_handler(ngx_event_t *wev)
{
    ngx_connection_t             *c;
    ngx_http_request_t           *r;
    ngx_http_upstream_t          *u;
    ngx_http_proxy_v2_stream_t   *active;
    ngx_http_proxy_v2_session_t  *session;
    ngx_http_proxy_v2_stream_t   *stream;

    c = wev->data;
    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return;
    }

    session = stream->session;
    u = r->upstream;

    if (session->orphan != NULL) {
        ngx_http_proxy_v2_flush_orphan(session);

        if (session->orphan != NULL) {
            return;
        }
    }

    r->main->count++;

    u->peer.connection = c;
    session->write_handler(wev);

    active = ngx_http_proxy_v2_get_stream(r);

    if (active == stream && stream->session == session
        && c->write->handler == ngx_http_proxy_v2_session_write_handler
        && u->peer.connection == c && stream->connection_created)
    {
        u->peer.connection = stream->connection;
        stream->write->ready = c->write->ready;
        stream->connection->buffered = c->buffered;
    }

    ngx_http_finalize_request(r, NGX_DONE);
}


/*
 * A stream-scoped frame for an id that is not registered.  Ids already used
 * belong to streams that have finished or were abandoned (late frames are
 * expected: the peer cannot know yet), they are dropped, but a DATA frame
 * still counts against the connection window.  An id never used is a
 * connection error.  HPACK has no dynamic table here (table size 0), so
 * dropping a header block cannot desynchronise anything.
 */

static ngx_int_t
ngx_http_proxy_v2_discard_frame(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    ngx_int_t  rc;

    if (!session->discarding) {

        if (session->type == NGX_HTTP_V2_HEADERS_FRAME
            || session->type == NGX_HTTP_V2_DATA_FRAME
            || session->type == NGX_HTTP_V2_CONTINUATION_FRAME
            || session->type == NGX_HTTP_V2_RST_STREAM_FRAME)
        {
            if ((session->stream_id & 1) == 0
                || session->stream_id > session->last_stream_id)
            {
                ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                              "upstream sent frame %d for idle stream %ui",
                              session->type, session->stream_id);
                ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
                return NGX_ERROR;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                       "http proxy frame %d for closed stream %ui dropped",
                       session->type, session->stream_id);

        if (session->type == NGX_HTTP_V2_DATA_FRAME) {

            if (session->rest > session->recv_window) {
                ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                              "upstream violated connection flow control, "
                              "received %uz data frame with window %uz",
                              session->rest, session->recv_window);
                ngx_http_proxy_v2_send_goaway(session,
                                         NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR);
                return NGX_ERROR;
            }

            session->recv_window -= session->rest;

            if (session->recv_window < NGX_HTTP_V2_MAX_WINDOW / 4) {
                if (ngx_http_proxy_v2_send_connection_window_update(session)
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }

                ngx_post_event(session->connection->write,
                               &ngx_posted_events);
            }
        }

        session->discarding = 1;
    }

    rc = ngx_http_proxy_v2_skip_frame(session, b);

    if (rc == NGX_OK) {
        session->discarding = 0;
    }

    return rc;
}


void
ngx_http_proxy_v2_swap_scratch(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_scratch_t *scratch)
{
    ngx_http_proxy_v2_scratch_t  t;

    t.state = session->state;
    t.frame_state = session->frame_state;
    t.rest = session->rest;
    t.stream_id = session->stream_id;
    t.type = session->type;
    t.flags = session->flags;
    t.padding = session->padding;

    session->state = scratch->state;
    session->frame_state = scratch->frame_state;
    session->rest = scratch->rest;
    session->stream_id = scratch->stream_id;
    session->type = scratch->type;
    session->flags = scratch->flags;
    session->padding = scratch->padding;

    *scratch = t;
}


static ngx_int_t
ngx_http_proxy_v2_session_dispatch(ngx_http_proxy_v2_session_t *session)
{
    ngx_int_t  rc;

    ngx_http_proxy_v2_swap_scratch(session, &session->dispatch);
    rc = ngx_http_proxy_v2_dispatch_run(session);
    ngx_http_proxy_v2_swap_scratch(session, &session->dispatch);

    return rc;
}


static ngx_int_t
ngx_http_proxy_v2_dispatch_run(ngx_http_proxy_v2_session_t *session)
{
    ngx_int_t                    rc;
    size_t                       n;
    ngx_buf_t                   *b;
    ngx_http_proxy_v2_stream_t  *target;

    b = &session->buffer;

    for ( ;; ) {
        if (session->discard_rest) {
            n = ngx_min(session->discard_rest, (size_t) (b->last - b->pos));

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy discard: %uz of %uz",
                           n, session->discard_rest);

            b->pos += n;
            session->discard_rest -= n;

            if (session->discard_rest) {
                return NGX_OK;
            }
        }

        if (session->stream_frame) {
            return NGX_OK;
        }

        if (session->state < ngx_http_proxy_v2_st_payload) {
            rc = ngx_http_proxy_v2_parse_frame(session, b);
            if (rc == NGX_AGAIN) {
                return NGX_OK;
            }
            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        rc = ngx_http_proxy_v2_process_control_frame(session, b);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc == NGX_OK) {
            continue;
        }

        /*
         * This is a stream-scoped frame (process_control_frame()
         * returned NGX_DECLINED for it -- HEADERS/DATA/CONTINUATION/
         * RST_STREAM).  Retarget session->active_stream to the frame's
         * real owner via the stream registry before staging it into
         * frame_header/stream_frame, so that delivery
         * (ngx_http_proxy_v2_stream_recv(), which always drains
         * through session->active_stream's fake connection) reaches
         * whichever stream this frame actually belongs to -- not
         * necessarily whichever stream last happened to be active.
         * A frame for an id this session
         * never registered is a genuine protocol violation and is not
         * expected to reach this point at all: every caller of
         * process_control_frame()/the per-request process_frames()
         * path already validates the id against the registry first
         * (see ngx_http_proxy_v2_parse_window_update() and
         * ngx_http_proxy_v2_process_frames() in module.c) and returns
         * NGX_ERROR before falling through here if it is unknown; if
         * one somehow still does, active_stream is simply left
         * unchanged and delivery proceeds against whatever it already
         * pointed at, which is no worse than the behavior before this
         * fix existed.
         */

        if (session->stream_id == 0) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent frame %d on stream 0",
                          session->type);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        target = ngx_http_proxy_v2_find_stream(session, session->stream_id);

        if (target == NULL) {
            rc = ngx_http_proxy_v2_discard_frame(session, b);

            if (rc == NGX_AGAIN) {
                return NGX_OK;
            }

            if (rc == NGX_ERROR) {
                return NGX_ERROR;
            }

            continue;
        }

        session->active_stream = target;

        session->frame_header[0] = (u_char) ((session->rest >> 16) & 0xff);
        session->frame_header[1] = (u_char) ((session->rest >> 8) & 0xff);
        session->frame_header[2] = (u_char) (session->rest & 0xff);
        session->frame_header[3] = session->type;
        session->frame_header[4] = session->flags;
        session->frame_header[5] =
                              (u_char) ((session->stream_id >> 24) & 0x7f);
        session->frame_header[6] =
                              (u_char) ((session->stream_id >> 16) & 0xff);
        session->frame_header[7] =
                              (u_char) ((session->stream_id >> 8) & 0xff);
        session->frame_header[8] = (u_char) (session->stream_id & 0xff);
        session->frame_sent = 0;
        session->frame_rest = session->rest;
        session->frame_validated = 1;
        session->stream_frame = 1;
        session->state = ngx_http_proxy_v2_st_start;

        return NGX_OK;
    }
}


static void
ngx_http_proxy_v2_wake_stream(ngx_http_proxy_v2_session_t *session)
{
    ngx_event_t  *rev;

    if (session->active_stream == NULL
        || !session->active_stream->connection_created)
    {
        return;
    }

    rev = session->active_stream->read;

    if (session->stream_frame || session->eof || session->error_state) {
        rev->ready = 1;
        rev->eof = session->eof;
        rev->error = session->error_state;
        ngx_post_event(rev, &ngx_posted_events);
    }
}


/*
 * Post the write event of a stream that still has output waiting, so that
 * its output filter runs again now that the window it was blocked on has
 * grown.  Streams with nothing to send are left alone.
 */

static void
ngx_http_proxy_v2_wake_writer(ngx_http_proxy_v2_stream_t *stream)
{
    if (stream == NULL || !stream->connection_created
        || stream->write == NULL)
    {
        return;
    }

    if (stream->in != NULL || stream->out != NULL || stream->output_blocked) {
        ngx_post_event(stream->write, &ngx_posted_events);
    }
}


static void
ngx_http_proxy_v2_wake_writers(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    if (node == sentinel) {
        return;
    }

    ngx_http_proxy_v2_wake_writer(
        ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node));

    ngx_http_proxy_v2_wake_writers(node->left, sentinel);
    ngx_http_proxy_v2_wake_writers(node->right, sentinel);
}


/*
 * The staged frame has been handed over completely: drop it, stage the next
 * one (waking its owner) and, if the socket still has data nobody has read
 * yet, have the session reader run again.
 */

static void
ngx_http_proxy_v2_next_frame(ngx_http_proxy_v2_session_t *session)
{
    session->frame_validated = 0;
    session->stream_frame = 0;
    session->frame_sent = 0;
    session->frame_rest = 0;

    if (ngx_http_proxy_v2_session_dispatch(session) != NGX_OK) {
        session->error_state = 1;
    }

    ngx_http_proxy_v2_wake_stream(session);

    if (!session->stream_frame && !session->eof && !session->error_state
        && session->connection->read->ready)
    {
        ngx_post_event(session->connection->read, &ngx_posted_events);
    }
}


/*
 * The stream a staged frame belongs to.  session->stream_id cannot be used:
 * it is the frame parser's scratch field and is overwritten as the body
 * filter parses the next frame header, while the staged frame's own header
 * stays in frame_header until the frame has been handed over.
 */

static ngx_uint_t
ngx_http_proxy_v2_frame_stream_id(ngx_http_proxy_v2_session_t *session)
{
    return ((ngx_uint_t) (session->frame_header[5] & 0x7f) << 24)
           | ((ngx_uint_t) session->frame_header[6] << 16)
           | ((ngx_uint_t) session->frame_header[7] << 8)
           | session->frame_header[8];
}


static ssize_t
ngx_http_proxy_v2_stream_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    size_t                         n, total;
    ngx_buf_t                     *b;
    ngx_http_request_t            *r;
    ngx_http_proxy_v2_session_t   *session;
    ngx_http_proxy_v2_stream_t    *stream;

    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return NGX_ERROR;
    }
    session = stream->session;
    b = &session->buffer;

    if (stream->refused) {
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (session->stream_frame && session->frame_rest == 0
        && session->frame_sent == sizeof(session->frame_header)
        && ngx_http_proxy_v2_frame_stream_id(session) == stream->id
        && stream->scratch.state == ngx_http_proxy_v2_st_start)
    {
        ngx_http_proxy_v2_next_frame(session);
    }

    if (session->error_state && !session->stream_frame) {
        c->read->error = 1;
        return NGX_ERROR;
    }

    /*
     * The staged frame belongs to one stream; any other stream asking for
     * data meanwhile must not be given it.  The owner has been woken by
     * ngx_http_proxy_v2_wake_stream() when the frame was staged.
     */

    if (session->stream_frame
        && ngx_http_proxy_v2_frame_stream_id(session) != stream->id)
    {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    total = 0;

    if (session->stream_frame
        && session->frame_sent < sizeof(session->frame_header))
    {
        n = ngx_min(size, sizeof(session->frame_header) - session->frame_sent);
        ngx_memcpy(buf, session->frame_header + session->frame_sent, n);
        session->frame_sent += n;
        buf += n;
        size -= n;
        total += n;
    }

    if (size && session->stream_frame && session->frame_rest && b->pos < b->last)
    {
        n = ngx_min(size, session->frame_rest);
        n = ngx_min(n, (size_t) (b->last - b->pos));
        ngx_memcpy(buf, b->pos, n);
        b->pos += n;
        session->frame_rest -= n;
        total += n;
    }

    if (total) {
        return total;
    }

    c->read->ready = 0;

    if (session->eof) {
        c->read->eof = 1;
        return 0;
    }

    /*
     * The staged frame (or the next one) continues in the socket: the
     * session buffer was filled to the end without hitting EAGAIN, so epoll
     * will not report this data again.  Let the session reader refill it.
     */

    if (b->pos == b->last && !session->error_state
        && session->connection->read->ready)
    {
        ngx_post_event(session->connection->read, &ngx_posted_events);
    }

    return NGX_AGAIN;
}


static ssize_t
ngx_http_proxy_v2_stream_recv_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    size_t    size;
    ssize_t   n, total;
    ngx_buf_t *b;

    total = 0;

    for ( /* void */ ; in; in = in->next) {
        b = in->buf;
        size = b->end - b->last;

        if (limit > 0 && total >= limit) {
            break;
        }

        if (limit > 0 && size > (size_t) (limit - total)) {
            size = limit - total;
        }

        if (size == 0) {
            break;
        }

        n = ngx_http_proxy_v2_stream_recv(c, b->last, size);
        if (n == NGX_AGAIN || n == NGX_ERROR || n == 0) {
            return total ? total : n;
        }

        total += n;

        if ((size_t) n < size || (limit > 0 && total == limit)) {
            break;
        }
    }

    return total;
}


static ssize_t
ngx_http_proxy_v2_stream_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ssize_t                     n;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_stream_t  *stream;

    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return NGX_ERROR;
    }

    n = stream->session->connection->send(stream->session->connection,
                                          buf, size);
    c->buffered = stream->session->connection->buffered;

    return n;
}


static ngx_chain_t *
ngx_http_proxy_v2_stream_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit)
{
    ngx_chain_t                 *cl;
    ngx_http_request_t          *r;
    ngx_http_proxy_v2_stream_t  *stream;

    r = c->data;
    stream = ngx_http_proxy_v2_get_stream(r);
    if (stream == NULL || stream->session == NULL) {
        return NGX_CHAIN_ERROR;
    }

    cl = stream->session->connection->send_chain(
                                      stream->session->connection, in, limit);
    c->buffered = stream->session->connection->buffered;

    return cl;
}


ngx_int_t
ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char                     ch, *p;
    ngx_http_proxy_v2_state_e  state;

    state = session->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

#if 0
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                       "http proxy frame byte: %02Xd, s:%d", ch, state);
#endif

        switch (state) {

        case ngx_http_proxy_v2_st_start:
            session->rest = ch << 16;
            state = ngx_http_proxy_v2_st_length_2;
            break;

        case ngx_http_proxy_v2_st_length_2:
            session->rest |= ch << 8;
            state = ngx_http_proxy_v2_st_length_3;
            break;

        case ngx_http_proxy_v2_st_length_3:
            session->rest |= ch;

            if (!session->frame_validated
                && session->rest > NGX_HTTP_V2_DEFAULT_FRAME_SIZE)
            {
                ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                              "upstream sent too large http2 frame: %uz",
                              session->rest);
                return NGX_ERROR;
            }

            state = ngx_http_proxy_v2_st_type;
            break;

        case ngx_http_proxy_v2_st_type:
            session->type = ch;
            state = ngx_http_proxy_v2_st_flags;
            break;

        case ngx_http_proxy_v2_st_flags:
            session->flags = ch;
            state = ngx_http_proxy_v2_st_stream_id;
            break;

        case ngx_http_proxy_v2_st_stream_id:
            session->stream_id = (ch & 0x7f) << 24;
            state = ngx_http_proxy_v2_st_stream_id_2;
            break;

        case ngx_http_proxy_v2_st_stream_id_2:
            session->stream_id |= ch << 16;
            state = ngx_http_proxy_v2_st_stream_id_3;
            break;

        case ngx_http_proxy_v2_st_stream_id_3:
            session->stream_id |= ch << 8;
            state = ngx_http_proxy_v2_st_stream_id_4;
            break;

        case ngx_http_proxy_v2_st_stream_id_4:
            session->stream_id |= ch;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy frame: %d, len: %uz, f:%d, i:%ui",
                           session->type, session->rest, session->flags,
                           session->stream_id);

            b->pos = p + 1;

            session->state = ngx_http_proxy_v2_st_payload;
            session->frame_state = 0;

            return NGX_OK;

        /* suppress warning */
        case ngx_http_proxy_v2_st_payload:
        case ngx_http_proxy_v2_st_padding:
            break;
        }
    }

    b->pos = p;
    session->state = state;

    return NGX_AGAIN;
}


ngx_int_t
ngx_http_proxy_v2_process_control_frame(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b)
{
    ngx_int_t  rc;

    switch (session->type) {

    case NGX_HTTP_V2_GOAWAY_FRAME:
        rc = ngx_http_proxy_v2_parse_goaway(session, b);

        if (rc != NGX_OK) {
            return rc;
        }

        session->goaway = 1;

        /*
         * Streams up to the last one the peer announces are still served
         * and drain normally; the later ones were not processed and are
         * failed over to another connection, one by one.
         */

        ngx_http_proxy_v2_refuse_streams(session, session->streams.root);

        return NGX_OK;

    case NGX_HTTP_V2_WINDOW_UPDATE_FRAME:
        rc = ngx_http_proxy_v2_parse_window_update(session, b);

        /*
         * Any registered stream, not only the one whose response frame is
         * being read, may be waiting for window: wake the one the update is
         * for, or all of them for the connection window.
         */

        if (rc == NGX_OK) {
            if (session->stream_id) {
                ngx_http_proxy_v2_wake_writer(
                    ngx_http_proxy_v2_find_stream(session,
                                                  session->stream_id));

            } else {
                ngx_http_proxy_v2_wake_writers(session->streams.root,
                                               session->streams.sentinel);
            }
        }

        return rc;

    case NGX_HTTP_V2_SETTINGS_FRAME:
        rc = ngx_http_proxy_v2_parse_settings(session, b);

        if (rc == NGX_OK) {
            ngx_http_proxy_v2_wake_writers(session->streams.root,
                                           session->streams.sentinel);
        }

        return rc;

    case NGX_HTTP_V2_PING_FRAME:
        rc = ngx_http_proxy_v2_parse_ping(session, b);

        if (rc == NGX_OK) {
            ngx_post_event(session->connection->write, &ngx_posted_events);
        }

        return rc;

    case NGX_HTTP_V2_PUSH_PROMISE_FRAME:
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "upstream sent unexpected push promise frame");
        ngx_http_proxy_v2_send_goaway(session,
                                      NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
        return NGX_ERROR;

    case NGX_HTTP_V2_HEADERS_FRAME:
    case NGX_HTTP_V2_DATA_FRAME:
    case NGX_HTTP_V2_CONTINUATION_FRAME:
    case NGX_HTTP_V2_RST_STREAM_FRAME:
        return NGX_DECLINED;
    }

    if (session->stream_id == 0) {
        return ngx_http_proxy_v2_skip_frame(session, b);
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_proxy_v2_parse_goaway(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0,
        sw_last_stream_id_2,
        sw_last_stream_id_3,
        sw_last_stream_id_4,
        sw_error,
        sw_error_2,
        sw_error_3,
        sw_error_4,
        sw_debug
    } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start) {
        if (session->stream_id) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent goaway frame "
                          "with non-zero stream id: %ui", session->stream_id);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        if (session->rest < 8) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent goaway frame "
                          "with invalid length: %uz", session->rest);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_FRAME_SIZE_ERROR);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        switch (state) {
        case sw_start:
            session->goaway_stream_id = (ch & 0x7f) << 24;
            state = sw_last_stream_id_2;
            break;
        case sw_last_stream_id_2:
            session->goaway_stream_id |= ch << 16;
            state = sw_last_stream_id_3;
            break;
        case sw_last_stream_id_3:
            session->goaway_stream_id |= ch << 8;
            state = sw_last_stream_id_4;
            break;
        case sw_last_stream_id_4:
            session->goaway_stream_id |= ch;
            state = sw_error;
            break;
        case sw_error:
            session->error = (ngx_uint_t) ch << 24;
            state = sw_error_2;
            break;
        case sw_error_2:
            session->error |= ch << 16;
            state = sw_error_3;
            break;
        case sw_error_3:
            session->error |= ch << 8;
            state = sw_error_4;
            break;
        case sw_error_4:
            session->error |= ch;
            state = sw_debug;
            break;
        case sw_debug:
            break;
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy goaway: %ui, stream %ui",
                   session->error, session->goaway_stream_id);

    session->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_window_update(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum { sw_start = 0, sw_size_2, sw_size_3, sw_size_4 } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start && session->rest != 4) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "upstream sent window update frame "
                      "with invalid length: %uz", session->rest);
        ngx_http_proxy_v2_send_goaway(session,
                                      NGX_HTTP_PROXY_V2_FRAME_SIZE_ERROR);
        return NGX_ERROR;
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        switch (state) {
        case sw_start:
            session->window_update = (ch & 0x7f) << 24;
            state = sw_size_2;
            break;
        case sw_size_2:
            session->window_update |= ch << 16;
            state = sw_size_3;
            break;
        case sw_size_3:
            session->window_update |= ch << 8;
            state = sw_size_4;
            break;
        case sw_size_4:
            session->window_update |= ch;
            state = sw_start;
            break;
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    session->state = ngx_http_proxy_v2_st_start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy window update: %ui", session->window_update);

    if (session->window_update == 0) {
        ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                      "upstream sent zero window update");
        ngx_http_proxy_v2_send_goaway(session,
                                      NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
        return NGX_ERROR;
    }

    if (session->stream_id) {
        ngx_http_proxy_v2_stream_t  *stream;

        /*
         * Route by looking the id up in the session's stream registry
         * rather than assuming the only legitimate target is whichever
         * stream happens to be active right now.
         * A WINDOW_UPDATE for a stream we never registered at
         * all is a genuine protocol violation (the peer is referencing
         * an id that was never opened on this connection) and still
         * ends the session; a WINDOW_UPDATE for a stream that *was*
         * registered but is not (or no longer) active is legal per RFC
         * 9113 sections 5.1 and 6.9 -- the request may have finished or been
         * cancelled locally while the peer's in-flight frame was still
         * on the wire -- and must be ignored, not treated as fatal.
         */

        stream = ngx_http_proxy_v2_find_stream(session, session->stream_id);

        if (stream == NULL) {

            /*
             * An id this session has already handed out and has since
             * closed (the request finished or was cancelled while the
             * peer's frame was in flight) is legal and ignored; only an
             * id that was never opened is a protocol violation.
             */

            if ((session->stream_id & 1)
                && session->stream_id <= session->last_stream_id)
            {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log,
                               0, "http proxy window update for closed "
                               "stream %ui ignored", session->stream_id);
                return NGX_OK;
            }

            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent window update frame "
                          "for unknown stream %ui", session->stream_id);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        if (session->window_update > (size_t) NGX_HTTP_V2_MAX_WINDOW
                                     - stream->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too large window update");
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR);
            return NGX_ERROR;
        }

        stream->send_window += session->window_update;

    } else {
        if (session->send_window > 0
            && session->window_update > (ngx_uint_t) NGX_HTTP_V2_MAX_WINDOW
                                         - session->send_window)
        {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too large window update");
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR);
            return NGX_ERROR;
        }

        session->send_window += session->window_update;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_parse_settings(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char   ch, *p, *last;
    ssize_t  window_update;
    enum {
        sw_start = 0, sw_id, sw_id_2, sw_value, sw_value_2, sw_value_3,
        sw_value_4
    } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start) {
        if (session->stream_id) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent settings frame "
                          "with non-zero stream id: %ui", session->stream_id);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        if (session->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy settings ack");

            if (session->rest != 0) {
                ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                              "upstream sent settings frame "
                              "with ack flag and non-zero length: %uz",
                              session->rest);
                ngx_http_proxy_v2_send_goaway(session,
                    NGX_HTTP_PROXY_V2_FRAME_SIZE_ERROR);
                return NGX_ERROR;
            }

            session->state = ngx_http_proxy_v2_st_start;
            return NGX_OK;
        }

        if (session->rest % 6 != 0) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent settings frame "
                          "with invalid length: %uz", session->rest);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_FRAME_SIZE_ERROR);
            return NGX_ERROR;
        }

        if (session->free == NULL && session->settings++ > 1000) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too many settings frames");
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_INTERNAL_ERROR);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        switch (state) {
        case sw_start:
        case sw_id:
            session->setting_id = ch << 8;
            state = sw_id_2;
            break;
        case sw_id_2:
            session->setting_id |= ch;
            state = sw_value;
            break;
        case sw_value:
            session->setting_value = (ngx_uint_t) ch << 24;
            state = sw_value_2;
            break;
        case sw_value_2:
            session->setting_value |= ch << 16;
            state = sw_value_3;
            break;
        case sw_value_3:
            session->setting_value |= ch << 8;
            state = sw_value_4;
            break;
        case sw_value_4:
            session->setting_value |= ch;
            state = sw_id;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy setting: %ui %ui",
                           session->setting_id, session->setting_value);

            if (session->setting_id == 0x03) {

                /*
                 * SETTINGS_MAX_CONCURRENT_STREAMS: recompute the
                 * effective cap session_admit() checks, min'd against
                 * the local directive value already set by
                 * ngx_http_proxy_v2_set_local_concurrent_streams().  A
                 * decrease here does not evict any already-admitted
                 * stream (RFC 9113 section 6.5.2: an endpoint that
                 * receives a SETTINGS frame lowering this value need
                 * not close streams that exceed it, only refrain from
                 * creating new ones) -- session_admit()'s own
                 * processing >= concurrent_streams check naturally
                 * refuses new admissions until enough streams have
                 * finished to fall back under the new, lower cap.
                 */

                session->peer_concurrent_streams = session->setting_value;

                session->concurrent_streams =
                    session->local_concurrent_streams
                        ? ngx_min(session->local_concurrent_streams,
                                  session->peer_concurrent_streams)
                        : session->peer_concurrent_streams;
            }

            if (session->setting_id == 0x04) {
                if (session->setting_value > NGX_HTTP_V2_MAX_WINDOW) {
                    ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                                  "upstream sent settings frame with too "
                                  "large initial window size: %ui",
                                  session->setting_value);
                    ngx_http_proxy_v2_send_goaway(session,
                        NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR);
                    return NGX_ERROR;
                }

                window_update = session->setting_value - session->init_window;

                if (ngx_http_proxy_v2_validate_initial_window(
                        session->streams.root, session->streams.sentinel,
                        window_update)
                    != NGX_OK)
                {
                    ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                                  "upstream sent settings frame with too "
                                  "large initial window size: %ui",
                                  session->setting_value);
                    ngx_http_proxy_v2_send_goaway(session,
                        NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR);
                    return NGX_ERROR;
                }

                session->init_window = session->setting_value;
                ngx_http_proxy_v2_update_initial_window(
                    session->streams.root, session->streams.sentinel,
                    window_update);
            }
            break;
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    session->state = ngx_http_proxy_v2_st_start;

    return ngx_http_proxy_v2_send_settings_ack(session);
}


static ngx_int_t
ngx_http_proxy_v2_validate_initial_window(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ssize_t update)
{
    ngx_http_proxy_v2_stream_t  *stream;

    if (node == sentinel) {
        return NGX_OK;
    }

    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

    if (stream->send_window > 0
        && update > (ssize_t) NGX_HTTP_V2_MAX_WINDOW - stream->send_window)
    {
        return NGX_ERROR;
    }

    if (ngx_http_proxy_v2_validate_initial_window(node->left, sentinel, update)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return ngx_http_proxy_v2_validate_initial_window(node->right, sentinel,
                                                      update);
}


static void
ngx_http_proxy_v2_update_initial_window(ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ssize_t update)
{
    ngx_http_proxy_v2_stream_t  *stream;

    if (node == sentinel) {
        return;
    }

    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);
    stream->send_window += update;

    ngx_http_proxy_v2_update_initial_window(node->left, sentinel, update);
    ngx_http_proxy_v2_update_initial_window(node->right, sentinel, update);
}


static ngx_int_t
ngx_http_proxy_v2_parse_ping(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    u_char  ch, *p, *last;
    enum {
        sw_start = 0, sw_data_2, sw_data_3, sw_data_4, sw_data_5, sw_data_6,
        sw_data_7, sw_data_8
    } state;

    last = (b->last - b->pos < (ssize_t) session->rest)
           ? b->last : b->pos + session->rest;
    state = session->frame_state;

    if (state == sw_start) {
        if (session->stream_id) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent ping frame "
                          "with non-zero stream id: %ui", session->stream_id);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        if (session->rest != 8) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent ping frame "
                          "with invalid length: %uz", session->rest);
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_FRAME_SIZE_ERROR);
            return NGX_ERROR;
        }

        if (session->flags & NGX_HTTP_V2_ACK_FLAG) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent ping frame with ack flag");
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_PROTOCOL_ERROR);
            return NGX_ERROR;
        }

        if (session->free == NULL && session->pings++ > 1000) {
            ngx_log_error(NGX_LOG_ERR, session->connection->log, 0,
                          "upstream sent too many ping frames");
            ngx_http_proxy_v2_send_goaway(session,
                                          NGX_HTTP_PROXY_V2_INTERNAL_ERROR);
            return NGX_ERROR;
        }
    }

    for (p = b->pos; p < last; p++) {
        ch = *p;

        if (state < sw_data_8) {
            session->ping_data[state] = ch;
            state++;
        } else {
            session->ping_data[7] = ch;
            state = sw_start;
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                           "http proxy ping");
        }
    }

    session->rest -= p - b->pos;
    session->frame_state = state;
    b->pos = p;

    if (session->rest > 0) {
        return NGX_AGAIN;
    }

    session->state = ngx_http_proxy_v2_st_start;

    return ngx_http_proxy_v2_send_ping_ack(session);
}


static ngx_int_t
ngx_http_proxy_v2_skip_frame(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b)
{
    if (b->last - b->pos < (ssize_t) session->rest) {
        session->rest -= b->last - b->pos;
        b->pos = b->last;
        return NGX_AGAIN;
    }

    b->pos += session->rest;
    session->rest = 0;
    session->state = ngx_http_proxy_v2_st_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_settings_ack(ngx_http_proxy_v2_session_t *session)
{
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy send settings ack");

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->type = NGX_HTTP_V2_SETTINGS_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;

    *ll = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_v2_send_ping_ack(ngx_http_proxy_v2_session_t *session)
{
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy send ping ack");

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->length_2 = 8;
    f->type = NGX_HTTP_V2_PING_FRAME;
    f->flags = NGX_HTTP_V2_ACK_FLAG;

    cl->buf->last = ngx_copy(cl->buf->last, session->ping_data, 8);
    *ll = cl;

    return NGX_OK;
}


ngx_int_t
ngx_http_proxy_v2_send_connection_window_update(
    ngx_http_proxy_v2_session_t *session)
{
    size_t                      n;
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy send connection window update: %uz",
                   session->recv_window);

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->length_2 = 4;
    f->type = NGX_HTTP_V2_WINDOW_UPDATE_FRAME;

    n = NGX_HTTP_V2_MAX_WINDOW - session->recv_window;
    session->recv_window = NGX_HTTP_V2_MAX_WINDOW;

    *cl->buf->last++ = (u_char) ((n >> 24) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 16) & 0xff);
    *cl->buf->last++ = (u_char) ((n >> 8) & 0xff);
    *cl->buf->last++ = (u_char) (n & 0xff);

    *ll = cl;

    return NGX_OK;
}


/*
 * Emits GOAWAY on the first protocol violation detected on this
 * connection. Idempotent: only the first call actually queues a frame,
 * since RFC 9113 section 6.8 permits (but does not require) more than
 * one GOAWAY, and the parse_* call sites in this file each detect their
 * own violation and call this once before returning NGX_ERROR, which
 * already tears the whole session down -- there is nothing to gain
 * from a second, more specific GOAWAY once the connection is being
 * abandoned anyway.
 */

ngx_int_t
ngx_http_proxy_v2_send_goaway(ngx_http_proxy_v2_session_t *session,
    ngx_uint_t error_code)
{
    u_char                     *p;
    ngx_chain_t                *cl, **ll;
    ngx_http_proxy_v2_frame_t  *f;

    if (session->goaway_sent) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy send goaway: %ui", error_code);

    for (cl = session->out, ll = &session->out; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_http_proxy_v2_get_control_buf(session);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    f = (ngx_http_proxy_v2_frame_t *) cl->buf->last;
    cl->buf->last += sizeof(ngx_http_proxy_v2_frame_t);

    ngx_memzero(f, sizeof(ngx_http_proxy_v2_frame_t));
    f->length_2 = 8;
    f->type = NGX_HTTP_V2_GOAWAY_FRAME;

    p = cl->buf->last;

    /*
     * Last-stream-id is 0: this session is a pure HTTP/2 client to the
     * upstream and never accepts a peer-initiated (even) stream id, so
     * there is nothing higher than 0 to report as processed (RFC 9113
     * section 6.8 permits 0 here).
     */

    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;

    *p++ = (u_char) ((error_code >> 24) & 0xff);
    *p++ = (u_char) ((error_code >> 16) & 0xff);
    *p++ = (u_char) ((error_code >> 8) & 0xff);
    *p++ = (u_char) (error_code & 0xff);

    cl->buf->last = p;

    *ll = cl;
    session->goaway_sent = 1;

    return NGX_OK;
}


static ngx_chain_t *
ngx_http_proxy_v2_get_control_buf(ngx_http_proxy_v2_session_t *session)
{
    u_char       *start;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;
    ngx_pool_t   *pool;

    pool = session->connection->pool;

    cl = ngx_chain_get_free_buf(pool, &session->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;
    start = b->start;

    if (start == NULL) {
        start = ngx_palloc(pool, 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8);
        if (start == NULL) {
            return NULL;
        }
    }

    ngx_memzero(b, sizeof(ngx_buf_t));

    b->start = start;
    b->pos = start;
    b->last = start;
    b->end = start + 2 * sizeof(ngx_http_proxy_v2_frame_t) + 8;
    b->tag = session->output_tag;
    b->temporary = 1;
    b->flush = 1;

    return cl;
}


/*
 * GOAWAY(last_stream_id): the streams above it were not processed and are
 * safe to send again.  Each one is woken with a read error, which sends its
 * request through ngx_http_upstream_next(); it is marked as using a cached
 * connection so that the failure does not use up the only try of a
 * single-server upstream.  The new attempt finds the session going away and
 * opens a new connection.
 */

static void
ngx_http_proxy_v2_refuse_streams(ngx_http_proxy_v2_session_t *session,
    ngx_rbtree_node_t *node)
{
    ngx_http_proxy_v2_stream_t  *stream;

    if (node == session->streams.sentinel) {
        return;
    }

    ngx_http_proxy_v2_refuse_streams(session, node->left);
    ngx_http_proxy_v2_refuse_streams(session, node->right);

    stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

    if (stream->id <= session->goaway_stream_id
        || stream->done || stream->rst || stream->refused
        || !stream->connection_created)
    {
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy stream %ui refused by goaway", stream->id);

    stream->refused = 1;
    stream->request->upstream->peer.cached = 1;

    stream->read->ready = 1;
    ngx_post_event(stream->read, &ngx_posted_events);
}


static ngx_http_proxy_v2_session_t *
ngx_http_proxy_v2_find_session(ngx_connection_t *c)
{
    ngx_pool_cleanup_t  *cln;

    for (cln = c->pool->cleanup; cln; cln = cln->next) {
        if (cln->handler == ngx_http_proxy_v2_session_cleanup) {
            return cln->data;
        }
    }

    return NULL;
}


/* what the control frames of an idle session queued for the peer */

static ngx_int_t
ngx_http_proxy_v2_flush_idle(ngx_http_proxy_v2_session_t *session)
{
    ngx_chain_t       *out, *chain;
    ngx_connection_t  *c;

    if (session->out == NULL) {
        return NGX_OK;
    }

    c = session->connection;

    out = session->out;
    session->out = NULL;

    chain = c->send_chain(c, out, 0);

    ngx_chain_update_chains(c->pool, &session->free, &session->busy, &out,
                            session->output_tag);

    /*
     * these frames are a few bytes each, so a short write means the
     * connection is not healthy; there is no stream to retry for
     */

    if (chain == NGX_CHAIN_ERROR || chain != NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Idle session (no stream attached): handle the control frames the peer
 * sends and drop stream frames, which can only be for closed streams.
 */

static ngx_int_t
ngx_http_proxy_v2_idle_dispatch(ngx_http_proxy_v2_session_t *session)
{
    size_t       n;
    ngx_int_t    rc;
    ngx_buf_t   *b;

    b = &session->buffer;

    rc = ngx_http_proxy_v2_session_dispatch(session);

    while (rc == NGX_OK && session->stream_frame) {
        n = ngx_min(session->frame_rest, (size_t) (b->last - b->pos));
        b->pos += n;
        session->frame_rest -= n;

        if (session->frame_rest > 0) {
            return NGX_OK;
        }

        session->frame_validated = 0;
        session->stream_frame = 0;
        session->frame_sent = 0;

        rc = ngx_http_proxy_v2_session_dispatch(session);
    }

    return rc;
}


static void
ngx_http_proxy_v2_session_idle_read(ngx_event_t *rev)
{
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *session;

    c = rev->data;

    session = ngx_http_proxy_v2_find_session(c);

    if (session == NULL || session->processing != 0) {
        c->close = 1;
        return;
    }

    b = &session->buffer;

    for ( ;; ) {
        if (b->pos != b->start && b->pos != b->last) {
            b->last = ngx_movemem(b->start, b->pos, b->last - b->pos);
            b->pos = b->start;

        } else if (b->pos == b->last) {
            b->pos = b->start;
            b->last = b->start;
        }

        if (b->last == b->end) {
            session->error_state = 1;
            break;
        }

        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR) {
            session->error_state = 1;
            break;
        }

        if (n == 0) {
            session->eof = 1;
            break;
        }

        b->last += n;

        if (ngx_http_proxy_v2_idle_dispatch(session) != NGX_OK) {
            session->error_state = 1;
            break;
        }
    }

    if (ngx_http_proxy_v2_flush_idle(session) != NGX_OK) {
        session->error_state = 1;
    }

    if (session->goaway || session->eof || session->error_state) {
        c->close = 1;
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        c->close = 1;
    }
}


static void
ngx_http_proxy_v2_session_idle_write(ngx_event_t *wev)
{
    ngx_connection_t             *c;
    ngx_http_proxy_v2_session_t  *session;

    c = wev->data;

    session = ngx_http_proxy_v2_find_session(c);

    if (session == NULL || session->processing != 0
        || ngx_http_proxy_v2_flush_idle(session) != NGX_OK)
    {
        c->close = 1;
    }
}


static void
ngx_http_proxy_v2_session_cleanup(void *data)
{
    ngx_rbtree_node_t            *node;
    ngx_http_proxy_v2_session_t  *session = data;
    ngx_http_proxy_v2_stream_t   *stream;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, session->connection->log, 0,
                   "http proxy session cleanup");

    if (session->orphan != NULL) {
        ngx_free(session->orphan);
        session->orphan = NULL;
    }

    while (session->streams.root != session->streams.sentinel) {
        node = session->streams.root;
        stream = ngx_rbtree_data(node, ngx_http_proxy_v2_stream_t, node);

        ngx_rbtree_delete(&session->streams, node);
        stream->session = NULL;
        stream->registered = 0;
    }

    if (session->active_stream != NULL) {
        ngx_log_error(NGX_LOG_ALERT, session->connection->log, 0,
                      "http2 session cleanup with an active stream");
        session->active_stream = NULL;
    }

    return;
}
