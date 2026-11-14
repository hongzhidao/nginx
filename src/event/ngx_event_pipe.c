
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_pipe.h>


typedef struct ngx_event_pipe_input_s {
    ngx_event_pipe_input_notify_pt  notify;
    void                           *data;

    ngx_queue_t                     buffers;
    ngx_queue_t                     available;
    ngx_queue_t                     pending;
    ngx_chain_t                    *receiving;

    ngx_int_t                       allocated;
    size_t                          size;
    size_t                          reserved;
    size_t                          committed;
    size_t                          ready;

    /*
     * closed stops admission; complete exposes terminal status after input
     * and required writes have drained.  done records explicit input-filter
     * completion independently of the remaining body length.
     */

    unsigned                        closed:1;
    unsigned                        done:1;
    unsigned                        eof:1;
    unsigned                        error:1;
    unsigned                        complete:1;
    unsigned                        cancelled:1;
} ngx_event_pipe_input_t;


/*
 * Storage cursors are independent of receive views and downstream shadows.
 * Each block has one reusable receive view and one live publication.  Socket
 * input seals partial publications until release; producers may keep receiving
 * into the unused tail while an earlier prefix is retained downstream.
 */

typedef struct {
    ngx_buf_t          raw;       /* must be first */
    ngx_buf_t          view;
    ngx_chain_t        receive;
    ngx_queue_t        buffers;
    ngx_queue_t        available;
    ngx_queue_t        pending;

    u_char            *start;
    u_char            *pos;
    u_char            *ready;
    u_char            *last;
    u_char            *end;
    size_t             reserved;

    unsigned           busy:1;
    unsigned           queued:1;
    unsigned           writable:1;
} ngx_event_pipe_input_block_t;


static ngx_int_t ngx_event_pipe_input_advance(ngx_event_pipe_t *p, size_t n);
static ngx_int_t ngx_event_pipe_input_publish(ngx_event_pipe_t *p, size_t n,
    ngx_uint_t seal);
static ngx_int_t ngx_event_pipe_input_preread(ngx_event_pipe_t *p);
static size_t ngx_event_pipe_input_full(ngx_event_pipe_t *p);
static ngx_buf_t *ngx_event_pipe_input_next(ngx_event_pipe_t *p);
static void ngx_event_pipe_input_release(ngx_event_pipe_t *p, ngx_buf_t *buf);
static void ngx_event_pipe_input_reclaim(ngx_event_pipe_t *p);
static void ngx_event_pipe_input_reset(ngx_event_pipe_t *p,
    ngx_event_pipe_input_block_t *b);
static void ngx_event_pipe_input_queue(ngx_event_pipe_t *p,
    ngx_event_pipe_input_block_t *b);
static ngx_uint_t ngx_event_pipe_input_blocked(ngx_event_pipe_t *p);
static void ngx_event_pipe_socket_notify(void *data);

static ngx_int_t ngx_event_pipe_read_upstream(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_read_socket(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_filter_input(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_output_chain(ngx_event_pipe_t *p,
    ngx_chain_t **out);
static ngx_int_t ngx_event_pipe_recycle_buffers(ngx_event_pipe_t *p);

static ngx_int_t ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_prepare_temp_file_write(ngx_event_pipe_t *p,
    ngx_chain_t **chain);
static ngx_int_t ngx_event_pipe_update_temp_file_bufs(ngx_event_pipe_t *p,
    ngx_chain_t *out, ssize_t n);
static ngx_inline void ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf);
static ngx_int_t ngx_event_pipe_free_chain(ngx_event_pipe_t *p,
    ngx_chain_t *chain);
static ngx_int_t ngx_event_pipe_drain_chains(ngx_event_pipe_t *p);


ngx_int_t
ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write)
{
    ngx_int_t     rc;
    ngx_uint_t    flags, busy;
    ngx_event_t  *rev, *wev;

    if (p->input == NULL) {
        if (ngx_event_pipe_input_init(p, ngx_event_pipe_socket_notify, p)
            != NGX_OK)
        {
            return NGX_ABORT;
        }
    }

    if (p->busy) {
        do_write = 1;
    }

    /*
     * A caller may report EOF or error while received input is still pending.
     * Keep terminal flags private until filtering and required writes finish.
     */

    if (!p->input->complete) {
        p->input->done |= p->upstream_done;
        p->input->eof |= p->upstream_eof;
        p->input->error |= p->upstream_error;
        p->input->closed |= p->upstream_done || p->upstream_eof
                            || p->upstream_error;
        p->upstream_done = 0;
        p->upstream_eof = 0;
        p->upstream_error = 0;
    }

    for ( ;; ) {
        busy = 0;

        if (do_write) {
            p->log->action = "sending to client";

            rc = ngx_event_pipe_write_to_downstream(p);

            if (rc == NGX_ABORT) {
                return NGX_ABORT;
            }

            if (rc == NGX_BUSY) {
                busy = 1;
            }
        }

        p->read = 0;
        p->upstream_blocked = 0;

        p->log->action = "reading upstream";

        if (ngx_event_pipe_read_upstream(p) == NGX_ABORT) {
            return NGX_ABORT;
        }

        /* A completed read still requires the terminal output handoff. */

        if ((busy && !p->input->complete)
            || (!p->read && !p->upstream_blocked))
        {
            break;
        }

        do_write = 1;
    }

    ngx_event_pipe_input_reclaim(p);

    if (p->upstream
        && p->upstream->fd != (ngx_socket_t) -1)
    {
        rev = p->upstream->read;

        flags = (rev->eof || rev->error) ? NGX_CLOSE_EVENT : 0;

        if (ngx_handle_read_event(rev, flags) != NGX_OK) {
            return NGX_ABORT;
        }

        if (!rev->delayed) {
            if (rev->active && !rev->ready
                && !p->input->closed
                && !p->input->cancelled)
            {
                ngx_add_timer(rev, p->read_timeout);

            } else if (rev->timer_set) {
                ngx_del_timer(rev);
            }
        }
    }

    if (p->downstream->fd != (ngx_socket_t) -1
        && p->downstream->data == p->output_ctx)
    {
        wev = p->downstream->write;
        if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
            return NGX_ABORT;
        }

        if (!wev->delayed) {
            if (wev->active && !wev->ready) {
                ngx_add_timer(wev, p->send_timeout);

            } else if (wev->timer_set) {
                ngx_del_timer(wev);
            }
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_event_pipe_input_init(ngx_event_pipe_t *p,
    ngx_event_pipe_input_notify_pt notify, void *data)
{
    ngx_event_pipe_input_t  *in;

    if (p->input) {
        return NGX_BUSY;
    }

    in = ngx_pcalloc(p->pool, sizeof(ngx_event_pipe_input_t));
    if (in == NULL) {
        return NGX_ERROR;
    }

    in->notify = notify;
    in->data = data;
    ngx_queue_init(&in->buffers);
    ngx_queue_init(&in->available);
    ngx_queue_init(&in->pending);
    p->input = in;
    p->preread = (p->preread_bufs != NULL);

    /* Adopt preread storage before producers can query or reserve capacity. */

    if (p->preread_bufs && ngx_event_pipe_input_preread(p) != NGX_OK) {
        ngx_event_pipe_input_cancel(p);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_event_pipe_input_reserve(ngx_event_pipe_t *p, ngx_uint_t n)
{
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    if (p->bufs.num <= 0 || p->bufs.size == 0
        || n > (ngx_uint_t) p->bufs.num || in->receiving
        || in->cancelled || in->closed
        || p->bufs.size > NGX_MAX_SIZE_T_VALUE / (size_t) p->bufs.num)
    {
        return NGX_ERROR;
    }

    while ((ngx_uint_t) in->allocated < n) {
        b = ngx_pcalloc(p->pool, sizeof(ngx_event_pipe_input_block_t));
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->start = ngx_palloc(p->pool, p->bufs.size);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->end = b->start + p->bufs.size;
        ngx_queue_insert_tail(&in->buffers, &b->buffers);
        ngx_event_pipe_input_reset(p, b);
        in->allocated++;
        in->size += p->bufs.size;
    }

    return NGX_OK;
}


size_t
ngx_event_pipe_input_capacity(ngx_event_pipe_t *p, size_t *size)
{
    size_t                         n;
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    if (size) {
        *size = in->size;
    }

    if (in->cancelled || in->closed) {
        return 0;
    }

    n = 0;

    for (q = ngx_queue_head(&in->available);
         q != ngx_queue_sentinel(&in->available);
         q = ngx_queue_next(q))
    {
        b = ngx_queue_data(q, ngx_event_pipe_input_block_t, available);

        if (b->queued && &b->pending != ngx_queue_last(&in->pending)) {
            continue;
        }

        n += b->end - b->last - b->reserved;
    }

    return n;
}


ngx_chain_t *
ngx_event_pipe_input_alloc_bufs(ngx_event_pipe_t *p, size_t limit)
{
    size_t                         n;
    ngx_chain_t                  **ll;
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    if (in->receiving || limit == 0 || in->cancelled || in->closed) {
        return NULL;
    }

    ll = &in->receiving;

    for (q = ngx_queue_head(&in->available);
         q != ngx_queue_sentinel(&in->available) && limit;
         q = ngx_queue_next(q))
    {
        b = ngx_queue_data(q, ngx_event_pipe_input_block_t, available);

        if (b->queued && &b->pending != ngx_queue_last(&in->pending)) {
            continue;
        }

        n = ngx_min((size_t) (b->end - b->last), limit);
        ngx_memzero(&b->view, sizeof(ngx_buf_t));
        b->view.start = b->last;
        b->view.pos = b->last;
        b->view.last = b->last;
        b->view.end = b->last + n;
        b->view.temporary = 1;
        b->receive.buf = &b->view;
        b->receive.next = NULL;
        b->reserved = n;

        *ll = &b->receive;
        ll = &b->receive.next;
        in->reserved += n;
        limit -= n;
    }

    return in->receiving;
}


ngx_int_t
ngx_event_pipe_input_commit(ngx_event_pipe_t *p, size_t n)
{
    ngx_event_pipe_input_t  *in;

    in = p->input;

    if (ngx_event_pipe_input_advance(p, n) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_event_pipe_input_publish(p, in->committed - in->ready, 0);
}


static ngx_int_t
ngx_event_pipe_input_advance(ngx_event_pipe_t *p, size_t n)
{
    size_t                         size;
    ngx_chain_t                   *cl, *next;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    /*
     * A filter may close admission while the producer owns a receive.
     * The producer must still be able to commit it or return it unused.
     */

    if (in->receiving == NULL || n > in->reserved || in->cancelled) {
        return NGX_ERROR;
    }

    p->read_length += n;
    in->committed += n;

    for (cl = in->receiving; cl; cl = next) {
        next = cl->next;
        b = (ngx_event_pipe_input_block_t *)
                 ((u_char *) cl
                  - offsetof(ngx_event_pipe_input_block_t, receive));

        size = ngx_min(n, b->reserved);
        b->last += size;
        b->reserved = 0;
        n -= size;

        if (size) {
            ngx_event_pipe_input_queue(p, b);

            if (b->last == b->end) {
                ngx_queue_remove(&b->available);
                b->writable = 0;
            }
        }

        if (!b->busy && !b->queued) {
            ngx_event_pipe_input_reset(p, b);
        }
    }

    in->receiving = NULL;
    in->reserved = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_input_publish(ngx_event_pipe_t *p, size_t n, ngx_uint_t seal)
{
    size_t                         size;
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    if (in->receiving || n > in->committed - in->ready || in->cancelled) {
        return NGX_ERROR;
    }

    in->ready += n;

    for (q = ngx_queue_head(&in->pending);
         q != ngx_queue_sentinel(&in->pending) && n;
         q = ngx_queue_next(q))
    {
        b = ngx_queue_data(q, ngx_event_pipe_input_block_t, pending);
        size = ngx_min(n, (size_t) (b->last - b->ready));
        b->ready += size;
        n -= size;

        if (seal && size && b->writable) {
            ngx_queue_remove(&b->available);
            b->writable = 0;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_event_pipe_input_finish(ngx_event_pipe_t *p, ngx_uint_t flags)
{
    ngx_event_pipe_input_t  *in;

    in = p->input;

    if (in->complete) {
        return NGX_BUSY;
    }

    if (in->cancelled || in->receiving
        || (flags != NGX_EVENT_PIPE_INPUT_EOF
            && flags != NGX_EVENT_PIPE_INPUT_ERROR))
    {
        return NGX_ERROR;
    }

    /*
     * All receive views have been returned.  Publish remaining bytes before
     * closing admission so the terminal status cannot overtake them.
     */

    if (ngx_event_pipe_input_publish(p, in->committed - in->ready, 1)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* A later EOF must not erase a reported error. */

    if (flags == NGX_EVENT_PIPE_INPUT_ERROR) {
        in->error = 1;
        in->eof = 0;

    } else if (!in->error) {
        in->eof = 1;
    }

    in->closed = 1;

    return NGX_OK;
}


void
ngx_event_pipe_input_cancel(ngx_event_pipe_t *p)
{
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    /*
     * The producer has stopped using its receive views.  Detach notifications
     * and discard unfiltered input, leaving published prefixes owned by
     * downstream shadows and any outstanding file write.
     */

    in->cancelled = 1;
    in->notify = NULL;
    in->data = NULL;
    in->receiving = NULL;
    in->reserved = 0;
    in->committed = 0;
    in->ready = 0;

    for (q = ngx_queue_head(&in->buffers);
         q != ngx_queue_sentinel(&in->buffers);
         q = ngx_queue_next(q))
    {
        b = ngx_queue_data(q, ngx_event_pipe_input_block_t, buffers);
        b->reserved = 0;

        if (b->queued) {
            ngx_queue_remove(&b->pending);
            b->queued = 0;
        }

        b->ready = b->pos;
        b->last = b->pos;
    }
}


static size_t
ngx_event_pipe_input_full(ngx_event_pipe_t *p)
{
    size_t                         n;
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;
    n = 0;

    for (q = ngx_queue_head(&in->pending);
         q != ngx_queue_sentinel(&in->pending);
         q = ngx_queue_next(q))
    {
        b = ngx_queue_data(q, ngx_event_pipe_input_block_t, pending);
        if (b->last != b->end) {
            break;
        }

        n += b->last - b->ready;
    }

    return n;
}


static ngx_buf_t *
ngx_event_pipe_input_next(ngx_event_pipe_t *p)
{
    size_t                         n;
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    if (in->cancelled || ngx_queue_empty(&in->pending)) {
        return NULL;
    }

    q = ngx_queue_head(&in->pending);
    b = ngx_queue_data(q, ngx_event_pipe_input_block_t, pending);

    if (b->busy || b->reserved || b->pos == b->ready) {
        return NULL;
    }

    ngx_memzero(&b->raw, sizeof(ngx_buf_t));
    b->raw.start = b->start;
    b->raw.pos = b->pos;
    b->raw.last = b->ready;
    b->raw.end = b->end;
    b->raw.temporary = 1;
    b->busy = 1;

    n = b->ready - b->pos;
    b->pos = b->ready;
    in->committed -= n;
    in->ready -= n;

    if (b->pos == b->last) {
        ngx_queue_remove(&b->pending);
        b->queued = 0;
    }

    return &b->raw;
}


static void
ngx_event_pipe_input_release(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;
    b = (ngx_event_pipe_input_block_t *) buf;

    if (!b->busy) {
        return;
    }

    b->busy = 0;
    b->raw.shadow = NULL;

    if (!b->queued && !b->reserved) {
        ngx_event_pipe_input_reset(p, b);
    }

    /*
     * A tail can be committed while an earlier prefix is retained.  Releasing
     * that prefix unblocks publication without adding capacity.  Only report
     * progress here; the callback must not reenter the pipe.
     */

    if (in->notify) {
        in->notify(in->data);
    }
}


static ngx_int_t
ngx_event_pipe_input_preread(ngx_event_pipe_t *p)
{
    size_t                         n;
    ngx_buf_t                     *raw;
    ngx_chain_t                   *cl;
    ngx_queue_t                   *available;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;
    n = 0;
    available = ngx_queue_head(&in->available);

    while (p->preread_bufs) {
        cl = p->preread_bufs;
        raw = cl->buf;

        b = ngx_pcalloc(p->pool, sizeof(ngx_event_pipe_input_block_t));
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->start = raw->start;
        b->pos = raw->pos;
        b->ready = raw->pos;
        b->last = raw->last;
        b->end = raw->end;
        ngx_queue_insert_tail(&in->buffers, &b->buffers);
        in->size += b->end - b->start;
        n += b->last - b->pos;

        if (b->pos != b->last) {
            ngx_event_pipe_input_queue(p, b);
        }

        if (b->last != b->end) {
            /* append to preread storage before using preallocated blocks */

            ngx_queue_insert_tail(available, &b->available);
            b->writable = 1;
        }

        p->preread_bufs = cl->next;
        ngx_free_chain(p->pool, cl);
    }

    in->committed += n;
    p->read_length += n;

    return NGX_OK;
}


static void
ngx_event_pipe_input_reclaim(ngx_event_pipe_t *p)
{
    u_char                        *last;
    ngx_uint_t                     changed;
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;
    changed = 0;

    for (q = ngx_queue_head(&in->buffers);
         q != ngx_queue_sentinel(&in->buffers);
         q = ngx_queue_next(q))
    {
        b = ngx_queue_data(q, ngx_event_pipe_input_block_t, buffers);

        if (b->start == NULL || b->busy || b->queued || b->reserved) {
            continue;
        }

        if (p->free_bufs && p->buf_to_file == NULL
            && (p->upstream_done || p->upstream_eof || p->upstream_error))
        {
            if (b->writable) {
                ngx_queue_remove(&b->available);
                b->writable = 0;
            }

            in->size -= b->end - b->start;
            ngx_pfree(p->pool, b->start);
            b->start = NULL;
            continue;
        }

        last = b->last;
        ngx_event_pipe_input_reset(p, b);
        changed |= (last != b->last);
    }

    /* Coalesce restored capacity into one notification after the scan. */

    if (changed && in->notify) {
        in->notify(in->data);
    }
}


static void
ngx_event_pipe_input_reset(ngx_event_pipe_t *p,
    ngx_event_pipe_input_block_t *b)
{
    ngx_buf_t  *header;

    header = p->buf_to_file;
    b->pos = (header && b->start == header->start) ? header->last : b->start;
    b->ready = b->pos;
    b->last = b->pos;

    if (!b->writable && b->last != b->end) {
        ngx_queue_insert_tail(&p->input->available, &b->available);
        b->writable = 1;
    }
}


static void
ngx_event_pipe_input_queue(ngx_event_pipe_t *p,
    ngx_event_pipe_input_block_t *b)
{
    if (!b->queued) {
        ngx_queue_insert_tail(&p->input->pending, &b->pending);
        b->queued = 1;
    }
}


static ngx_int_t
ngx_event_pipe_read_upstream(ngx_event_pipe_t *p)
{
    ngx_int_t                rc;
    ngx_event_pipe_input_t  *in;

    in = p->input;

    if (in->cancelled || in->complete) {
        return NGX_OK;
    }

#if (NGX_THREADS)

    if (p->writing) {
        rc = ngx_event_pipe_write_chain_to_temp_file(p);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (p->aio && p->cacheable) {
        return NGX_AGAIN;
    }

#endif

    if (p->length == 0) {
        in->closed = 1;
    }

    rc = ngx_event_pipe_read_socket(p);

    if (rc == NGX_ABORT) {
        return NGX_ABORT;
    }

    if (ngx_event_pipe_filter_input(p) != NGX_OK) {
        return NGX_ABORT;
    }

    if ((p->cacheable && (p->in || p->buf_to_file))
        || (p->in && !in->closed
            && ngx_event_pipe_input_capacity(p, NULL) == 0
            && p->temp_file->offset < p->max_temp_file_size
            && (p->downstream_error
                || p->downstream->data != p->output_ctx
                || !p->downstream->write->ready
                || p->downstream->write->delayed)))
    {
#if (NGX_THREADS)
        if (p->aio) {
            return NGX_AGAIN;
        }
#endif

        rc = ngx_event_pipe_write_chain_to_temp_file(p);
        if (rc != NGX_OK) {
            return rc;
        }

        p->read = 1;
    }

    /*
     * Terminal status follows all accepted input and required file writes.
     * Downstream may still retain published buffers; the final output handoff
     * handles their ownership without delaying input completion.
     */

    if (in->closed
        && in->committed == 0 && in->receiving == NULL && !p->writing
        && (!p->cacheable || (p->in == NULL && p->buf_to_file == NULL)))
    {
        p->upstream_done = in->done || p->length == 0;
        p->upstream_eof = in->eof;
        p->upstream_error = in->error;
        in->complete = 1;
        p->read = 1;
    }

    if (p->busy && ngx_event_pipe_input_blocked(p)
        && !p->downstream_error
        && p->downstream->data == p->output_ctx
        && p->downstream->write->ready
        && !p->downstream->write->delayed)
    {
        p->upstream_blocked = 1;
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_event_pipe_input_blocked(ngx_event_pipe_t *p)
{
    ngx_queue_t                   *q;
    ngx_event_pipe_input_t        *in;
    ngx_event_pipe_input_block_t  *b;

    in = p->input;

    if (in->cancelled || ngx_queue_empty(&in->pending)) {
        return 0;
    }

    q = ngx_queue_head(&in->pending);
    b = ngx_queue_data(q, ngx_event_pipe_input_block_t, pending);

    return b->busy && b->pos != b->ready;
}


static void
ngx_event_pipe_socket_notify(void *data)
{
    ngx_event_pipe_t  *p = data;

    p->read = 1;
}


static ngx_int_t
ngx_event_pipe_read_socket(ngx_event_pipe_t *p)
{
    off_t         limit;
    size_t        capacity;
    ssize_t       n;
    ngx_int_t     rc;
    ngx_msec_t    delay;
    ngx_chain_t  *chain;
#if (NGX_DEBUG)
    ngx_chain_t  *cl;
#endif

    if (p->input->closed
        || p->upstream == NULL
        || p->input->cancelled)
    {
        return NGX_OK;
    }

#if (NGX_THREADS)

    if (p->aio) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe read upstream: aio");
        return NGX_AGAIN;
    }

#endif

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe read upstream: %d", p->upstream->read->ready);

    for ( ;; ) {

        if (p->input->closed) {
            break;
        }

        if (!p->preread && !p->upstream->read->ready) {
            break;
        }

        if (p->preread) {

            /* Apply socket batching and rate accounting to adopted preread. */

            n = p->preread_size;
            p->preread = 0;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe preread: %z", n);

            if (n) {
                p->read = 1;
            }

        } else {

#if (NGX_HAVE_KQUEUE)

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a buf on these conditions
             * and not to call c->recv_chain().
             */

            if (p->upstream->read->available == 0
                && p->upstream->read->pending_eof
#if (NGX_SSL)
                && !p->upstream->ssl
#endif
                )
            {
                p->upstream->read->ready = 0;
                p->upstream->read->eof = 1;
                p->read = 1;

                if (p->upstream->read->kq_errno) {
                    p->upstream->read->error = 1;
                    ngx_log_error(NGX_LOG_ERR, p->log,
                                  p->upstream->read->kq_errno,
                                  "kevent() reported that upstream "
                                  "closed connection");
                }

                if (ngx_event_pipe_input_finish(p,
                                                p->upstream->read->error
                                                ? NGX_EVENT_PIPE_INPUT_ERROR
                                                : NGX_EVENT_PIPE_INPUT_EOF)
                    != NGX_OK)
                {
                    return NGX_ABORT;
                }

                break;
            }
#endif

            if (p->limit_rate) {
                if (p->upstream->read->delayed) {
                    break;
                }

                limit = (off_t) p->limit_rate * (ngx_time() - p->start_sec + 1)
                        - p->read_length;

                if (limit <= 0) {
                    p->upstream->read->delayed = 1;
                    delay = (ngx_msec_t) (- limit * 1000 / p->limit_rate + 1);
                    ngx_add_timer(p->upstream->read, delay);
                    break;
                }

            } else {
                limit = 0;
            }

            capacity = ngx_event_pipe_input_capacity(p, NULL);

            if (capacity == 0 && p->input->allocated < p->bufs.num) {

                /* allocate a new buf if it's still allowed */

                if (ngx_event_pipe_input_reserve(p, p->input->allocated + 1)
                    != NGX_OK)
                {
                    return NGX_ABORT;
                }

                capacity = ngx_event_pipe_input_capacity(p, NULL);
            }

            if (capacity == 0 && !p->cacheable
                && !p->downstream_error
                && p->downstream->data == p->output_ctx
                && p->downstream->write->ready
                && !p->downstream->write->delayed)
            {
                /*
                 * if the bufs are not needed to be saved in a cache and
                 * a downstream is ready then write the bufs to a downstream
                 */

                p->upstream_blocked = 1;

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe downstream ready");

                break;

            } else if (capacity == 0
                       && (p->cacheable
                           || p->temp_file->offset < p->max_temp_file_size))
            {

                /*
                 * if it is allowed, then save some bufs from p->in
                 * to a temporary file, and add them to a p->out chain
                 */

                rc = ngx_event_pipe_write_chain_to_temp_file(p);

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe temp offset: %O", p->temp_file->offset);

                if (rc == NGX_BUSY) {
                    break;
                }

                if (rc != NGX_OK) {
                    return rc;
                }

                capacity = ngx_event_pipe_input_capacity(p, NULL);
            }

            if (capacity == 0) {

                /* there are no bufs to read in */

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "no pipe bufs to read in");

                break;
            }

            if (limit && (off_t) capacity > limit) {
                capacity = (size_t) limit;
            }

            chain = ngx_event_pipe_input_alloc_bufs(p, capacity);
            if (chain == NULL) {
                return NGX_ABORT;
            }

            n = p->upstream->recv_chain(p->upstream, chain, limit);

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe recv chain: %z", n);

            if (ngx_event_pipe_input_advance(p, n > 0 ? n : 0) != NGX_OK) {
                return NGX_ABORT;
            }

            if (n == NGX_ERROR) {
                if (ngx_event_pipe_input_finish(p, NGX_EVENT_PIPE_INPUT_ERROR)
                    != NGX_OK)
                {
                    return NGX_ABORT;
                }
                break;
            }

            if (n == NGX_AGAIN) {
                break;
            }

            p->read = 1;

            if (n == 0) {
                if (ngx_event_pipe_input_finish(p, NGX_EVENT_PIPE_INPUT_EOF)
                    != NGX_OK)
                {
                    return NGX_ABORT;
                }
                break;
            }
        }

        if (ngx_event_pipe_input_publish(p, ngx_event_pipe_input_full(p), 1)
            != NGX_OK)
        {
            return NGX_ABORT;
        }

        if (ngx_event_pipe_filter_input(p) != NGX_OK) {
            return NGX_ABORT;
        }

        delay = p->limit_rate ? (ngx_msec_t) n * 1000 / p->limit_rate : 0;

        if (delay > 0) {
            p->upstream->read->delayed = 1;
            ngx_add_timer(p->upstream->read, delay);
            break;
        }
    }

#if (NGX_DEBUG)

    for (cl = p->busy; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf busy s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->out; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf out  s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->in; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf in   s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe length: %O", p->length);

#endif

    if (p->input->committed
        && (p->input->eof || p->input->error
            || (p->length != -1
                && (off_t) p->input->committed >= p->length)))
    {
        if (ngx_event_pipe_input_publish(p,
                                         p->input->committed - p->input->ready,
                                         1)
            != NGX_OK)
        {
            return NGX_ABORT;
        }

        if (ngx_event_pipe_filter_input(p) != NGX_OK) {
            return NGX_ABORT;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_filter_input(ngx_event_pipe_t *p)
{
    ngx_int_t                rc;
    ngx_buf_t               *buf;
    ngx_event_pipe_input_t  *in;

    in = p->input;

    for ( ;; ) {
        if (in->closed && in->receiving == NULL
            && in->committed != in->ready)
        {
            if (ngx_event_pipe_input_publish(p, in->committed - in->ready, 1)
                != NGX_OK)
            {
                return NGX_ABORT;
            }
        }

        buf = ngx_event_pipe_input_next(p);
        if (buf == NULL) {
            break;
        }

        /* STUB */ buf->num = p->num++;

        /*
         * Filters inspect and update the public terminal flags.  Expose the
         * saved status during the callback, then retain its result privately
         * until all accepted input and required writes have been processed.
         */

        p->upstream_done = in->done;
        p->upstream_eof = in->eof;
        p->upstream_error = in->error;

        rc = p->input_filter(p, buf);

        in->done = p->upstream_done;
        in->eof = p->upstream_eof;
        in->error = p->upstream_error;
        in->closed |= in->done || in->eof || in->error || p->length == 0;
        p->upstream_done = 0;
        p->upstream_eof = 0;
        p->upstream_error = 0;

        if (rc == NGX_ERROR) {
            in->error = 1;
            in->closed = 1;

            /* Keep receive and published-buffer ownership until teardown. */

            return NGX_ABORT;
        }

        if (buf->shadow == NULL) {
            ngx_event_pipe_input_release(p, buf);
        }

        p->read = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)
{
    u_char            *prev;
    size_t             bsize;
    ngx_int_t          rc;
    ngx_uint_t         flush, flushed, prev_last_shadow;
    ngx_chain_t       *out, **ll, *cl;
    ngx_connection_t  *downstream;

    downstream = p->downstream;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe write downstream: %d", downstream->write->ready);

    out = NULL;
    ngx_chain_update_chains(p->pool, &p->free, &p->busy, &out, p->tag);

    if (ngx_event_pipe_recycle_buffers(p) != NGX_OK) {
        return NGX_ABORT;
    }

#if (NGX_THREADS)

    if (p->writing) {
        rc = ngx_event_pipe_write_chain_to_temp_file(p);

        if (rc == NGX_ABORT) {
            return NGX_ABORT;
        }
    }

#endif

    flushed = 0;

    for ( ;; ) {
        if (p->downstream_error) {
            return ngx_event_pipe_drain_chains(p);
        }

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {

            /* pass the p->out and p->in chains to the output filter */

            for (cl = p->busy; cl; cl = cl->next) {
                cl->buf->recycled = 0;
            }

            if (p->out == NULL && p->in == NULL) {
                out = NULL;
                ngx_chain_update_chains(p->pool, &p->free, &p->busy, &out,
                                        p->tag);

                if (ngx_event_pipe_recycle_buffers(p) != NGX_OK) {
                    return NGX_ABORT;
                }
            }

            if (p->out) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush out");

                for (cl = p->out; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = ngx_event_pipe_output_chain(p, &p->out);

                if (rc == NGX_ABORT) {
                    return NGX_ABORT;
                }

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }
            }

            if (p->writing) {
                break;
            }

            if (p->in) {
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush in");

                for (cl = p->in; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = ngx_event_pipe_output_chain(p, &p->in);
                p->last_in = &p->in;

                if (rc == NGX_ABORT) {
                    return NGX_ABORT;
                }

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe write downstream done");

            /* TODO: free unused bufs */

            p->downstream_done = 1;
            break;
        }

        if (downstream->data != p->output_ctx
            || !downstream->write->ready
            || downstream->write->delayed)
        {
            break;
        }

        /* bsize is the size of the busy recycled bufs */

        prev = NULL;
        bsize = 0;

        for (cl = p->busy; cl; cl = cl->next) {

            if (cl->buf->recycled) {
                if (prev == cl->buf->start) {
                    continue;
                }

                bsize += cl->buf->end - cl->buf->start;
                prev = cl->buf->start;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write busy: %uz", bsize);

        out = NULL;

        if (bsize >= (size_t) p->busy_size) {
            flush = 1;
            goto flush;
        }

        flush = p->busy && ngx_event_pipe_input_blocked(p);
        ll = NULL;
        prev_last_shadow = 1;

        for ( ;; ) {
            if (p->out) {
                cl = p->out;

                if (cl->buf->recycled) {
                    ngx_log_error(NGX_LOG_ALERT, p->log, 0,
                                  "recycled buffer in pipe out chain");
                }

                p->out = p->out->next;

            } else if (!p->cacheable && !p->writing && p->in) {
                cl = p->in;

                ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write buf ls:%d %p %z",
                               cl->buf->last_shadow,
                               cl->buf->pos,
                               cl->buf->last - cl->buf->pos);

                if (cl->buf->recycled && prev_last_shadow) {
                    if (bsize + cl->buf->end - cl->buf->start > p->busy_size) {
                        flush = 1;
                        break;
                    }

                    bsize += cl->buf->end - cl->buf->start;
                }

                prev_last_shadow = cl->buf->last_shadow;

                p->in = p->in->next;

            } else {
                break;
            }

            cl->next = NULL;

            if (out) {
                *ll = cl;
            } else {
                out = cl;
            }
            ll = &cl->next;
        }

    flush:

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write: out:%p, f:%ui", out, flush);

        if (out == NULL) {

            if (!flush) {
                break;
            }

            /* a workaround for AIO */
            if (flushed++ > 10) {
                return NGX_BUSY;
            }
        }

        rc = ngx_event_pipe_output_chain(p, &out);

        if (rc == NGX_ABORT) {
            return NGX_ABORT;
        }

        if (rc == NGX_ERROR) {
            p->downstream_error = 1;
            return ngx_event_pipe_drain_chains(p);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_output_chain(ngx_event_pipe_t *p, ngx_chain_t **out)
{
    ngx_int_t  rc;

    rc = p->output_filter(p->output_ctx, *out);

    ngx_chain_update_chains(p->pool, &p->free, &p->busy, out, p->tag);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    return ngx_event_pipe_recycle_buffers(p);
}


static ngx_int_t
ngx_event_pipe_recycle_buffers(ngx_event_pipe_t *p)
{
    ngx_chain_t  *cl;

    for (cl = p->free; cl; cl = cl->next) {

        /* TODO: free buf if p->free_bufs && upstream done */

        /* return the storage behind the last consumed shadow */

        if (cl->buf->last_shadow) {
            if (ngx_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
                return NGX_ABORT;
            }

            cl->buf->last_shadow = 0;
        }

        cl->buf->shadow = NULL;
    }

    if (p->cacheable || !p->cyclic_temp_file || p->writing) {
        return NGX_OK;
    }

    /* rewind only when no live buffers reference the temporary file */

    for (cl = p->out; cl; cl = cl->next) {
        if (cl->buf->in_file
            && cl->buf->file == &p->temp_file->file
            && cl->buf->file_pos < cl->buf->file_last)
        {
            return NGX_OK;
        }
    }

    for (cl = p->busy; cl; cl = cl->next) {
        if (cl->buf->in_file
            && cl->buf->file == &p->temp_file->file
            && cl->buf->file_pos < cl->buf->file_last)
        {
            return NGX_OK;
        }
    }

    p->temp_file->offset = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p)
{
    ssize_t       n;
    ngx_int_t     rc;
    ngx_chain_t  *out;

#if (NGX_THREADS)

    if (p->writing) {

        if (p->aio) {
            return NGX_AGAIN;
        }

        out = p->writing;
        p->writing = NULL;

        n = ngx_write_chain_to_temp_file(p->temp_file, NULL);

        if (n == NGX_ERROR) {
            (void) ngx_event_pipe_free_chain(p, out);
            return NGX_ABORT;
        }

        return ngx_event_pipe_update_temp_file_bufs(p, out, n);
    }

#endif

    rc = ngx_event_pipe_prepare_temp_file_write(p, &out);

    if (rc != NGX_OK) {
        return rc;
    }

#if (NGX_THREADS)
    if (p->thread_handler) {
        p->temp_file->thread_write = 1;
        p->temp_file->file.thread_task = p->thread_task;
        p->temp_file->file.thread_handler = p->thread_handler;
        p->temp_file->file.thread_ctx = p->thread_ctx;
    }
#endif

    n = ngx_write_chain_to_temp_file(p->temp_file, out);

    if (n == NGX_ERROR) {
        (void) ngx_event_pipe_free_chain(p, out);
        return NGX_ABORT;
    }

#if (NGX_THREADS)

    if (n == NGX_AGAIN) {
        p->writing = out;
        p->thread_task = p->temp_file->file.thread_task;
        return NGX_AGAIN;
    }

#endif

    return ngx_event_pipe_update_temp_file_bufs(p, out, n);
}


static ngx_int_t
ngx_event_pipe_prepare_temp_file_write(ngx_event_pipe_t *p,
    ngx_chain_t **chain)
{
    ssize_t       size, bsize;
    ngx_uint_t    prev_last_shadow;
    ngx_chain_t  *cl, *out, **ll;

    if (p->buf_to_file) {
        out = ngx_alloc_chain_link(p->pool);
        if (out == NULL) {
            return NGX_ABORT;
        }

        out->buf = p->buf_to_file;
        out->next = p->in;

    } else {
        out = p->in;
    }

    if (out == NULL) {
        return NGX_BUSY;
    }

    if (!p->cacheable) {

        size = 0;
        cl = out;
        ll = NULL;
        prev_last_shadow = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe offset: %O", p->temp_file->offset);

        do {
            bsize = cl->buf->last - cl->buf->pos;

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe buf ls:%d %p, pos %p, size: %z",
                           cl->buf->last_shadow, cl->buf->start,
                           cl->buf->pos, bsize);

            if (prev_last_shadow
                && ((size + bsize > p->temp_file_write_size)
                    || (p->temp_file->offset + size + bsize
                        > p->max_temp_file_size)))
            {
                break;
            }

            prev_last_shadow = cl->buf->last_shadow;

            size += bsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "size: %z", size);

        if (ll == NULL) {
            return NGX_BUSY;
        }

        if (cl) {
            p->in = cl;
            *ll = NULL;

        } else {
            p->in = NULL;
            p->last_in = &p->in;
        }

    } else {
        p->in = NULL;
        p->last_in = &p->in;
    }

    *chain = out;

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_update_temp_file_bufs(ngx_event_pipe_t *p, ngx_chain_t *out,
    ssize_t n)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl, **last_out;

    if (p->buf_to_file) {
        p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
        n -= p->buf_to_file->last - p->buf_to_file->pos;
        p->buf_to_file = NULL;
        cl = out;
        out = out->next;
        ngx_free_chain(p->pool, cl);
    }

    if (n > 0) {
        /* update previous buffer or add new buffer */

        if (p->out) {
            for (cl = p->out; cl->next; cl = cl->next) { /* void */ }

            b = cl->buf;

            if (b->file_last == p->temp_file->offset) {
                p->temp_file->offset += n;
                b->file_last = p->temp_file->offset;
                goto free;
            }

            last_out = &cl->next;

        } else {
            last_out = &p->out;
        }

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            (void) ngx_event_pipe_free_chain(p, out);
            return NGX_ABORT;
        }

        b = cl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->tag = p->tag;

        b->file = &p->temp_file->file;
        b->file_pos = p->temp_file->offset;
        p->temp_file->offset += n;
        b->file_last = p->temp_file->offset;

        b->in_file = 1;
        b->temp_file = 1;

        *last_out = cl;
    }

free:

    return ngx_event_pipe_free_chain(p, out);
}


/* the copy input filter */

ngx_int_t
ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    if (p->upstream_done) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "input data after close");
        return NGX_OK;
    }

    if (p->length == 0) {
        p->upstream_done = 1;

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        return NGX_OK;
    }

    cl = ngx_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    b = cl->buf;

    ngx_memcpy(b, buf, sizeof(ngx_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return NGX_OK;
    }

    if (b->last - b->pos > p->length) {

        ngx_log_error(NGX_LOG_WARN, p->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");

        b->last = b->pos + p->length;
        p->upstream_done = 1;

        return NGX_OK;
    }

    p->length -= b->last - b->pos;

    return NGX_OK;
}


static ngx_inline void
ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf)
{
    ngx_buf_t  *b, *next;

    b = buf->shadow;

    if (b == NULL) {
        return;
    }

    while (!b->last_shadow) {
        next = b->shadow;

        b->temporary = 0;
        b->recycled = 0;

        b->shadow = NULL;
        b = next;
    }

    b->temporary = 0;
    b->recycled = 0;
    b->last_shadow = 0;

    b->shadow = NULL;

    buf->shadow = NULL;
}


ngx_int_t
ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    ngx_event_pipe_input_release(p, b);

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_free_chain(ngx_event_pipe_t *p, ngx_chain_t *chain)
{
    ngx_buf_t    *raw;
    ngx_chain_t  *cl, *next;

    /* These chains have not been handed to a downstream filter. */

    for (cl = chain; cl; cl = next) {
        next = cl->next;

        if (cl->buf->last_shadow) {
            raw = cl->buf->shadow;
            ngx_event_pipe_remove_shadow_links(raw);

            if (ngx_event_pipe_add_free_buf(p, raw) != NGX_OK) {
                return NGX_ABORT;
            }
        }

        if (cl->buf->tag != p->tag) {
            ngx_free_chain(p->pool, cl);
            continue;
        }

        cl->next = p->free;
        p->free = cl;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_drain_chains(ngx_event_pipe_t *p)
{
    ngx_chain_t  *cl;

    for ( ;; ) {
        if (p->out) {
            cl = p->out;
            p->out = NULL;

        } else if (p->in) {
            cl = p->in;
            p->in = NULL;
            p->last_in = &p->in;

        } else {
            return NGX_OK;
        }

        if (ngx_event_pipe_free_chain(p, cl) != NGX_OK) {
            return NGX_ABORT;
        }
    }
}
