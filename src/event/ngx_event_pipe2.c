
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Zhidao HONG
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_pipe2.h>


typedef struct ngx_event_pipe2_block_s  ngx_event_pipe2_block_t;

/*
 * A block has one output owner and an independent receive view.  The private
 * cursors describe bytes not yet handed off: start <= pos <= last <= end.
 * A retained output prefix does not take away the writable tail.  Its next
 * publication to the output filter waits for that prefix.
 */

struct ngx_event_pipe2_block_s {
    ngx_buf_t                  output;  /* must be first */
    ngx_chain_t                chain;
    ngx_buf_t                  recv_buf;
    ngx_chain_t                receive;

    ngx_event_pipe2_block_t   *next;
    ngx_event_pipe2_block_t   *recv_next;
    u_char                    *start;
    u_char                    *pos;
    u_char                    *last;
    u_char                    *end;
    size_t                     reserved;

    unsigned                   busy:1;
    unsigned                   in_queue:1;
};


typedef struct {
    ngx_event_pipe_t                pipe;  /* upstream config and resources */

    ngx_event_pipe2_notify_pt       notify;
    void                           *data;

    ngx_event_pipe2_block_t        *free;
    ngx_uint_t                      allocated;
    size_t                          capacity;

    ngx_event_pipe2_block_t        *recv_block;
    ngx_event_pipe2_block_t        *receiving;
    size_t                          reserved;

    ngx_event_pipe2_block_t        *in;
    ngx_event_pipe2_block_t       **last_in;

    ngx_chain_t                    *busy;
    ngx_chain_t                   **last_busy;

    ngx_int_t                       terminal;
    unsigned                        initialized:1;
    unsigned                        complete:1;
    unsigned                        cancelled:1;
    unsigned                        progress:1;
} ngx_event_pipe2_t;


static void ngx_event_pipe2_release_block(ngx_event_pipe2_t *q,
    ngx_event_pipe2_block_t *block);
static ngx_chain_t *ngx_event_pipe2_take_chain(ngx_event_pipe2_t *q);
static ngx_uint_t ngx_event_pipe2_recycle_busy(ngx_event_pipe2_t *q);
static void ngx_event_pipe2_discard(ngx_event_pipe2_t *q);
static ngx_int_t ngx_event_pipe2_output(ngx_event_pipe2_t *q,
    ngx_uint_t terminal, ngx_int_t flush);


static const ngx_event_pipe_ops_t  ngx_event_pipe2_ops = {
    ngx_event_pipe2,
    ngx_event_pipe2_input_complete,
    ngx_event_pipe2_input_error,
    ngx_event_pipe2_input_cancel
};


ngx_event_pipe_t *
ngx_event_pipe2_create(ngx_pool_t *pool)
{
    ngx_event_pipe2_t  *q;

    q = ngx_pcalloc(pool, sizeof(ngx_event_pipe2_t));
    if (q == NULL) {
        return NULL;
    }

    q->pipe.ops = &ngx_event_pipe2_ops;
    q->pipe.pool = pool;
    q->last_in = &q->in;
    q->last_busy = &q->busy;

    return &q->pipe;
}


ngx_uint_t
ngx_event_pipe2_input_initialized(ngx_event_pipe_t *p)
{
    return ((ngx_event_pipe2_t *) p)->initialized;
}


ngx_uint_t
ngx_event_pipe2_input_complete(ngx_event_pipe_t *p)
{
    return ((ngx_event_pipe2_t *) p)->complete;
}


ngx_int_t
ngx_event_pipe2_input_init(ngx_event_pipe_t *p,
    ngx_event_pipe2_notify_pt notify, void *data)
{
    ngx_event_pipe2_t  *q;

    q = (ngx_event_pipe2_t *) p;

    if (q->initialized || q->cancelled || q->terminal) {
        return NGX_BUSY;
    }

    if (p->upstream || p->preread_bufs) {
        return NGX_ERROR;
    }

    q->notify = notify;
    q->data = data;
    q->initialized = 1;

    return NGX_OK;
}


ngx_int_t
ngx_event_pipe2_input_reserve(ngx_event_pipe_t *p, ngx_uint_t n)
{
    ngx_event_pipe2_t        *q;
    ngx_event_pipe2_block_t  *block;

    q = (ngx_event_pipe2_t *) p;

    if (!q->initialized || q->cancelled || q->terminal || q->receiving
        || p->bufs.num <= 0 || p->bufs.size == 0
        || n > (ngx_uint_t) p->bufs.num
        || p->bufs.size > NGX_MAX_SIZE_T_VALUE / (size_t) p->bufs.num)
    {
        return NGX_ERROR;
    }

    while (q->allocated < n) {
        block = ngx_pcalloc(p->pool, sizeof(ngx_event_pipe2_block_t));
        if (block == NULL) {
            return NGX_ERROR;
        }

        block->start = ngx_palloc(p->pool, p->bufs.size);
        if (block->start == NULL) {
            return NGX_ERROR;
        }

        block->pos = block->start;
        block->last = block->start;
        block->end = block->start + p->bufs.size;
        block->next = q->free;
        q->free = block;
        q->allocated++;
        q->capacity += p->bufs.size;
    }

    return NGX_OK;
}


size_t
ngx_event_pipe2_input_capacity(ngx_event_pipe_t *p, size_t *size)
{
    ngx_event_pipe2_t  *q;

    q = (ngx_event_pipe2_t *) p;

    if (size) {
        *size = q->allocated * p->bufs.size;
    }

    return q->cancelled || q->terminal ? 0 : q->capacity - q->reserved;
}


ngx_chain_t *
ngx_event_pipe2_input_alloc_bufs(ngx_event_pipe_t *p, size_t limit)
{
    size_t                     n;
    ngx_chain_t               *chain, **last;
    ngx_event_pipe2_t         *q;
    ngx_event_pipe2_block_t   *block, *next, **last_recv;

    q = (ngx_event_pipe2_t *) p;

    if (!q->initialized || q->cancelled || q->terminal || q->receiving) {
        return NULL;
    }

    chain = NULL;
    last = &chain;
    last_recv = &q->receiving;
    block = q->recv_block ? q->recv_block : q->free;

    for ( ; block && limit; block = next) {
        next = block == q->recv_block ? q->free : block->next;
        n = ngx_min(limit, (size_t) (block->end - block->last));
        if (n == 0) {
            continue;
        }

        if (block != q->recv_block) {
            q->free = next;
        }

        ngx_memzero(&block->recv_buf, sizeof(ngx_buf_t));
        block->recv_buf.start = block->last;
        block->recv_buf.pos = block->last;
        block->recv_buf.last = block->last;
        block->recv_buf.end = block->last + n;
        block->recv_buf.temporary = 1;
        block->receive.buf = &block->recv_buf;
        block->receive.next = NULL;
        block->recv_next = NULL;
        block->reserved = n;
        *last_recv = block;
        last_recv = &block->recv_next;
        *last = &block->receive;
        last = &block->receive.next;
        q->reserved += n;
        limit -= n;
    }

    return chain;
}


ngx_int_t
ngx_event_pipe2_input_commit(ngx_event_pipe_t *p, size_t n)
{
    size_t                     size;
    ngx_event_pipe2_t         *q;
    ngx_event_pipe2_block_t   *block, *next;

    q = (ngx_event_pipe2_t *) p;

    if (q->cancelled || q->receiving == NULL || n > q->reserved) {
        return NGX_ERROR;
    }

    p->read_length += n;
    q->capacity -= n;

    for (block = q->receiving; block; block = next) {
        next = block->recv_next;
        size = ngx_min(n, block->reserved);
        block->reserved = 0;
        n -= size;

        if (size) {
            if (block != q->recv_block) {
                q->recv_block = block;
            }

            block->last += size;

            if (!block->in_queue) {
                block->in_queue = 1;
                block->next = NULL;
                *q->last_in = block;
                q->last_in = &block->next;
            }
        }

        if (!block->busy && !block->in_queue) {
            ngx_event_pipe2_release_block(q, block);
        }
    }

    q->receiving = NULL;
    q->reserved = 0;

    return NGX_OK;
}


void
ngx_event_pipe2_input_error(ngx_event_pipe_t *p)
{
    ngx_event_pipe2_t  *q;

    q = (ngx_event_pipe2_t *) p;

    if (!q->cancelled) {
        q->terminal = NGX_ERROR;
        p->upstream_done = 0;
        p->upstream_eof = 0;
        p->upstream_error = 1;
    }
}


ngx_int_t
ngx_event_pipe2_input_finish(ngx_event_pipe_t *p, ngx_int_t status)
{
    ngx_event_pipe2_t  *q;

    q = (ngx_event_pipe2_t *) p;

    if (q->cancelled) {
        return NGX_ERROR;
    }

    if (status == NGX_ERROR) {
        ngx_event_pipe2_input_error(p);
        return NGX_OK;
    }

    if (status != NGX_DONE || !q->initialized || q->receiving) {
        return NGX_ERROR;
    }

    if (q->terminal == 0) {
        q->terminal = status;
    }

    return NGX_OK;
}


void
ngx_event_pipe2_input_cancel(ngx_event_pipe_t *p)
{
    ngx_event_pipe2_t        *q;
    ngx_event_pipe2_block_t  *block;

    q = (ngx_event_pipe2_t *) p;

    if (q->cancelled) {
        return;
    }

    q->cancelled = 1;
    q->notify = NULL;
    q->data = NULL;

    for (block = q->receiving; block; block = block->recv_next) {
        block->reserved = 0;
    }

    q->receiving = NULL;
    q->reserved = 0;
    ngx_event_pipe2_discard(q);
}


static void
ngx_event_pipe2_release_block(ngx_event_pipe2_t *q,
    ngx_event_pipe2_block_t *block)
{
    block->busy = 0;
    q->progress = 1;

    if (block->in_queue || block->reserved) {
        return;
    }

    if (block == q->recv_block) {
        q->recv_block = NULL;
    }

    q->capacity += block->last - block->start;
    block->pos = block->start;
    block->last = block->start;
    block->next = q->free;
    q->free = block;
}


static ngx_chain_t *
ngx_event_pipe2_take_chain(ngx_event_pipe2_t *q)
{
    ngx_buf_t                *b;
    ngx_chain_t              *cl;
    ngx_event_pipe2_block_t  *block;

    block = q->in;
    q->in = block->next;

    if (q->in == NULL) {
        q->last_in = &q->in;
    }

    block->in_queue = 0;

    block->busy = 1;
    b = &block->output;
    cl = &block->chain;

    ngx_memzero(b, sizeof(ngx_buf_t));
    b->start = block->start;
    b->end = block->end;
    b->pos = block->pos;
    b->last = block->last;
    b->temporary = 1;
    b->recycled = 1;
    b->flush = 1;
    b->tag = q->pipe.tag;
    cl->buf = b;
    cl->next = NULL;
    block->pos = block->last;

    return cl;
}


static ngx_uint_t
ngx_event_pipe2_recycle_busy(ngx_event_pipe2_t *q)
{
    ngx_uint_t    progress;
    ngx_chain_t  *cl;

    progress = 0;

    while (q->busy && ngx_buf_size(q->busy->buf) == 0) {
        cl = q->busy;
        q->busy = cl->next;
        progress = 1;

        ngx_event_pipe2_release_block(q, (ngx_event_pipe2_block_t *) cl->buf);
    }

    if (q->busy == NULL) {
        q->last_busy = &q->busy;
    }

    return progress;
}


static void
ngx_event_pipe2_discard(ngx_event_pipe2_t *q)
{
    ngx_event_pipe2_block_t  *block;

    while (q->in) {
        block = q->in;
        q->in = block->next;
        block->in_queue = 0;
        block->pos = block->last;

        if (!block->busy) {
            ngx_event_pipe2_release_block(q, block);
        }
    }

    q->last_in = &q->in;
}


static ngx_int_t
ngx_event_pipe2_output(ngx_event_pipe2_t *q, ngx_uint_t terminal,
    ngx_int_t flush)
{
    size_t             busy;
    ngx_int_t          rc;
    ngx_chain_t       *out, *cl, **last;
    ngx_event_pipe_t  *p;

    p = &q->pipe;
    out = NULL;
    last = &out;
    busy = 0;

    for (cl = q->busy; cl; cl = cl->next) {
        if (terminal) {
            cl->buf->recycled = 0;
        }
        busy += cl->buf->end - cl->buf->start;
    }

    while (q->in && !q->in->busy) {
        if (!terminal && busy + p->bufs.size > (size_t) p->busy_size) {
            break;
        }

        cl = ngx_event_pipe2_take_chain(q);
        cl->buf->recycled = !terminal;
        *last = cl;
        last = &cl->next;
        busy += p->bufs.size;
    }

    if (out == NULL && (!flush || q->busy == NULL)) {
        return NGX_BUSY;
    }

    if (out) {
        *q->last_busy = out;
        q->last_busy = last;
    }

    rc = p->output_filter(p->output_ctx, out);

    if (rc == NGX_ERROR) {
        p->downstream_error = 1;
        ngx_event_pipe2_discard(q);
    }

    return ngx_event_pipe2_recycle_busy(q) || out ? NGX_OK : NGX_BUSY;
}


ngx_int_t
ngx_event_pipe2(ngx_event_pipe_t *p, ngx_int_t do_write)
{
    ngx_int_t           rc;
    ngx_uint_t          progress, terminal;
    ngx_event_t        *wev;
    ngx_event_pipe2_t  *q;

    q = (ngx_event_pipe2_t *) p;

    if (!q->initialized || p->downstream == NULL || p->cacheable) {
        return NGX_ABORT;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "event pipe2: %i", do_write);

    do_write |= (q->busy != NULL);

    for ( ;; ) {
        progress = ngx_event_pipe2_recycle_busy(q);

        if (q->cancelled) {
            break;
        }

        if (p->downstream_error) {
            ngx_event_pipe2_discard(q);
        }

        terminal = q->terminal && !q->receiving;

        if (!p->aio && !p->downstream_error
            && (terminal || (p->downstream->data == p->output_ctx
                             && p->downstream->write->ready
                             && !p->downstream->write->delayed)))
        {
            rc = ngx_event_pipe2_output(q, terminal, do_write || progress);
            progress |= (rc == NGX_OK);
            do_write = 0;
        }

        if (terminal && q->in == NULL) {
            q->complete = 1;
            p->upstream_done = q->terminal == NGX_DONE;
            p->upstream_eof = p->upstream_done;
            p->upstream_error = !p->upstream_done;
            p->downstream_done = !p->downstream_error;
        }

        if (!progress) {
            break;
        }

        do_write = 1;
    }

    if (!q->cancelled && p->downstream->fd != (ngx_socket_t) -1
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

    if (q->progress) {
        q->progress = 0;
        if (q->notify) {
            q->notify(q->data);
        }
    }

    return NGX_OK;
}
