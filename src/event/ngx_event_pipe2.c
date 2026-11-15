
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Zhidao HONG
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_pipe2.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif


typedef struct ngx_event_pipe2_block_s  ngx_event_pipe2_block_t;

/*
 * A block has one output owner and an independent receive view.  The private
 * cursors describe bytes not yet handed off: start <= pos <= last <= end.
 * A retained output prefix does not take away the writable tail.  Its next
 * publication to the output filter waits for that prefix.  At capacity a full
 * block's receive view can instead spill its unpublished tail in FIFO order.
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
    unsigned                   spilling:1;
    unsigned                   in_queue:1;
};


typedef struct {
    ngx_buf_t                  buf;
    ngx_chain_t                chain;
} ngx_event_pipe2_file_chain_t;


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

    ngx_event_pipe2_file_chain_t    file_chains[2];
    ngx_chain_t                    *free_file;
    ngx_chain_t                     cache_header;
    size_t                          cache_header_size;
    size_t                          file_write_size;
    ngx_file_t                      read_file;
    ngx_chain_t                    *file_out;
    ngx_uint_t                      file_busy;

    ngx_int_t                       terminal;
    unsigned                        initialized:1;
    unsigned                        complete:1;
    unsigned                        cancelled:1;
    unsigned                        progress:1;
} ngx_event_pipe2_t;


static void ngx_event_pipe2_release_block(ngx_event_pipe2_t *q,
    ngx_event_pipe2_block_t *block);
static ngx_chain_t *ngx_event_pipe2_take_chain(ngx_event_pipe2_t *q,
    ngx_uint_t spill);
static ngx_uint_t ngx_event_pipe2_recycle_busy(ngx_event_pipe2_t *q);
static void ngx_event_pipe2_discard(ngx_event_pipe2_t *q);
static ngx_int_t ngx_event_pipe2_write_temp_file(ngx_event_pipe2_t *q);
static void ngx_event_pipe2_release_file_chain(ngx_event_pipe2_t *q,
    ngx_chain_t *cl);
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
    ngx_uint_t          i;
    ngx_event_pipe2_t  *q;

    q = ngx_pcalloc(pool, sizeof(ngx_event_pipe2_t));
    if (q == NULL) {
        return NULL;
    }

    q->pipe.ops = &ngx_event_pipe2_ops;
    q->pipe.pool = pool;
    q->last_in = &q->in;
    q->last_busy = &q->busy;
    q->read_file.fd = NGX_INVALID_FILE;

    /* One submitted file extent and one accumulating extent suffice. */

    for (i = 0; i < 2; i++) {
        q->file_chains[i].chain.buf = &q->file_chains[i].buf;
        q->file_chains[i].chain.next = q->free_file;
        q->free_file = &q->file_chains[i].chain;
    }

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

    if (block->in_queue || block->reserved || block->spilling) {
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
ngx_event_pipe2_take_chain(ngx_event_pipe2_t *q, ngx_uint_t spill)
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

    if (spill) {
        /*
         * At zero capacity all blocks are full and their receive views have
         * been returned.  The output filter may still hold a prefix.
         */
        block->spilling = 1;
        b = &block->recv_buf;
        cl = &block->receive;

    } else {
        block->busy = 1;
        b = &block->output;
        cl = &block->chain;
    }

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

        if (cl->buf->in_file) {
            q->file_busy--;
            cl->next = q->free_file;
            q->free_file = cl;

        } else {
            ngx_event_pipe2_release_block(q,
                                          (ngx_event_pipe2_block_t *) cl->buf);
        }
    }

    if (q->busy == NULL) {
        q->last_busy = &q->busy;
    }

    if (!q->pipe.cacheable && q->pipe.cyclic_temp_file
        && q->file_busy == 0 && q->file_out == NULL && !q->pipe.writing)
    {
        q->pipe.temp_file->offset = 0;
    }

    return progress;
}


static void
ngx_event_pipe2_discard(ngx_event_pipe2_t *q)
{
    ngx_event_pipe2_block_t  *block;

    if (q->file_out) {
        q->file_out->next = q->free_file;
        q->free_file = q->file_out;
        q->file_out = NULL;
    }

    if (q->pipe.cacheable && !q->cancelled) {
        return;
    }

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
ngx_event_pipe2_write_temp_file(ngx_event_pipe2_t *q)
{
    size_t                    size, limit;
    ssize_t                   n;
    off_t                     offset;
    ngx_buf_t                *buf;
    ngx_chain_t              *cl, **last;
    ngx_event_pipe_t         *p;
    ngx_event_pipe2_block_t  *block;

    p = &q->pipe;

    if (p->writing) {
#if (NGX_THREADS)
        if (!p->temp_file->file.thread_task->event.complete) {
            return NGX_AGAIN;
        }
#endif
        n = ngx_write_chain_to_temp_file(p->temp_file, NULL);
        goto done;
    }

    if (p->aio) {
        return NGX_AGAIN;
    }

    limit = p->temp_file_write_size;
    if (!p->cacheable) {
        limit = ngx_min((off_t) limit,
                       p->max_temp_file_size - p->temp_file->offset);
    }

    q->file_write_size = 0;
    q->cache_header_size = 0;
    last = &p->writing;

    if (p->buf_to_file) {
        q->cache_header.buf = p->buf_to_file;
        q->cache_header.next = NULL;
        q->cache_header_size = p->buf_to_file->last - p->buf_to_file->pos;
        *last = &q->cache_header;
        last = &q->cache_header.next;
        q->file_write_size = q->cache_header_size;
    }

    while (q->in) {
        block = q->in;
        size = block->last - block->pos;

        if (size > limit && (!p->cacheable || q->file_write_size)) {
            break;
        }

        cl = ngx_event_pipe2_take_chain(q, !p->cacheable);
        *last = cl;
        last = &cl->next;
        q->file_write_size += size;
        limit -= ngx_min(size, limit);
    }

    if (p->writing == NULL) {
        return NGX_BUSY;
    }

#if (NGX_THREADS)
    if (p->thread_handler) {
        p->temp_file->thread_write = 1;
        p->temp_file->file.thread_handler = p->thread_handler;
        p->temp_file->file.thread_ctx = p->thread_ctx;
    }
#endif

    p->temp_file->file.sys_offset = -1;
    n = ngx_write_chain_to_temp_file(p->temp_file, p->writing);

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

done:

    if (n == NGX_ERROR || n != (ssize_t) q->file_write_size) {
        ngx_log_error(NGX_LOG_CRIT, p->log, 0,
                      "pipe2 temporary file write failed: %z of %uz",
                      n, q->file_write_size);
        cl = p->writing;
        p->writing = NULL;
        if (p->buf_to_file) {
            cl = cl->next;
        }
        ngx_event_pipe2_release_file_chain(q, cl);
        return NGX_ABORT;
    }

    offset = p->temp_file->offset + q->cache_header_size;
    p->temp_file->offset += n;

    /* The same fd has separate read and write task ownership. */

    if (q->read_file.fd == NGX_INVALID_FILE) {
        q->read_file = p->temp_file->file;
#if (NGX_THREADS)
        q->read_file.thread_task = NULL;
#endif
    }

    q->read_file.sys_offset = -1;

    if ((off_t) n > (off_t) q->cache_header_size && !q->cancelled) {
        if (q->file_out == NULL) {
            cl = q->free_file;
            if (cl == NULL) {
                return NGX_ABORT;
            }
            q->free_file = cl->next;
            cl->next = NULL;
            q->file_out = cl;
            buf = cl->buf;
            ngx_memzero(buf, sizeof(ngx_buf_t));
            buf->file = &q->read_file;
            buf->file_pos = offset;
            buf->in_file = 1;
            buf->temp_file = 1;
            buf->flush = 1;
            buf->tag = p->tag;
        }

        q->file_out->buf->file_last = p->temp_file->offset;
    }

    cl = p->writing;
    p->writing = NULL;

    if (p->buf_to_file) {
        p->buf_to_file = NULL;
        cl = cl->next;
    }

    ngx_event_pipe2_release_file_chain(q, cl);

    return NGX_OK;
}


static void
ngx_event_pipe2_release_file_chain(ngx_event_pipe2_t *q, ngx_chain_t *cl)
{
    ngx_chain_t              *next;
    ngx_event_pipe2_block_t  *block;

    while (cl) {
        next = cl->next;

        if (q->pipe.cacheable) {
            block = (ngx_event_pipe2_block_t *) cl->buf;
            ngx_event_pipe2_release_block(q, block);

        } else {
            block = (ngx_event_pipe2_block_t *) ((u_char *) cl
                                   - offsetof(ngx_event_pipe2_block_t, receive));
            block->spilling = 0;

            if (!block->busy) {
                ngx_event_pipe2_release_block(q, block);
            }
        }

        cl = next;
    }
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
        if (!cl->buf->in_file) {
            busy += cl->buf->end - cl->buf->start;
        }
    }

    if (q->file_out
        && (q->file_busy == 0
            || (terminal && (!p->cacheable || q->in == NULL))))
    {
        out = q->file_out;
        q->file_out = NULL;
        q->file_busy++;
        last = &out->next;
    }

    while (!q->file_out && !p->cacheable && q->in && !q->in->busy) {
        if (!terminal && busy + p->bufs.size > (size_t) p->busy_size) {
            break;
        }

        cl = ngx_event_pipe2_take_chain(q, 0);
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

    if (!q->initialized || p->downstream == NULL) {
        return NGX_ABORT;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "event pipe2: %i", do_write);

    do_write |= (q->busy != NULL);

    for ( ;; ) {
        progress = ngx_event_pipe2_recycle_busy(q);

        if (p->writing) {
            rc = ngx_event_pipe2_write_temp_file(q);
            if (rc == NGX_ABORT) {
                return NGX_ABORT;
            }
            if (rc == NGX_AGAIN) {
                break;
            }
            progress = 1;
        }

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

        /* Hand off completed output before starting another asynchronous write. */

        if ((p->cacheable && (q->in || p->buf_to_file))
            || (!p->cacheable && q->in && !q->terminal
                && q->capacity == 0
                && p->temp_file->offset < p->max_temp_file_size))
        {
            rc = ngx_event_pipe2_write_temp_file(q);
            if (rc == NGX_ABORT) {
                return NGX_ABORT;
            }
            if (rc == NGX_AGAIN) {
                break;
            }
            progress |= (rc == NGX_OK);
        }

        if (terminal && q->in == NULL && q->file_out == NULL
            && (!p->cacheable || p->buf_to_file == NULL))
        {
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
