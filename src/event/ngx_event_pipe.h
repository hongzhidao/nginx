
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

typedef void (*ngx_event_pipe_input_notify_pt)(void *data);

#define NGX_EVENT_PIPE_INPUT_EOF    1
#define NGX_EVENT_PIPE_INPUT_ERROR  2

typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
    ngx_buf_t *buf);
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
    ngx_chain_t *chain);


struct ngx_event_pipe_s {
    ngx_connection_t                 *upstream;
    ngx_connection_t                 *downstream;

    struct ngx_event_pipe_input_s    *input;

    ngx_chain_t                      *in;
    ngx_chain_t                     **last_in;

    ngx_chain_t                      *writing;

    ngx_chain_t                      *out;
    ngx_chain_t                      *free;
    ngx_chain_t                      *busy;

    /*
     * the input filter i.e. that moves HTTP/1.1 chunks
     * from the raw bufs to an incoming chain
     */

    ngx_event_pipe_input_filter_pt    input_filter;
    void                             *input_ctx;

    ngx_event_pipe_output_filter_pt   output_filter;
    void                             *output_ctx;

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                       (*thread_handler)(ngx_thread_task_t *task,
                                                      ngx_file_t *file);
    void                             *thread_ctx;
    ngx_thread_task_t                *thread_task;
#endif

    unsigned                          read:1;
    unsigned                          preread:1;
    unsigned                          cacheable:1;
    unsigned                          free_bufs:1;
    unsigned                          upstream_done:1;
    unsigned                          upstream_error:1;
    unsigned                          upstream_eof:1;
    unsigned                          upstream_blocked:1;
    unsigned                          downstream_done:1;
    unsigned                          downstream_error:1;
    unsigned                          cyclic_temp_file:1;
    unsigned                          aio:1;

    ngx_bufs_t                        bufs;
    ngx_buf_tag_t                     tag;

    ssize_t                           busy_size;

    off_t                             read_length;
    off_t                             length;

    off_t                             max_temp_file_size;
    ssize_t                           temp_file_write_size;

    ngx_msec_t                        read_timeout;
    ngx_msec_t                        send_timeout;
    ssize_t                           send_lowat;

    ngx_pool_t                       *pool;
    ngx_log_t                        *log;

    ngx_chain_t                      *preread_bufs;
    size_t                            preread_size;
    ngx_buf_t                        *buf_to_file;

    size_t                            limit_rate;
    time_t                            start_sec;

    ngx_temp_file_t                  *temp_file;

    /* STUB */ int                    num;
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


/*
 * The pipe owns private input state.  Producers borrow writable buffers
 * and commit received bytes; the pipe filters and forwards them when driven
 * by ngx_event_pipe(), independently of socket reception.  All input
 * operations use the pipe as their context; input state has no back pointer
 * to the pipe.
 *
 * Initialize after configuring the pipe and preread buffers.  reserve()
 * targets a total configured-buffer count, excluding preread storage.
 * capacity() reports writable bytes, excluding an outstanding receive; size,
 * when non-NULL, receives total managed storage, including preread storage.
 * finish(), parser completion and cancellation close admission; capacity then
 * returns zero, while total managed storage remains queryable.
 *
 * Only one receive may be active.  Its views expire on commit() or cancel().
 * commit() releases the unused reservation and makes received bytes available
 * to the pipe.  A zero-byte commit releases an unused receive.  Readers may
 * alter buffer descriptors, but must preserve the receive chain links.
 * Storage retained by downstream readers remains owned by the pipe.
 *
 * Parser completion closes admission but preserves an active receive until
 * commit() or cancel(); the pipe defers completion until that receive ends.
 *
 * finish() stops admission and publishes the remaining committed bytes.
 * Pipe completion waits for filtering and required file writes, independently
 * of buffers retained downstream.  cancel() detaches the user and discards
 * unfiltered bytes; the caller must first stop using its receive views.
 * Downstream and outstanding file-write ownership survive cancellation.
 * NGX_ABORT from ngx_event_pipe() requires teardown: stop the user, invalidate
 * its scheduled work and cancel the input before any further pipe processing.
 *
 * notify(data) reports possible progress, including release of a prefix that
 * blocks publication.  It must schedule the user, never reenter the pipe.
 * The user must also invalidate any notifications already scheduled before
 * cancellation.  input_ctx continues to belong exclusively to input_filter.
 */

ngx_int_t ngx_event_pipe_input_init(ngx_event_pipe_t *p,
    ngx_event_pipe_input_notify_pt notify, void *data);
ngx_int_t ngx_event_pipe_input_reserve(ngx_event_pipe_t *p, ngx_uint_t n);
size_t ngx_event_pipe_input_capacity(ngx_event_pipe_t *p, size_t *size);
ngx_chain_t *ngx_event_pipe_input_alloc_bufs(ngx_event_pipe_t *p,
    size_t limit);
ngx_int_t ngx_event_pipe_input_commit(ngx_event_pipe_t *p, size_t n);
ngx_int_t ngx_event_pipe_input_finish(ngx_event_pipe_t *p, ngx_uint_t flags);
void ngx_event_pipe_input_cancel(ngx_event_pipe_t *p);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
