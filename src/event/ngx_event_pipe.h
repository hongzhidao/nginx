
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

typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,
                                                    ngx_buf_t *buf);
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,
                                                     ngx_chain_t *chain);


struct ngx_event_pipe_s {
    ngx_connection_t       *upstream;
    ngx_connection_t       *downstream;

    struct ngx_event_pipe_input_s  *input;

    ngx_chain_t            *in;
    ngx_chain_t           **last_in;

    ngx_chain_t            *writing;

    ngx_chain_t            *out;
    ngx_chain_t            *free;
    ngx_chain_t            *busy;

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

    unsigned           read:1;
    unsigned           cacheable:1;
    unsigned           free_bufs:1;
    unsigned           upstream_done:1;
    unsigned           upstream_error:1;
    unsigned           upstream_eof:1;
    unsigned           upstream_blocked:1;
    unsigned           downstream_done:1;
    unsigned           downstream_error:1;
    unsigned           cyclic_temp_file:1;
    unsigned           aio:1;

    ngx_bufs_t         bufs;
    ngx_buf_tag_t      tag;

    ssize_t            busy_size;

    off_t              read_length;
    off_t              length;

    off_t              max_temp_file_size;
    ssize_t            temp_file_write_size;

    ngx_msec_t         read_timeout;
    ngx_msec_t         send_timeout;
    ssize_t            send_lowat;

    ngx_pool_t        *pool;
    ngx_log_t         *log;

    ngx_chain_t       *preread_bufs;
    size_t             preread_size;
    ngx_buf_t         *buf_to_file;

    size_t             limit_rate;
    time_t             start_sec;

    ngx_temp_file_t   *temp_file;

    /* STUB */ int     num;
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


/*
 * The pipe owns private input state.  Producers borrow writable buffers
 * and commit received bytes; the pipe filters and forwards them when driven
 * by ngx_event_pipe(), independently of socket reception.  All input operations
 * use the pipe as their context; input state has no back pointer to the pipe.
 *
 * reserve() targets a total configured-buffer count, excluding preread storage.
 * capacity() reports writable bytes, excluding an outstanding receive; size,
 * when non-NULL, receives the total managed storage, including preread storage.
 *
 * Only one receive may be active.  Its views expire on commit(), which releases
 * the unused reservation and makes received bytes available to the pipe.
 * A zero-byte commit releases an unused receive.  Readers may alter the buffer
 * descriptors, but must preserve the receive chain links.  Storage retained by
 * downstream readers remains owned by the pipe.
 */

ngx_int_t ngx_event_pipe_input_init(ngx_event_pipe_t *p);
ngx_int_t ngx_event_pipe_input_reserve(ngx_event_pipe_t *p, ngx_uint_t n);
size_t ngx_event_pipe_input_capacity(ngx_event_pipe_t *p, size_t *size);
ngx_chain_t *ngx_event_pipe_input_alloc_bufs(ngx_event_pipe_t *p,
    size_t limit);
ngx_int_t ngx_event_pipe_input_commit(ngx_event_pipe_t *p, size_t n);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
