
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Zhidao HONG
 */


#ifndef _NGX_EVENT_PIPE2_H_INCLUDED_
#define _NGX_EVENT_PIPE2_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event_pipe.h>


typedef void (*ngx_event_pipe2_notify_pt)(void *data);


/*
 * Producer-only body queue.  Every pipe, including retries, comes from create(),
 * which binds its operations for the common event pipe entry points.
 * The producer validates framing and lengths before committing body bytes.
 * init() precedes reception; output configuration must precede the first run.
 * Socket input, preread chains and input filters are not used.
 *
 * reserve() grows storage to n configured blocks, at most bufs.num.  capacity()
 * excludes an active reservation; size returns total allocated payload storage.
 * A single receive borrows writable views until commit() or cancel().  commit()
 * accepts a prefix, independent of changes to receive descriptors or links;
 * commit(0) returns an unused reservation.  Committed bytes can be output even
 * while another receive owns their block's tail.
 *
 * finish() accepts NGX_DONE for EOF or NGX_ERROR for input failure.
 * EOF requires returned receives.  Error is allocation-free, can upgrade EOF,
 * and preserves active receive and output owners.  Completion follows accepted
 * bytes, but does not wait for downstream retention.
 * The legacy upstream status fields are results, not input to this queue.
 *
 * Stop the producer and its scheduled work before cancel(), including on abort.
 * Cancellation is idempotent, prevents reopening, and preserves submitted output
 * buffers.  notify(data) coalesces possible progress at the end
 * of a successful run; it must schedule work rather than reenter the queue.
 */

ngx_event_pipe_t *ngx_event_pipe2_create(ngx_pool_t *pool);
ngx_int_t ngx_event_pipe2(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe2_input_init(ngx_event_pipe_t *p,
    ngx_event_pipe2_notify_pt notify, void *data);
ngx_uint_t ngx_event_pipe2_input_initialized(ngx_event_pipe_t *p);
ngx_int_t ngx_event_pipe2_input_reserve(ngx_event_pipe_t *p, ngx_uint_t n);
size_t ngx_event_pipe2_input_capacity(ngx_event_pipe_t *p, size_t *size);
ngx_chain_t *ngx_event_pipe2_input_alloc_bufs(ngx_event_pipe_t *p, size_t limit);
ngx_int_t ngx_event_pipe2_input_commit(ngx_event_pipe_t *p, size_t n);
ngx_int_t ngx_event_pipe2_input_finish(ngx_event_pipe_t *p, ngx_int_t status);
void ngx_event_pipe2_input_error(ngx_event_pipe_t *p);
ngx_uint_t ngx_event_pipe2_input_complete(ngx_event_pipe_t *p);
void ngx_event_pipe2_input_cancel(ngx_event_pipe_t *p);


#endif /* _NGX_EVENT_PIPE2_H_INCLUDED_ */
