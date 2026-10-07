
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_
#define _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_


typedef struct ngx_http_proxy_v2_session_s  ngx_http_proxy_v2_session_t;
typedef struct ngx_http_proxy_v2_stream_s   ngx_http_proxy_v2_stream_t;


/*
 * HTTP/2 error codes (RFC 9113 section 7).  Only the ones this module
 * needs to send are defined here; ngx_http_v2.c defines the full set for
 * its own use, but privately (not exported via ngx_http_v2.h), so they
 * are not reusable from here without duplicating them under this
 * module's own prefix, matching the existing convention that this module
 * does not reach into ngx_http_v2.c internals.
 */

#define NGX_HTTP_PROXY_V2_NO_ERROR           0x0
#define NGX_HTTP_PROXY_V2_PROTOCOL_ERROR     0x1
#define NGX_HTTP_PROXY_V2_INTERNAL_ERROR     0x2
#define NGX_HTTP_PROXY_V2_FLOW_CTRL_ERROR    0x3
#define NGX_HTTP_PROXY_V2_FRAME_SIZE_ERROR   0x6
#define NGX_HTTP_PROXY_V2_CANCEL             0x8


typedef struct {
    u_char                          length_0;
    u_char                          length_1;
    u_char                          length_2;
    u_char                          type;
    u_char                          flags;
    u_char                          stream_id_0;
    u_char                          stream_id_1;
    u_char                          stream_id_2;
    u_char                          stream_id_3;
} ngx_http_proxy_v2_frame_t;


typedef enum {
    ngx_http_proxy_v2_st_start = 0,
    ngx_http_proxy_v2_st_length_2,
    ngx_http_proxy_v2_st_length_3,
    ngx_http_proxy_v2_st_type,
    ngx_http_proxy_v2_st_flags,
    ngx_http_proxy_v2_st_stream_id,
    ngx_http_proxy_v2_st_stream_id_2,
    ngx_http_proxy_v2_st_stream_id_3,
    ngx_http_proxy_v2_st_stream_id_4,
    ngx_http_proxy_v2_st_payload,
    ngx_http_proxy_v2_st_padding
} ngx_http_proxy_v2_state_e;


typedef struct {
    ngx_http_proxy_v2_state_e        state;
    ngx_uint_t                       frame_state;
    size_t                           rest;
    ngx_uint_t                       stream_id;
    u_char                           type;
    u_char                           flags;
    u_char                           padding;
} ngx_http_proxy_v2_scratch_t;


struct ngx_http_proxy_v2_stream_s {
    ngx_rbtree_node_t                node;

    ngx_http_request_t              *request;
    ngx_http_proxy_v2_session_t     *session;

    ngx_connection_t                *connection;
    ngx_event_t                     *read;
    ngx_event_t                     *write;

    ngx_chain_t                     *in;
    ngx_chain_t                     *out;
    ngx_chain_t                     *free;
    ngx_chain_t                     *busy;

    ngx_uint_t                       id;
    ngx_uint_t                       error;

    off_t                            length;

    ssize_t                          send_window;
    size_t                           recv_window;

    ngx_uint_t                       fragment_state;
    ngx_uint_t                       index;
    ngx_str_t                        name;
    ngx_str_t                        value;

    u_char                          *field_end;
    size_t                           header_limit;
    size_t                           field_length;
    size_t                           field_rest;
    u_char                           field_state;

    unsigned                         literal:1;
    unsigned                         field_huffman:1;

    unsigned                         header_sent:1;
    unsigned                         output_closed:1;
    unsigned                         output_blocked:1;
    unsigned                         parsing_headers:1;
    unsigned                         end_stream:1;
    unsigned                         done:1;
    unsigned                         status:1;
    unsigned                         rst:1;
    unsigned                         registered:1;
    unsigned                         connection_created:1;
    unsigned                         rst_sent:1;   /* RST_STREAM already
                                                     * sent on
                                                     * abandonment, see
                                                     * ngx_http_proxy_v2_
                                                     * send_rst_stream() */
    unsigned                         refused:1;    /* above the last stream
                                                     * id of a GOAWAY: not
                                                     * processed, to be
                                                     * retried elsewhere */

    /*
     * Write-turn gate (replaces the old single-active-stream write
     * restriction): at most one stream may call ngx_chain_writer() at
     * a time, tracked by session->writer.  A stream that wants a turn
     * while another stream holds it links onto session->waiting via
     * wait_link and is woken (its write event posted) when the holder
     * releases the turn.  No frame is ever queued or buffered here --
     * only a stream pointer waits, never bytes; the stream builds its
     * frame and calls ngx_chain_writer() only once it is actually its
     * turn.
     */
    ngx_queue_t                       wait_link;
    unsigned                         admitted:1;    /* counted in
                                                      * session->processing;
                                                      * distinct from
                                                      * holding the
                                                      * write turn */
    unsigned                         waiting:1;     /* linked into
                                                      * session->waiting
                                                      * via wait_link;
                                                      * ngx_queue_t has
                                                      * no reliable
                                                      * not-linked
                                                      * sentinel of its
                                                      * own in release
                                                      * builds, so this
                                                      * explicit flag
                                                      * is the source
                                                      * of truth, not
                                                      * wait_link's
                                                      * pointers */

    /* frame parser state of this stream, see swap_scratch() */
    ngx_http_proxy_v2_scratch_t      scratch;
};


struct ngx_http_proxy_v2_session_s {
    ngx_connection_t                *connection;
    ngx_rbtree_t                     streams;
    ngx_rbtree_node_t                streams_sentinel;

    /*
     * Read side only: the stream whose response frame is currently
     * being delivered out of the single frame_header/buffer staging
     * area below (session_dispatch() parses one stream-scoped frame
     * at a time and hands it to whichever stream this points at).
     * Not a write concurrency gate -- see "writer" below for that.
     * When a parsed frame's real stream id names a stream other than
     * this one, ngx_http_proxy_v2_find_stream() locates it and this
     * pointer is switched to it before the frame is delivered, so
     * read delivery still reaches the right stream even though only
     * one frame is ever in flight through this staging area at once
     * (see ngx_http_proxy_v2_session_dispatch()).
     */
    ngx_http_proxy_v2_stream_t      *active_stream;

    /*
     * Write-turn gate.  At most one stream may be inside
     * ngx_chain_writer() at a time (TCP is one ordered byte stream;
     * this is what prevents two streams' frames from interleaving
     * mid-write).  "writer" is that stream, or NULL if the physical
     * connection is idle.  "waiting" is a FIFO of stream pointers
     * (via stream->wait_link) wanting a turn -- never frames, never
     * bytes; see ngx_http_proxy_v2_body_output_filter() for the
     * acquire/release sequence.
     */
    ngx_http_proxy_v2_stream_t      *writer;
    ngx_queue_t                      waiting;

    /*
     * Concurrent-stream admission (ngx_http_proxy_v2_session_admit()).
     * "processing" counts currently-admitted streams.
     * "local_concurrent_streams" is fixed once, from the
     * proxy_http2_max_concurrent_streams directive, the first time a
     * stream registers on this session (ngx_http_proxy_v2_get_ctx()).
     * "peer_concurrent_streams" is 0 (meaning "not yet advertised";
     * RFC 9113 section 6.5.2 permits treating this as unbounded, but
     * this implementation applies the local cap immediately anyway --
     * always safe to be more conservative than the peer allows) until
     * the peer's own SETTINGS_MAX_CONCURRENT_STREAMS is seen
     * (ngx_http_proxy_v2_parse_settings()).  "concurrent_streams" is
     * the derived effective cap, recomputed as
     * min(local_concurrent_streams, peer_concurrent_streams) whenever
     * either input changes, and is the value session_admit() actually
     * checks against.
     */
    ngx_uint_t                       processing;
    ngx_uint_t                       local_concurrent_streams;
    ngx_uint_t                       peer_concurrent_streams;
    ngx_uint_t                       concurrent_streams;

    ngx_chain_t                     *out;
    ngx_chain_t                     *free;
    ngx_chain_t                     *busy;
    ngx_buf_tag_t                    output_tag;

    ngx_buf_t                        buffer;
    u_char                           frame_header[9];
    size_t                           frame_sent;
    size_t                           frame_rest;

    u_char                          *orphan;       /* unsent output of a
                                                     * stream that left the
                                                     * turn holder's frame
                                                     * unfinished */
    size_t                           orphan_len;
    size_t                           orphan_sent;

    size_t                           discard_rest;  /* payload bytes of a
                                                     * frame nobody wants,
                                                     * still to be dropped */

    void                            *connection_data;
    ngx_event_handler_pt             read_handler;
    ngx_event_handler_pt             write_handler;

    ngx_http_proxy_v2_state_e        state;
    ngx_uint_t                       frame_state;

    size_t                           rest;
    ngx_uint_t                       stream_id;
    u_char                           type;
    u_char                           flags;
    u_char                           padding;

    /*
     * The fields above are the frame parser's scratch for the stream that
     * is parsing a frame; session_dispatch() works on this separate copy,
     * swapped in while it runs, so that a stream abandoning a frame
     * halfway cannot leave the dispatcher with a state that is not its own.
     */

    ngx_http_proxy_v2_scratch_t      dispatch;

    size_t                           init_window;
    ssize_t                          send_window;
    size_t                           recv_window;
    ngx_uint_t                       last_stream_id;

    ngx_uint_t                       pings;
    ngx_uint_t                       settings;
    ngx_uint_t                       setting_id;
    ngx_uint_t                       setting_value;
    ngx_uint_t                       window_update;
    ngx_uint_t                       error;
    ngx_uint_t                       goaway_stream_id;

    u_char                           ping_data[8];

    unsigned                         goaway:1;
    unsigned                         goaway_sent:1;
    unsigned                         handlers_saved:1; /* set once, by
                                                * the first stream to
                                                * attach; see
                                                * ngx_http_proxy_v2_
                                                * create_stream_
                                                * connection() */
    unsigned                         stream_frame:1;
    unsigned                         frame_validated:1;
    unsigned                         discarding:1;  /* skipping a frame for
                                                     * a closed stream */
    unsigned                         eof:1;
    unsigned                         error_state:1;
};


/*
 * The frame parser keeps its position in session->state/rest/stream_id/...;
 * each stream has its own copy, exchanged with the session's around every
 * run of the stream's parser.
 */
void ngx_http_proxy_v2_swap_scratch(ngx_http_proxy_v2_session_t *session,
    ngx_http_proxy_v2_scratch_t *scratch);


ngx_int_t ngx_http_proxy_v2_get_session(ngx_peer_connection_t *pc,
    ngx_http_proxy_v2_session_t **session);
void ngx_http_proxy_v2_set_local_concurrent_streams(
    ngx_http_proxy_v2_session_t *session, ngx_uint_t local);
ngx_int_t ngx_http_proxy_v2_register_stream(
    ngx_http_proxy_v2_session_t *session, ngx_http_proxy_v2_stream_t *stream);
ngx_int_t ngx_http_proxy_v2_session_admit(
    ngx_http_proxy_v2_session_t *session, ngx_http_proxy_v2_stream_t *stream);
void ngx_http_proxy_v2_unregister_stream(ngx_http_proxy_v2_stream_t *stream);
void ngx_http_proxy_v2_deactivate_stream(
    ngx_http_proxy_v2_stream_t *stream);
ngx_int_t ngx_http_proxy_v2_create_stream_connection(
    ngx_http_proxy_v2_stream_t *stream, ngx_http_upstream_t *u,
    size_t buffer_size);
void ngx_http_proxy_v2_restore_connection(ngx_http_proxy_v2_stream_t *stream,
    ngx_http_upstream_t *u);
ngx_uint_t ngx_http_proxy_v2_session_reusable(
    ngx_http_proxy_v2_session_t *session);
ngx_http_proxy_v2_stream_t *ngx_http_proxy_v2_get_stream(
    ngx_http_request_t *r);
ngx_http_proxy_v2_stream_t *ngx_http_proxy_v2_find_stream(
    ngx_http_proxy_v2_session_t *session, ngx_uint_t id);
ngx_int_t ngx_http_proxy_v2_parse_frame(ngx_http_proxy_v2_session_t *session,
    ngx_buf_t *b);
ngx_int_t ngx_http_proxy_v2_process_control_frame(
    ngx_http_proxy_v2_session_t *session, ngx_buf_t *b);
ngx_int_t ngx_http_proxy_v2_send_connection_window_update(
    ngx_http_proxy_v2_session_t *session);
ngx_int_t ngx_http_proxy_v2_send_goaway(ngx_http_proxy_v2_session_t *session,
    ngx_uint_t error_code);


#endif /* _NGX_HTTP_PROXY_V2_SESSION_H_INCLUDED_ */
