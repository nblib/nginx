
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

/**
 * 。ngx_buf_t是一种基本数据结构，本质上它提供的仅仅是一些指针成员和标志位。
 */
struct ngx_buf_s {
    /**
     * 通常是用来告诉使用者本次应该从
     * pos这个位置开始处理内存中的数据，这样设置是因为同一个
     * ngx_buf_t可能被多次反复处理。当然，
     * pos的含义是由使用它的模块定义的
     */
    u_char          *pos;
    /**
     * 通常表示有效的内容到此为止，注意，
     * pos与
     * last之间的内存是希望
     * nginx处理的内容
     */
    u_char          *last;
    /**
     *  处理文件时，
     *  file_pos与
     *  file_last的含义与处理内存时的
     *  pos与
     *  last相同，
     *  file_pos表示将要处理的文件位置，
     *  file_last表示截止的文件位置
     */
    off_t            file_pos;
    off_t            file_last;

    /**
     * 如果
     * ngx_buf_t缓冲区用于内存，那么
     * start指向这段内存的起始地址
     */
    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    /**
     * 表示当前缓冲区的类型，例如由哪个模块使用就指向这个模块
     * ngx_module_t变量的地址
     */
    ngx_buf_tag_t    tag;
    /**
     * 引用的文件
     */
    ngx_file_t      *file;
    /**
     * 当前缓冲区的影子缓冲区，该成员很少用到，仅仅在
     * 使用缓冲区转发上游服务器的响应时才使用了
     * shadow成员，这是因为
     * Nginx太节约内存了，分配一块内存并使用
     * ngx_buf_t表示接收到的上游服务器响应后，在向下游客户端转发时可能会把这块内存存储到文件中，也可能直接向下游发送，此时
     * Nginx绝不会重新复制一份内存用于新的目的，而是再次建立一个
     * ngx_buf_t结构体指向原内存，这样多个
     * ngx_buf_t结构体指向了同一块内存，它们之间的关系就通过
     * shadow成员来引用。这种设计过于复杂，通常不建议使用
     */
    ngx_buf_t       *shadow;


    /* the buf's content could be changed */
    /**
     * 临时内存标志位，为1时表示数据在内存中且这段内存可以修改
     */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    /**
     * 标志位，为1时表示数据在内存中且这段内存不可以被修改
     */
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    /**
     * 标志位，为1时表示这段内存是用mmap系统调用映射过来的，不可以被修改
     */
    unsigned         mmap:1;

    /**
     * 标志位，为1时表示可回收
     */
    unsigned         recycled:1;
    /**
     * 标志位，为1时表示这段缓冲区处理的是文件而不是内存
     */
    unsigned         in_file:1;
    /**
     * 标志位，为1时表示需要执行flush操作
     */
    unsigned         flush:1;
    /**
     * 标志位，对于操作这块缓冲区时是否使用同步方式，需谨慎考虑，这可能会阻塞Nginx进程，
     * Nginx中所有操作几乎都是异步的，这是它支持高并发的关键。有些框架代码在sync为1时可能会有阻塞的方式进行
     * I/O操作，它的意义视使用它的Nginx模块而定
     */
    unsigned         sync:1;
    /**
     * 标志位，表示是否是最后一块缓冲区，因为ngx_buf_t可以由ngx_chain_t链表串联起来，
     * 因此，当last_buf为1时，表示当前是最后一块待处理的缓冲区
     */
    unsigned         last_buf:1;
    /**
     * 标志位，表示是否是ngx_chain_t中的最后一块缓冲区
     */
    unsigned         last_in_chain:1;

    /**
     * 标志位，表示是否是最后一个影子缓冲区，与shadow域配合使用。通常不建议使用它
     */
    unsigned         last_shadow:1;
    /**
     * 标志位，表示当前缓冲区是否属于临时文件
     */
    unsigned         temp_file:1;

    /* STUB */ int   num;
};


/**
 * buf指向当前的ngx_buf_t缓冲区，next则用来指向下一个ngx_chain_t。如果这是最后一个
 * ngx_chain_t，则需要把next置为NULL。
 * 在向用户发送HTTP包体时，就要传入ngx_chain_t链表对象，注意，如果是最后一个
 * ngx_chain_t，那么必须将next置为NULL，否则永远不会发送成功，而且这个请求将一直不会
 * 结束（Nginx框架的要求）
 */
struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
