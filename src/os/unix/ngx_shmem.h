
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/**
 * 描述一块共享内存
 */
typedef struct {
    //指向共享内存的起始地址
    u_char      *addr;
    //共享内存的长度
    size_t       size;
    //这块共享内存的名称
    ngx_str_t    name;
    ngx_log_t   *log;
    //表示共享内存是否已经分配过的标志位，为1时表示已经存在
    ngx_uint_t   exists;   /* unsigned  exists:1;  */
} ngx_shm_t;


ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);


#endif /* _NGX_SHMEM_H_INCLUDED_ */
