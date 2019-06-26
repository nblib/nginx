
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts; // 指向数组的起始地址
    ngx_uint_t        nelts; // 表示数组中已经使用了多少个元素,必须小于等于nalloc
    ngx_list_part_t  *next; // 下一个链表元素ngx_list_part_t的地址
};


typedef struct {
    ngx_list_part_t  *last; //指向链表的最后一个数组元素。
    ngx_list_part_t   part; //链表的首个数组元素。
    size_t            size; // 每一个数组元素的占用的空间大小, 也就是sizeof(元素)
    ngx_uint_t        nalloc; // 链表的数组元素一旦分配后是不可更改的。nalloc表示每个ngx_list_part_t数组的容量，即最多可存储多少个数据
    ngx_pool_t       *pool; // 内存池
} ngx_list_t;

/**
 * 至少会创建一个数组（不会创建空链表），其中包含n个大小为size字节的连续内存块，也就是ngx_list_t结构中的part成员
 * @param pool
 * @param n  每个链表数组可容纳元素的个数
 * @param size  sizeof(元素)
 * @return 新创建的链表地址，如果创建失败，则返回NULL空指针
 */
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

/**
 *  初始化一个新创建的list_t,包括为list_t中的part_t分配一个长度为n * size 的数组
 * @param list  新创建的list_t
 * @param pool
 * @param n 链表数组可容纳元素的个数
 * @param size  sizeof(元素)
 * @return list_t
 */
static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 * 遍历list的例子
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


/**
 * 添加新的元素. 使用它时通常先调用ngx_list_push得到返回的元素地址，再对返回的地址进行赋值
 * 如果 part_t数组满了,那么就再创建一个part_t同样大小的part_t
 * @param list
 * @return ，新分配的元素首地
 */
void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
