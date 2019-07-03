
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};

/**
 * Nginx全局变量cycle
 */
struct ngx_cycle_s {
    /**
     * 配置文件 上下文的数组，每个模块的配置信息. 只保存每个模块配置文件数据结构的指针地址
     */
    void                  ****conf_ctx;
    /**
     * 内存池地址
     */
    ngx_pool_t               *pool;

    /**
     * 日志模块中提供了生成基本ngx_log_t日志对象的功能，
     * 这里的log实际上是在还没有执行ngx_init_cycle方法前，也就是还没有解析配置前，如果有信息需要输出到日志，就会暂时使用log对象，它会输出到屏幕。
     * 在ngx_init_cycle方法执行后，将会根据nginx.conf配置文件中的配置项，构造出正确的日志文件，此时会对log重新赋值
     */
    ngx_log_t                *log;
    /**
     * 由nginx.conf配置文件读取到日志文件路径后，将开始初始化error_log日志文件，
     * 由于log对象还在用于输出日志到屏幕，这时会用new_log对象暂时性地替代log日志，
     * 待初始化成功后，会用new_log的地址覆盖上面的log指针
     */
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */


    /**
     * 对于poll、rtsig这样的事件模块，会以有效文件句柄数来预先建立这些ngx_connection_t结构体，以加速事件的收集、分发。
     * 这时files就会保存所有ngx_connection_t的指针组成的数组，files_n就是指针的总数，而文件句柄的值用来访问files数组成员
     */
    ngx_connection_t        **files;

     /**
      * 双向链表容器，元素类型是ngx_connection_t结构体，表示可重复使用连接队列
      */
    ngx_connection_t         *free_connections;
    /**
      * 可用连接池，与free_connection_n配合使用
      */
    ngx_uint_t                free_connection_n;

    /**
     * 模块数组
     */
    ngx_module_t            **modules;
    ngx_uint_t                modules_n; // 模块个数
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    ngx_queue_t               reusable_connections_queue;
    ngx_uint_t                reusable_connections_n;

    ngx_array_t               listening;
    /**
     * 动态数组容器，它保存着Nginx所有要操作的目录。
     * 如果有目录不存在，则会试图创建，而创建目录失败将会导致Nginx启动失败。
     * 例如，上传文件的临时目录也在pathes中，如果没有权限创建，则会导致Nginx无法启动
     */
    ngx_array_t               paths;

    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    /**
     * 单链表容器，元素类型是ngx_open_file_t结构体，它表示Nginx已经打开的所有文件。
     * 事实上，Nginx框架不会向open_files链表中添加文件，
     * 而是由对此感兴趣的模块向其中添加文件路径名，Nginx框架会在ngx_init_cycle方法中打开这些文件
     */
    ngx_list_t                open_files;
    /**
     * 单链表容器，元素的类型是ngx_shm_zone_t结构体，每个元素表示一块共享内存，
     */
    ngx_list_t                shared_memory;

    /**
     * 当前进程中所有连接对象的总数
     */
    ngx_uint_t                connection_n;
    /**
     * 与下面的files成员配合使用，指出files数组里元素的总数
     */
    ngx_uint_t                files_n;

    /**
     * 指向当前进程中的所有连接对象，与connection_n配合使用
     */
    ngx_connection_t         *connections;
    /**
     * 指向当前进程中的所有读事件对象，connection_n同时表示所有读事件的总数
     */
    ngx_event_t              *read_events;
    /**
     * 指向当前进程中的所有写事件对象，connection_n同时表示所有写事件的总数
     */
    ngx_event_t              *write_events;

    /**
     * 旧的ngx_cycle_t对象用于引用上一个ngx_cycle_t对象中的成员。
     * 例如ngx_init_cycle方法，在启动初期，需要建立一个临时的ngx_cycle_t对象保存一些变量，
     * 再调用ngx_init_cycle方法时就可以把旧的ngx_cycle_t对象传进去，而这时old_cycle对象就会保存这个前期的ngx_cycle_t对象
     */
    ngx_cycle_t              *old_cycle;

    /**
     * 配置文件相对于安装目录的路径名称
     */
    ngx_str_t                 conf_file;
    /**
     * Nginx处理配置文件时需要特殊处理的在命令行携带的参数，一般是-g选项携带的参数
     */
    ngx_str_t                 conf_param;
    /**
     * Nginx配置文件所在目录的路径
     */
    ngx_str_t                 conf_prefix;
    /**
     * Nginx安装目录的路径
     */
    ngx_str_t                 prefix;
    /**
     * 用于进程间同步的文件锁名称
     */
    ngx_str_t                 lock_file;
    /**
     * 使用gethostname系统调用得到的主机名
     */
    ngx_str_t                 hostname;
};


/**
 * 核心模块配置字段结构体
 */
typedef struct {
    ngx_flag_t                daemon;
    ngx_flag_t                master;

    ngx_msec_t                timer_resolution;
    ngx_msec_t                shutdown_timeout;

    ngx_int_t                 worker_processes;
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;
    ngx_cpuset_t             *cpu_affinity;

    char                     *username;
    ngx_uid_t                 user;
    ngx_gid_t                 group;

    ngx_str_t                 working_directory;
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
