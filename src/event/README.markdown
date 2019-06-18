# event模块
## 概览
* `ngx_event.c` ：这个文件主要放置Nginx事件event模块的核心代码。包含：进程事件分发器（ngx_process_events_and_timers）、事件模块的模块和配置、模块初始化/配置初始化等事件模块初始化的核心函数。
* `ngx_event_timer.c`：定时器事件管理。主要放置定时器的代码。
* `ngx_event_posted.c`：主要用于 拿到accept锁的进程 处理accept和read事件的回调函数。
* `ngx_event_pipe.c`：主要用于处理管道。
* `ngx_event_openssl.c`：主要用于处理SSL通道。HTTPS协议。
* `ngx_event_connect.c`：主要用于处理TCP的连接通道。
* `ngx_event_accept.c`：核心是ngx_event_accept和ngx_event_recvmsg，主要是处理accept事件的回调函数handler。而后续的read事件被ngx_event_accept中回调ngx_listen_t结构中的ls->handler回调函数回调，并且将rev->handler修改成ngx_http_wait_request_handler方法。
* `modules/xxxx.c`：主要封装了各种平台的事件模型。

## 主要数据结构
* ngx_listening_s：主要是监听套接字结构，存放socket的信息
* ngx_connection_s：存储连接有关的信息和读写事件。
* ngx_event_s：主要存放事件的数据结构。