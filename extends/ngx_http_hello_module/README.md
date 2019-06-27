# 自定义简单的nginx模块

## 使用方法
进入nginx源码目录:
```
# 指定模块所在的文件夹
./configure --add-module=/data/ngx_http_hello_module/
make &&make install
```
进入安装目录/usr/local/nginx,编辑配置文件:
```
location /test{
    hello;
}
```
启动nginx
```
./sbin/nginx
```
访问:
```
curl "http://localhost/test"
```
相应结果:
```
你好
```

## 遇到的问题

### 问题1
```
objs/ngx_modules.c:158:1: error: missing terminating " character
```
windows下的换行符导致,修改为linux的换行符

### 问题2
```
 undefined reference to `ngx_http_hello_module'
 ```
 代码中ngx_module_t变量的名字要和模块名字相同,否则找不到定义