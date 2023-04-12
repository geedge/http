# 1.简介

http.so是sapp平台解析层插件。

# 2.业务层开发指南

HTTP业务层插件demo参见project http_service：https://git.mesalab.cn/MESA_Platform/http_service

# 3. 依赖库

G_HTTP_VERSION_4_20191112之后的http.so依赖http_parsr.so，该库可以从./src/lib/中获取。
编译http_parsr源码，make library生成动态库。

# 4.配置文件说明

http_main.conf

=================

``` 
[FUNCTION]
switch_no_biz=1

#0 means close stat
stat_cycle=0
#stat output screen 0: screen 1: file
stat_screen_print=0
stat_file=./log/http/http_stat.log

#ungzip
ungzip_switch=1

#support proxy
proxy_switch=1

#single-way traffic need http session num, 0 means no this function
singleway_maxseq=2

#0: field callback mode(default)     1:batch callback mode
callback_mode=0

#batch field maxnum when http_all or http_other
batch_field_maxnum=32

#check HEAD when s2c one-way
s2c_head_check_switch=1   # 检查s2c单向流情况下，应答消息是否是HEAD的应答，如果是，头部中的content-length与实际响应体大小不一致。

[LOG]
#FATAL:wrong info
#INFO: lostlen; special proc ;proxy info
#DEBUG: pending and close info; all url; 
log_level=30
log_path=./log/http/runtime
``` 