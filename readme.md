# 1.简介

http.so是sapp平台解析层插件。

# 2.业务层开发指南

HTTP业务层插件demo参见project http_service：https://git.mesalab.cn/MESA_Platform/http_service

# 3. 依赖库

G_HTTP_VERSION_4_20191112之后的http.so依赖http_parsr.so，该库可以从./src/lib/中获取。
编译http_parsr源码，make library生成动态库。