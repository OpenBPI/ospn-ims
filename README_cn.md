# OSN-IMSDemo
**作者：apowners**  
`OSN-IMSDemo` 是一个IM演示服务，仅仅支持端到端的聊天功能。
## 安装
### 一、编译  
TODO
### 二、部署
启动演示版ims服务  
```norup java -jar osn-ims.jar > ims.log &```
## 配置
配置OSN-connector的IP和端口，端口目前固定为8400，配置命令如下：  
```nohup java -jar osn_ims.jar [ip] > ims.log &```
## 文档
* OSN-IMSDemo与OSN-connector之间进行通信，请参见[OSN-connector](https://github.com/OpenBPI/osn-connector)接口文档  
* OSN-IMSDemo与客户端的通信文档见[interface.md](./interface.md)


