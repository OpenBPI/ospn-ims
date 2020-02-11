# OSN-IMSDemo 接口文档

1. 用户注册  

```
{
"user":"OSNID",
"command":"login"
}
```
回复
```
{
"userHash":"user hash",
"errCode":"0"
}
```

2. 发送消息  

```
{
"sign":"",
"description":"",
"from":"",
"to":"",
"command":"message",
"content":"",
"hash":"",
"crypto":"",
"timestamp":""
}
```
回复
```
 {
"errCode":"0"
}
```

3. 获取消息

```
{
"user":"",
"command":"getmsg"
}
回复
```
{
"data":[msg1,msg2,msg3...],
"errCode":"0"
}
```














