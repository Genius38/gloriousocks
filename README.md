#### Intro

这是一个基于libev写的Socks5 Proxy Server

当前状态：未完成

***

##### Run
```bash
git clone --recursive https://github.com/Genius38/gloriousocks.git
./build/gloriousocks_server
```
***
##### Test
```bash
curl --socks5 localhost:15593 -U cricetinae:123456 www.baidu.com
```
