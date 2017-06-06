# [barbossa](https://leohowell.github.io/barbossa/)

barbossa项目模拟网页版微信行为，为使用扫码登录、消息收发、群聊管理等功能提供了封装良好的接口。


## 快速上手

扫码登录、打印收到的消息：

```python
from wechat import WeChatClient

client = WeChatClient()
client.print_cli_qrcode()
client.login_by_qrcode(timeout=120)

def handle_msg(msg):
    print(msg)

client.message_callback = [handle_msg]

print('Nickname: {}\n'
      'Username: {}\n'
      'Uin: {}\n'
      'alias: {}\n'
      'Time: {}\n'
      'Main Uri: {}\n'
      .format(client.nickname, client.username, client.uin,
              client.alias, time.ctime(),
              client.login_info['main_uri'])
      )
while True:
    logger.info('Waiting for event...')
    time.sleep(30)
```

## 致谢
- [itchat](https://github.com/littlecodersh/ItChat)

