# -*- coding: utf-8 -*-

import time

from wechat.client import WeChat

w = WeChat()
w.login()

print(w.client.login_info)

while True:
    time.sleep(100)
