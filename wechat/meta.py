# -*- coding: utf-8 -*-

import re


class WeChatMeta(object):
    APP_ID = 'wx782c26e4c19acffb'
    
    LOGIN_URI = 'https://login.weixin.qq.com'

    URL = {
        'uuid': '/jslogin',
        'push_login': '/cgi-bin/mmwebwx-bin/webwxpushloginurl',
        'login_status': '/cgi-bin/mmwebwx-bin/login',
        'qr_code': '/l/',
        'upload_media': '/webwxuploadmedia',
        'sync_check': '/synccheck',
        'web_sync': '/webwxsync',
        'web_init': '/webwxinit',
        'web_status ': '/webwxstatusnotify',
        'get_contacts': '/webwxgetcontact',
        'batch_get_contacts': '/webwxbatchgetcontact',
        'send_message': '/webwxsendmsg',
        'send_image': '/webwxsendmsgimg',
        'send_video': '/webwxsendvideomsg',
        'send_file': '/webwxsendappmsg',
        'update_chatroom': '/webwxupdatechatroom',
        'create_chatroom': '/webwxcreatechatroom',
        'set_pin': '/webwxoplog',
    }

    RE = {
        'uuid': re.compile(r'QRLogin\.uuid = "(?P<uuid>\S+)"'),
        'login_status': re.compile(r'window\.code=(?P<status>\d+)'),
        'main_uri': re.compile(r'window.redirect_uri="(?P<main_uri>\S+)"'),
        'sync_check': re.compile(r'synccheck=\{retcode:"(?P<retcode>\d+)",'
                                 r'selector:"(?P<selector>\d+)"\}')
    }
