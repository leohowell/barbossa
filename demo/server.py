# -*- coding: utf-8 -*-

import os
import sys
import json
import time
from collections import deque

import redis
import bottle
import requests
from bottle import (route, run, template, response, request, post,
                    get, delete, static_file, redirect)

sys.path.append(os.path.dirname(__file__) + '/../wechat')

from wechat import WeChatClient, WeChatMeta


ROOT_PATH = os.path.dirname(os.path.abspath(__file__))


bottle.debug(True)
bottle.TEMPLATE_PATH = [ROOT_PATH + '/static/templates']


client = WeChatClient()

MQ = deque()
REDIS = redis.StrictRedis()
CREDENTIAL_KEY_PREFIX = 'barbossa:test-user'


def message_callback(msg):
    print(msg)
    MQ.append(msg)


def save_credential(uin, data):
    REDIS.set(CREDENTIAL_KEY_PREFIX, json.dumps(data), ex=300)


client.message_callback = [message_callback]
client.credential_update_callback = [save_credential]


@route('/static/<filename:path>')
def send_static(filename):
    return static_file(filename, root=ROOT_PATH + '/static')


@route('/hello/<name>')
def index(name):
    return template('<h3>Hello {{name}}</h3>!', name=name)


@route('/login')
def login():
    credential = REDIS.get(CREDENTIAL_KEY_PREFIX)
    if credential:
        login = client.login_by_credential(json.loads(credential))
        if login:
            return redirect('/login/result')
    response.content_type = 'image/svg+xml'
    client.login_by_qrcode(thread=True)
    return client.get_qrcode()


@route('/login/result')
def login_result():
    if client.login:
        return (
            '<h3>Nickname: {}</h3>'
            '<h3>Username: {}</h3>'
            '<h3>Uin: {}</h3>'
            '<h3>alias: {}</h3>'
            '<h3>Time: {}</h3>'
            '<h3>Main Uri: {}</h3>'
            '<h3>pass_ticket: {}</h3>'
            '<h3>upload_url: {}</h3>'.
            format(client.nickname, client.username, client.uin,
                   client.alias, time.ctime(),
                   client.login_info['main_uri'],
                   client.login_info['pass_ticket'],
                   client.login_info['upload_uri'] + WeChatMeta.URL['upload_media']
                   )
        )
    else:
        return '<h3>Please refresh the page</h3>'


@route('/message')
def message():
    return template('msg')


@route('/sse/message')
def sse_message():
    response.content_type = 'text/event-stream'
    response.cache_control = 'no-cache'
    yield 'retry: 100\n\n'

    n = 1

    end = time.time() + 60

    try:
        while time.time() < end:
            if not MQ:
                yield 'data: waiting for message...\n\n'.format(time.ctime())
            else:
                msg = MQ.popleft()
                yield 'data: {}\n\n'.format(json.dumps(msg))
            n += 1
            time.sleep(3)
    except Exception:
        pass
    return 'over.'


@route('/contacts')
def contacts():
    return template('contacts', groups=client.groups,
                    main_uri=client.login_info['main_uri'].rsplit('/', 2)[0],
                    skey=client.login_info['skey'],
                    )


@post('/message/text/<group_id>')
def send_message(group_id):
    msg = request.forms.get('message')
    result = client.send_message(group_id, 'text', msg)
    return 'success' if result else 'failed'


@delete('/contacts/group/<group_id>/<member_id>')
def del_group_member(group_id, member_id):
    result = client.del_group_member(group_id, member_ids=[member_id])
    response.content_type = 'application/json'
    return json.dumps({'status': 'success' if result else 'failed'})


@post('/message/image/<group_id>')
def send_image_message(group_id):
    url = request.forms.get('url')
    result = client.send_message(group_id, msg_type='image', payload=url)
    return 'success' if result else 'failed'


@get('/contacts/avatar/<user_id>')
def get_avatar(user_id):
    response.content_type = 'image/jpeg'
    return client.get_avatar(user_id)


if __name__ == '__main__':
    run(host='localhost', port=8000)
