# -*- coding: utf-8 -*-

import os
import io
import re
import sys
import json
import time
import random
import logging
import hashlib
import weakref
import functools
import threading
import mimetypes
from pprint import pprint
from collections import defaultdict, OrderedDict

import redis
import requests
from lxml import etree
from pyqrcode import QRCode
from requests.utils import cookiejar_from_dict

if sys.version_info > (3, 0):
    from urllib.parse import urlparse
    from html import unescape
else:
    from urlparse import urlparse
    from HTMLParser import HTMLParser
    unescape = HTMLParser().unescape

try:
    import enum
except:
    raise ImportError(
        'For Python 2.x, install package enum34 to fix this error'
    )


# TODO remove from here
USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) ' \
             'AppleWebKit/537.36 (KHTML, like Gecko) ' \
             'Chrome/57.0.2987.110 Safari/537.36'


def set_logger(name, level=logging.INFO):
    formatter = logging.Formatter(
        '[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] %(message)s',
    )
    stream_handler = logging.StreamHandler()
    stream_handler.formatter = formatter
    logger = logging.getLogger(name)
    logger.addHandler(stream_handler)
    logger.setLevel(level)
    return logger


logger = set_logger('wechatclient')

emojiRegex = re.compile(r'<span class="emoji emoji(.{1,10})"></span>')


# TODO move to wechat client static method

def emoji_formatter(d, k):
    ''' _emoji_deebugger is for bugs about emoji match caused by wechat
    backstage
    like :face with tears of joy: will be replaced with :cat face with tears
    of joy:
    '''

    def _emoji_debugger(d, k):
        s = d[k].replace('<span class="emoji emoji1f450"></span',
                         '<span class="emoji emoji1f450"></span>')

        def __fix_miss_match(m):
            return '<span class="emoji emoji%s"></span>' % ({
                '1f63c': '1f601', '1f639': '1f602', '1f63a': '1f603',
                '1f4ab': '1f616', '1f64d': '1f614', '1f63b': '1f60d',
                '1f63d': '1f618', '1f64e': '1f621', '1f63f': '1f622',
            }.get(m.group(1), m.group(1)))

        return emojiRegex.sub(__fix_miss_match, s)

    def _emoji_formatter(m):
        s = m.group(1)
        if len(s) == 6:
            return ('\\U%s\\U%s' % (s[:2].rjust(8, '0'), s[2:].rjust(8, '0'))
            ).encode('utf8').decode('unicode-escape', 'replace')
        elif len(s) == 10:
            return ('\\U%s\\U%s' % (s[:5].rjust(8, '0'), s[5:].rjust(8, '0'))
            ).encode('utf8').decode('unicode-escape', 'replace')
        else:
            return ('\\U%s' % m.group(1).rjust(8, '0')
            ).encode('utf8').decode('unicode-escape', 'replace')

    d[k] = _emoji_debugger(d, k)
    d[k] = emojiRegex.sub(_emoji_formatter, d[k])


class WeChatClientError(Exception):
    pass


class LoginFailedError(WeChatClientError):
    pass


class MultiListenThreadError(WeChatClientError):
    pass


class WeChatMeta(object):
    BASE_URI = 'https://login.weixin.qq.com'
    JSON_LOGIN_URL = BASE_URI + '/jslogin'
    PUSH_LOGIN_URL = BASE_URI + '/cgi-bin/mmwebwx-bin/webwxpushloginurl'
    LOGIN_POLLING_URL = BASE_URI + '/cgi-bin/mmwebwx-bin/login'
    QR_CODE_URL = BASE_URI + '/l/'
    UPLOAD_MEDIA_URL = '/webwxuploadmedia'

    SYNC_CHECK_URL = '/synccheck'

    WEB_SYNC_URL = '/webwxsync'
    WEB_INIT_URL = '/webwxinit'
    WEB_STATUS = '/webwxstatusnotify'
    GET_CONTACT_URL = '/webwxgetcontact'
    BATCH_CONTACT_URL = '/webwxbatchgetcontact'
    SEND_MESSAGE_URL = '/webwxsendmsg'
    SEND_IMAGE_URL = '/webwxsendmsgimg'
    SEND_VIDEO_URL = '/webwxsendvideomsg'
    SEND_FILE_URL = '/webwxsendappmsg'
    UPDATE_CHATROOM_URL = '/webwxupdatechatroom'
    CREATE_CHATROOM_URL = '/webwxcreatechatroom'
    SET_PIN_URL = '/webwxoplog'

    APP_ID = 'wx782c26e4c19acffb'

    JSON_LOGIN_PARAMS = {'appid': APP_ID, 'fun': 'new'}

    UUID_RE = re.compile(r'QRLogin\.uuid = "(?P<uuid>\S+)"')
    LOGIN_POLLING_RE = re.compile(r'window\.code=(?P<status>\d+)')
    LOGIN_REDIRECT_RE = re.compile(
        r'window.redirect_uri="(?P<redirect_uri>\S+)"'
    )
    SYNC_CHECK_RE = re.compile(r'synccheck=\{retcode:"(?P<retcode>\d+)",'
                               r'selector:"(?P<selector>\d+)"\}')
    UIN_RE = re.compile(r'<username>(?P<uin>[^<]*?)<')
    CHRTROOM_MSG = re.compile(u'(?P<username>@[0-9a-z]+):<br/>'
                              u'(@(?P<nickname>.*?)\u2005)?'
                              u'(?P<content>.*)')
    INVITE_MEMBER_RE = re.compile(u'"(?P<nickname>.*?)"加入了群聊')
    REMOVE_MEMBER_RE = re.compile(u'"(?P<nickname>.*?)"移出了群聊')

    FILE_MESSAGE_TEMPLATE = (
        "<appmsg appid='{}' sdkver=''><title>{}</title><des></des><action>"
        "</action><type>6</type><content></content><url></url><lowurl>"
        "</lowurl><appattach><totallen>{}</totallen><attachid>{}</attachid>"
        "<fileext>{}</fileext></appattach><extinfo></extinfo></appmsg>")

    __default_empty_string = [
        'UserName', 'City', 'DisplayName', 'PYQuanPin', 'RemarkPYInitial',
        'Province', 'KeyWord', 'RemarkName', 'PYInitial', 'EncryChatRoomId',
        'Alias', 'Signature', 'NickName', 'RemarkPYQuanPin', 'HeadImgUrl',
    ]
    __default_zero = [
        'UniFriend', 'Sex', 'AppAccountFlag', 'VerifyFlag', 'ChatRoomId',
        'HideInputBarFlag', 'AttrStatus', 'SnsFlag', 'MemberCount',
        'OwnerUin', 'ContactFlag', 'Uin', 'StarFriend', 'Statues',
    ]
    __default_list = ['MemberList']

    __default_contact = dict([(f, '') for f in __default_empty_string] +
                             [(f, 0) for f in __default_zero] +
                             [(f, []) for f in __default_list])

    @classmethod
    def format_contact(cls, values):
        result = cls.__default_contact.copy()
        result.update(values)
        return result


class MessageType(enum.IntEnum):
    TEXT = 1
    IMAGE = 3
    FILE = 6
    CONTACT_CARD = 42
    VIDEO = 43
    SHARE = 49
    SYSTEM = 10000


class WeChatClient(object):
    DEFAULT_HEADERS = {
        'User-Agent': USER_AGENT,
        'ContentType': 'application/json; charset=UTF-8',
    }
    # 512KB
    CHUNK_SIZE = 1024 * 512

    instance_pool = defaultdict(list)

    def __new__(cls, credential=None):
        if credential:
            uin = credential['login_info']['wxuin']
            if uin in cls.instance_pool:
                instance = cls.instance_pool[uin]()
                if instance and instance.alive:
                    return instance
                else:
                    del cls.instance_pool[uin]
                    del instance
        return super(WeChatClient, cls).__new__(cls)

    def __init__(self, credential=None):
        self.loggedin = False
        self._alive = False
        self.uuid = None
        self.login_info = {}

        self.init_data = None
        self.session = requests.Session()
        self.session.headers = self.DEFAULT_HEADERS

        self.contacts = []
        self._chatrooms = {}
        self.non_chatrooms = []
        self.uin_username_map = {}

        self.logout_callback = []
        self.message_callback = {}
        self.credential_update_callback = []

        self._uin = None
        self.username = None
        self.nickname = None
        self.alias = None

        self._listen_thread = None

        if credential:
            self._load_credential(credential)

    @property
    def uin(self):
        return self._uin

    @uin.setter
    def uin(self, value):
        def destroy_instance():
            del self.instance_pool[self.uin]

        self._uin = value
        self.uin_username_map[value] = self.username
        self.instance_pool[self.uin] = weakref.ref(self, destroy_instance)

    @property
    def alive(self):
        return bool(self._alive and self.listen_thread and
                    self.listen_thread.isAlive())

    @property
    def listen_thread(self):
        return self._listen_thread

    @listen_thread.setter
    def listen_thread(self, value):
        if self.listen_thread and self.listen_thread.isAlive():
            raise MultiListenThreadError
        self._listen_thread = value

    @property
    def chatrooms(self):
        return list(self._chatrooms.values())

    def logout(self):
        self._alive = False
        self.loggedin = False
        old_listen_thread = self._listen_thread
        del old_listen_thread
        self._listen_thread = None
        for cb in self.logout_callback:
            cb(self)

    def update_chatroom(self, chatroom):
        username = chatroom['UserName']
        if isinstance(chatroom['MemberList'], list):
            chatroom['MemberList'] = {
                m['UserName']: m for m in chatroom['MemberList']
            }
        if username in self._chatrooms:
            self._chatrooms[username].update(chatroom)
        else:
            self._chatrooms[username] = WeChatMeta.format_contact(chatroom)

    def _process_new_message(self, messages):
        for msg in messages:
            try:
                msg = self._reform_raw_message(msg)
                self._run_message_callback(msg)
            except Exception:
                logger.exception('Failed process raw message')

    def _fetch_server_change(self):
        url = self.login_info['main_uri'] + WeChatMeta.WEB_SYNC_URL
        params = {
            'sid': self.login_info['wxsid'],
            'skey': self.login_info['skey'],
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'SyncKey': self.login_info['SyncKey'],
            'rr': ~int(time.time()),
        }
        resp = self.session.post(url, params=params, json=data)
        result = self._decode_content(resp.content)
        self.login_info['SyncKey'] = result['SyncCheckKey']
        self.login_info['synckey'] = '|'.join([
            '{}_{}'.format(item['Key'], item['Val'])
            for item in result['SyncCheckKey']['List']
        ])
        for item in result['ModContactList']:
            self.update_chatroom(item)

        self._run_credential_update_callback()

        return result['AddMsgList'], result['ModContactList']

    def _push_login(self):
        url = WeChatMeta.PUSH_LOGIN_URL
        uin = self.login_info['wxuin']
        resp = self.session.get(url, params={'uin': uin})
        result = resp.json()
        if 'uuid' in result and str(result.get('ret')) == '0':
            self.uuid = result['uuid']
            return True
        else:
            return False

    def _batch_get_contact(self, usernames, chatrooms=None):
        url = self.login_info['main_uri'] + WeChatMeta.BATCH_CONTACT_URL
        params = {'type': 'ex', 'r': int(time.time())}

        if not chatrooms:
            request_list = [
                {'UserName': username, 'EncryChatRoomId': ''}
                for username in usernames
            ]
        else:
            assert len(usernames) == len(chatrooms), \
                'Username length not equal to Chatrooms length'
            request_list = [
                {'UserName': username, 'EncryChatRoomId': chatroom_id}
                for username, chatroom_id in zip(usernames, chatrooms)
            ]
        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'Count': len(usernames),
            'List': request_list,
        }
        resp = self.session.post(url, params=params, json=data)
        return self._decode_content(resp.content)

    def _get_contact(self):
        url = self.login_info['main_uri'] + WeChatMeta.GET_CONTACT_URL
        all_contact = []

        def fetch_fragment(seq):
            params = {
                'r': int(time.time()),
                'seq': seq,
                'skey': self.login_info['skey'],
            }
            try:
                resp = self.session.get(url, params=params)
            except Exception as err:
                print(err)
                return 0, []
            data = self._decode_content(resp.content)
            all_contact.extend(data.get('MemberList', []))
            return data.get('Seq')

        seq = 0
        while True:
            seq = fetch_fragment(seq)
            if seq == 0:
                break
        other_contacts = []
        for c in all_contact:
            if '@@' in c['UserName']:
                chatroom = self._get_username_info(c['UserName'])
                if not chatroom:
                    continue
                self.update_chatroom(chatroom)
            elif c['Sex'] != 0 or '@' in c['UserName']:
                other_contacts.append(c)

        self.contacts = all_contact
        self.non_chatrooms = other_contacts

    def _get_username_info(self, username, singleton=True):
        if not isinstance(username, (list, set, tuple)):
            username = [username]
        else:
            singleton = False

        def fetch_member_info(members, chatroom_id):
            """fetch 50 contacts info each time"""
            contacts = {}
            for i in range(1, len(members) // 50 + 2):
                batch_members = members[(i - 1) * 50: i * 50]
                result = self._batch_get_contact(
                    batch_members, [chatroom_id] * len(batch_members)
                )
                contacts.update({
                    m['UserName']: m for m in result['ContactList']
                })
            return contacts

        chatrooms = self._batch_get_contact(username)['ContactList']
        for chatroom in chatrooms:
            members = [m['UserName'] for m in chatroom['MemberList']]
            # modify chatroom in-place
            chatroom['MemberList'] = fetch_member_info(members,
                                                       chatroom['UserName'])
        if not chatrooms:
            return {} if singleton else []
        return chatrooms[0] if singleton else chatrooms

    @staticmethod
    def _decode_content(content):
        return json.loads(content.decode('utf-8', 'replace'))

    def _web_init(self):
        url = self.login_info['main_uri'] + WeChatMeta.WEB_INIT_URL

        resp = self.session.post(
            url, params={'r': int(time.time())},
            json={'BaseRequest': self.login_info['BaseRequest']}
        )

        # TODO handle exception
        result = self._decode_content(resp.content)
        # TODO explicit processing
        emoji_formatter(result['User'], 'NickName')
        self.init_data = result

        self.login_info['InviteStartCount'] = int(result['InviteStartCount'])
        self.login_info['SyncKey'] = result['SyncKey']
        self.login_info['username'] = result['User']['UserName']
        self.login_info['nickname'] = result['User']['NickName']

        self.username = result['User']['UserName']
        self.nickname = result['User']['NickName']

    def _polling_login(self):
        if not self.uuid:
            return False
        timestamp = int(time.time())
        params = {
            'uuid': self.uuid,
            'loginicon': True,
            'tip': 0,
            'r': timestamp / 1579,
            '_': timestamp
        }
        resp = self.session.get(WeChatMeta.LOGIN_POLLING_URL, params=params)
        result = WeChatMeta.LOGIN_POLLING_RE.search(resp.text)
        if not result:
            return False

        status = result.group('status')
        if status != '200':
            return False
        else:
            self._extract_login_credential(resp.text)
            return True

    def _extract_login_credential(self, content):
        result = WeChatMeta.LOGIN_REDIRECT_RE.search(content)
        if not result:
            raise LoginFailedError(
                'Failed extract redirect uri after login success'
            )
        redirect_uri = result.group('redirect_uri')
        resp = self.session.get(redirect_uri, allow_redirects=False)

        credit = self.login_info
        resp_xml = etree.fromstring(resp.text)

        parsed_uri = urlparse(redirect_uri)
        essentials = (parsed_uri.scheme, parsed_uri.netloc,
                      parsed_uri.path[:parsed_uri.path.rfind('/')])
        credit['main_uri'] = '{}://{}{}'.format(*essentials)
        credit['upload_uri'] = '{}://file.{}{}'.format(*essentials)
        credit['web_sync_uri'] = '{}://webpush.{}{}'.format(*essentials)
        credit['deviceid'] = 'e' + repr(random.random())[2:17]
        try:
            br = credit['BaseRequest'] = {}
            credit['skey'] = br['Skey'] = resp_xml.xpath('//skey')[0].text
            credit['wxsid'] = br['Sid'] = resp_xml.xpath('//wxsid')[0].text
            credit['wxuin'] = br['Uin'] = resp_xml.xpath('//wxuin')[0].text
            credit['pass_ticket'] = br['DeviceID'] = \
                resp_xml.xpath('//pass_ticket')[0].text
            self.uin = credit['wxuin']
        except TypeError:
            self.login_info = {}
            raise LoginFailedError(
                'Failed extract login credential from login xml'
            )

    def _login_init(self):
        self._web_init()
        self._get_uin_message()
        self._get_contact()
        self._alive = True
        self.alias = self._get_username_info(self.username).get('Alias', '')

        def async_request():
            self._get_contact()
        t = threading.Thread(target=async_request)
        t.setDaemon(True)
        t.start()

    def _get_uin_message(self):
        url = self.login_info['main_uri'] + WeChatMeta.WEB_STATUS
        params = {
            'lang': 'zh_CN',
            'pass_ticket': self.login_info['pass_ticket'],
        }

        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'Code': 3,
            'FromUserName': self.username,
            'ToUserName': self.username,
            'ClientMsgId': int(time.time()),
        }

        resp = self.session.post(url, params=params, json=data)
        return resp.json()['BaseResponse']['Ret'] == 0

    def _get_login_uuid(self):
        resp = self.session.get(WeChatMeta.JSON_LOGIN_URL,
                                params=WeChatMeta.JSON_LOGIN_PARAMS)
        result = WeChatMeta.UUID_RE.search(resp.text)
        assert result, 'Failed get uuid from {}'.format(
            WeChatMeta.JSON_LOGIN_URL)
        return result.group('uuid')

    def _sync_check(self):
        timestamp = int(time.time() * 1000)
        params = {
            'r': timestamp,
            'skey': self.login_info['skey'],
            'sid': self.login_info['wxsid'],
            'uin': self.login_info['wxuin'],
            'deviceid': self.login_info['deviceid'],
            'synckey': self.login_info['synckey'],
            '_': timestamp,
        }
        url = self.login_info['web_sync_uri'] + WeChatMeta.SYNC_CHECK_URL
        resp = self.session.get(url, params=params)
        matched = WeChatMeta.SYNC_CHECK_RE.search(resp.text)
        if not matched or matched.group('retcode') != '0':
            logger.debug('unexpected sync check result')
            return None
        else:
            return matched.group('selector')

    def _update_uin_from_message(self, message):
        matched = WeChatMeta.UIN_RE.search(unescape(message['Content']))
        if not matched:
            return

        uins = matched.group('uin').split(',')
        usernames = message['StatusNotifyUserName'].split(',')

        # TODO use processing pool aysnc update
        for uin, username in zip(uins, usernames):
            if username.startswith('@@'):
                if not username in self._chatrooms:
                    chatroom = self._get_username_info(username)
                    if not chatroom:
                        continue
                    chatroom['Uin'] = uin
                    self.uin_username_map[uin] = username
                    self._chatrooms[username] = chatroom
                else:
                    self._chatrooms[username]['Uin'] = uin

    def _reform_raw_message(self, message):
        message['IsAtMe'] = False
        message['ToUin'] = ''
        message['ToNickName'] = ''
        message['GroupMemberChange'] = None

        if message['MsgType'] == 51:
            self._update_uin_from_message(message)

        try:
            message['MsgType'] = MessageType(message['MsgType']).name.lower()
        except (KeyError, ValueError):
            message['MsgType'] = 'other'

        from_username = message['FromUserName']
        username = message['ToUserName']

        if from_username.startswith('@@'):
            if from_username not in self._chatrooms:
                self._chatrooms[from_username] = \
                    self._get_username_info(from_username)
            chatroom = self._chatrooms[from_username]

            if message['MsgType'] == MessageType.TEXT.name.lower():
                matched = WeChatMeta.CHRTROOM_MSG.match(message['Content'])
                if not matched:
                    return message

                message['FromUserName'] = matched.group('username')
                message['ToUserName'] = from_username
                message['Content'] = matched.group('content')

                display_name = chatroom['MemberList'] \
                    [username]['DisplayName'] or self.nickname
                if display_name == matched.group('nickname'):
                    message['IsAtMe'] = True
            elif message['MsgType'] == MessageType.SYSTEM.name.lower():
                if WeChatMeta.INVITE_MEMBER_RE.search(message['Content']):
                    message['GroupMemberChange'] = 'in'
                elif WeChatMeta.INVITE_MEMBER_RE.search(message['Content']):
                    message['GroupMemberChange'] = 'out'

        username = message['ToUserName']
        if username.startswith('@@'):
            if username not in self._chatrooms:
                self._chatrooms[username] = self._get_username_info(username)
            message['ToUin'] = self._chatrooms[username].get('Uin')
            message['ToNickName'] = self._chatrooms[username].get('NickName')

        return message

    def _run_credential_update_callback(self):
        for cb in self.credential_update_callback:
            cb(self.uin, self.export_credential())

    def _run_message_callback(self, message):
        if isinstance(self.message_callback, dict):
            callbacks = list(self.message_callback.values())
        else:
            callbacks = self.message_callback
        for callback in callbacks:
            try:
                callback(message)
            except Exception as error:
                logger.error(
                    'Failed run callback: {}, error: {}'.format(
                        callback, error))

    def _send(self, to_user, msg_type, url, content=None, media_id=None):
        params = {
            'fun': 'async', 'f': 'json',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        timestamp = int(time.time() * 1e4)
        current_user = self.login_info['username']
        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'Scene': 0,
            'Msg': {
                'Type': msg_type,
                'Content': content,
                'MediaId': media_id,
                'FromUserName': current_user,
                'ToUserName': to_user if to_user else current_user,
                'LocalID': timestamp,
                'ClientMsgId': timestamp,
            }
        }
        resp = self.session.post(
            url, params=params,
            data=json.dumps(data, ensure_ascii=False).encode('utf8')
        )
        return self._decode_content(resp.content)

    @staticmethod
    def _build_file_message_content(file_path, media_id):
        return WeChatMeta.FILE_MESSAGE_TEMPLATE.format(
            os.path.basename(file_path), str(os.path.getsize(file_path)),
            media_id, os.path.splitext(file_path)[1].replace('.', ''),
        )

    def _upload_media(self, file_path, media_type, to_user='filehelper'):
        """
        :return: media_id
        """

        assert media_type in ('pic', 'video', 'doc'), \
            'Invalid media type: {}'.format(media_type)
        params = {'f': 'json'}

        file_size = os.path.getsize(file_path)
        file_type = mimetypes.guess_type(file_path)[0] or \
                    'application/octet-stream'
        with open(file_path, 'rb') as fd:
            file_md5 = hashlib.md5(fd.read()).hexdigest()

        upload_media_request = json.dumps(OrderedDict([
            ('UploadType', 2),
            ('BaseRequest', self.login_info['BaseRequest']),
            ('ClientMediaId', int(time.time() * 1e4)),
            ('TotalLen', file_size),
            ('StartPos', 0),
            ('DataLen', file_size),
            ('MediaType', 4),
            ('FromUserName', self.login_info['username']),
            ('ToUserName', to_user),
            ('FileMd5', file_md5),
        ]), separators=(',', ':'))

        result = None
        chunks = int((file_size - 1) / self.CHUNK_SIZE) + 1
        with open(file_path, 'rb') as fd:
            for chunk in range(chunks):
                last_modified = time.strftime(
                    '%a %b %d %Y %H:%M:%S GMT+0800 (CST)')
                data_ticket = self.session.cookies['webwx_data_ticket']
                files = OrderedDict([
                    ('id', (None, 'WU_FILE_0')),
                    ('name', (None, os.path.basename(file_path))),
                    ('type', (None, file_type)),
                    ('lastModifiedDate', (None, last_modified)),
                    ('size', (None, str(file_size))),
                    ('mediatype', (None, media_type)),
                    ('uploadmediarequest', (None, upload_media_request)),
                    ('webwx_data_ticket', (None, data_ticket)),
                    ('pass_ticket', (None, self.login_info['pass_ticket'])),
                    ('filename', (os.path.basename(file_path),
                        fd.read(self.CHUNK_SIZE), 'application/octet-stream'))
                ])
                if chunks != 1:
                    files['chunk'] = (None, str(chunk))
                    files['chunks'] = (None, str(chunks))

                url = self.login_info['upload_uri'] + \
                      WeChatMeta.UPLOAD_MEDIA_URL
                resp = self.session.post(url, params=params, files=files)
                try:
                    result = resp.json()['MediaId']
                except (TypeError, ValueError):
                    result = None
        return result

    def _load_credential(self, credential):
        self.login_info = credential['login_info']
        self.session.cookies = cookiejar_from_dict(credential['cookies'])
        self.uin_username_map = credential['uin_username_map']
        self.uin = self.login_info['wxuin']
        self.nickname = self.login_info['nickname']
        self.username = self.login_info['username']
        self._chatrooms = credential['chatrooms']

    def register_credential_update_callback(self, callback, *args, **kwargs):
        self.credential_update_callback.append(
            functools.partial(callback, *args, **kwargs))

    def export_credential(self):
        return {
            'cookies': self.session.cookies.get_dict(),
            'login_info': self.login_info,
            'uin_username_map': self.uin_username_map,
            'chatrooms': self._chatrooms,
        }

    def login_by_credential(self, credential=None):
        if credential:
            self._load_credential(credential)

        cookies = self.session.cookies.get_dict()
        cookies.update({
            'login_frequency': '2',
            'last_wxuin': self.login_info['wxuin'],
            'MM_WX_NOTIFY_STATE': '1',
            'MM_WX_SOUND_STATE': '1',
        })
        self.session.cookies = cookiejar_from_dict(cookies)

        message, contacts = self._fetch_server_change()
        if message:
            self.loggedin = True
            self._login_init()
            return True
        else:
            return False

    def login_by_qrcode(self, timeout=180, thread=False, callback=None):
        def polling():
            start_time = time.time()
            while not self.loggedin:
                if time.time() - start_time > timeout:
                    return self.loggedin
                self.loggedin = self._polling_login()
                time.sleep(0.1)
            self._login_init()
            if callback:
                callback()
            return self.loggedin

        if thread:
            polling_thread = threading.Thread(target=polling)
            polling_thread.setDaemon(True)
            polling_thread.start()
            return

        return polling()

    def print_cli_qrcode(self):
        self.uuid = self._get_login_uuid()
        qr_code = QRCode(WeChatMeta.QR_CODE_URL + self.uuid)
        qr_code.svg('uca-url.svg', scale=6)
        print(qr_code.terminal(quiet_zone=1))

    def get_qrcode(self):
        self.uuid = self._get_login_uuid()
        qr_storage = io.BytesIO()
        qr_code = QRCode(WeChatMeta.QR_CODE_URL + self.uuid)
        qr_code.svg(qr_storage, scale=10)
        return qr_storage.getvalue()

    def create_chatroom(self, member_list, name=''):
        """
        :param member_list: member username list
        :param name: chatroom name
        :return: chatroom info dict
        """
        url = self.login_info['main_uri'] + WeChatMeta.CREATE_CHATROOM_URL
        params = {
            'pass_ticket': self.login_info['pass_ticket'],
            'r': int(time.time()),
        }
        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'MemberCount': len(member_list),
            'MemberList':
                [{'UserName': member} for member in member_list],
            'Topic': name,
        }
        resp = self.session.post(
            url, params=params,
            data=json.dumps(data, ensure_ascii=False).encode('utf8', 'ignore')
        )
        result = resp.json()
        if not result['BaseResponse']['Ret'] == 0:
            return None
        else:
            username = result['ChatRoomName']
            self.send_message(username, 'text', 'Everyone welcome!')
            self._get_uin_message()
            return username

    def set_pin(self, username, pin=True):
        url = self.login_info['main_uri'] + WeChatMeta.SET_PIN_URL
        params = {
            'pass_ticket': self.login_info['pass_ticket'],
            'lang': 'zh_CN',
        }
        data = {
            'UserName': username,
            'CmdId': 3,
            'OP': int(pin),
            'RemarkName': '',
            'BaseRequest': self.login_info['BaseRequest'],
        }
        resp = self.session.post(url, params=params, json=data)
        return resp.json()['BaseResponse']['Ret'] == 0

    def get_chatrooms(self, uins=None, usernames=None, nicknames=None):
        if not self.chatrooms:
            username_uin_map = {v: k for k, v in self.uin_username_map.items()}
            usernames = list(self.uin_username_map.values())
            usernames = [u for u in usernames if u and u.startswith('@@')]
            chatrooms = self._get_username_info(usernames)
            for chatroom in chatrooms:
                username = chatroom['UserName']
                chatroom['Uin'] = username_uin_map.get(username, 0)
                self._chatrooms[username] = chatroom

        result = []
        if uins:
            usernames = [self.uin_username_map.get(uin) for uin in uins]

        if usernames:
            for username in usernames:
                result.append(self._chatrooms.get(username))
                return result

        if nicknames:
            for nickname in nicknames:
                for chatroom in self.chatrooms:
                    if chatroom['NickName'] == nickname:
                        result.append(chatroom)
                        break
            return result

        return self.chatrooms

    def _handle_chatroom_id(self, chatroom_id):
        if chatroom_id.startswith('@@'):
            return chatroom_id

        username = self.uin_username_map.get(chatroom_id)
        if username:
            return username

        for chatroom in self.chatrooms:
            if chatroom['NickName'] == chatroom_id:
                return chatroom['UserName']

    def delete_chatroom_member(self, chatroom_id, member_list):
        username = self._handle_chatroom_id(chatroom_id)
        if not username:
            logger.error('Failed delete members, invalid uin: {}'.format(
                chatroom_id))
            return False

        url = self.login_info['main_uri'] + WeChatMeta.UPDATE_CHATROOM_URL
        params = {
            'fun': 'delmember',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'ChatRoomName': username,
            'DelMemberList': ','.join(member_list),
        }
        resp = self.session.post(url, params=params, json=data)
        self._chatrooms[username] = self._get_username_info(username)
        return resp.json()['BaseResponse']['Ret'] == 0

    def add_chatroom_number(self, chatroom_id, member_list):
        username = self._handle_chatroom_id(chatroom_id)
        if not username or username not in self._chatrooms:
            logger.error('Failed delete chatroom members,'
                         ' invalid chatroom_id: {}'.format(chatroom_id))
            return False

        url = self.login_info['main_uri'] + WeChatMeta.UPDATE_CHATROOM_URL
        params = {'pass_ticket': self.login_info['pass_ticket']}
        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'ChatRoomName': username,
        }

        members = ','.join(member_list)
        chatroom = self._chatrooms.get(username)

        if len(chatroom['MemberList']) > self.login_info['InviteStartCount']:
            params['fun'] = 'invitemember'
            data['InviteMemberList'] = members
        else:
            params['fun'] = 'addmember'
            data['AddMemberList'] = members

        resp = self.session.post(url, params=params, json=data)
        self._chatrooms[username] = self._get_username_info(username)
        return resp.json()['BaseResponse']['Ret'] == 0

    def update_chatroom_nickname(self, chatroom_id, nickname):
        username = self._handle_chatroom_id(chatroom_id)
        if not username:
            logger.error('Failed update chatroom nickname,'
                         ' invalid chatroom_id: {}'.format(chatroom_id))
            return False

        url = self.login_info['main_uri'] + WeChatMeta.UPDATE_CHATROOM_URL
        params = {
            'fun': 'modtopic',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['BaseRequest'],
            'ChatRoomName': username,
            'NewTopic': nickname,
        }
        resp = self.session.post(
            url, params=params,
            data=json.dumps(data, ensure_ascii=False).encode('utf8', 'ignore'),
        )
        self._chatrooms[username] = self._get_username_info(username)
        return resp.json()['BaseResponse']['Ret'] == 0

    def listen_message(self, retry_times=3):
        def receive_message_loop(retry_times):
            # sync uin
            self._get_uin_message()
            messages, _ = self._fetch_server_change()
            self._process_new_message(messages)

            while self._alive:
                check_result = self._sync_check()
                if check_result is None:
                    if retry_times < 1:
                        return self.logout()
                    else:
                        retry_times -= 1
                elif check_result != '0':
                    messages, _ = self._fetch_server_change()
                    self._process_new_message(messages)

        self.listen_thread = threading.Thread(
            target=receive_message_loop, args=(retry_times,)
        )
        self.listen_thread.setDaemon(True)
        self.listen_thread.start()

    def send_message(self, to_user, msg_type, payload=None, media_id=None):
        # optimize for chatroom
        to_user = self._handle_chatroom_id(to_user) or to_user

        assert payload or media_id, \
            'Requires at least one argument of payload and media_id'
        try:
            msg_type = MessageType[msg_type.upper()]
        except KeyError:
            raise ValueError('Unsupported message type: {}'.format(msg_type))

        if msg_type == MessageType.TEXT:
            url = self.login_info['main_uri'] + WeChatMeta.SEND_MESSAGE_URL
            result = self._send(to_user, msg_type.value, url, content=payload)
            return result['BaseResponse']['Ret'] == 0

        if msg_type == MessageType.IMAGE:
            media_type = 'pic'
            path = WeChatMeta.SEND_IMAGE_URL
        elif msg_type == MessageType.VIDEO:
            media_type = 'video'
            path = WeChatMeta.SEND_VIDEO_URL
        elif msg_type == MessageType.FILE:
            media_type = 'doc'
            path = WeChatMeta.SEND_FILE_URL
        else:
            raise ValueError('Unsupported message type: {}'.format(msg_type))

        media_id = self._upload_media(payload, media_type, to_user)
        assert media_id, 'Failed upload file: {}'.format(payload)

        url = self.login_info['main_uri'] + path

        if msg_type == MessageType.FILE:
            content = self._build_file_message_content(payload, media_id)
            media_id = None
        else:
            content = None

        result = self._send(to_user, msg_type, url,
                            media_id=media_id, content=content)
        return result['BaseResponse']['Ret'] == 0


if __name__ == '__main__':
    cache = redis.StrictRedis()
    cache_key = 'wechat:uin:%s'

    def demo_message_callback(message):
        pprint(message['Content'])

    def demo_credential_update_callback(uin, credential):
        cache.set(cache_key % uin, json.dumps(credential))

    def demo_login_by_qrcode():
        client = WeChatClient()
        client.print_cli_qrcode()

        def foo():
            client.register_credential_update_callback(
                demo_credential_update_callback)
            client.message_callback = [demo_message_callback]
            pprint(client.username)
            client.listen_message()
        client.login_by_qrcode(timeout=120, thread=True, callback=foo)

        # client.set_pin('filehelper')

        while True:
            # client.send_message(client.username, 'text', str(time.ctime()))
            time.sleep(30)

    def demo_send_message():
        credential = json.loads(cache.get('wechat:uin:569391775'))
        client = WeChatClient(credential)
        pprint(client.get_chatrooms(uins=['7956018427@chatroom']))
        # client._get_uin_message()
        # client.send_message('filehelper', 'text', '000')

    def demo_login_by_credential():
        credential = json.loads(cache.get('wechat:uin:569391775'))
        client = WeChatClient(credential)
        client.login_by_credential()

        client.register_credential_update_callback(
            demo_credential_update_callback)
        client.message_callback = [demo_message_callback]
        client.listen_message()

        while True:
            client.send_message(client.username, 'text', 'c')
            time.sleep(30)

    demo_login_by_qrcode()
    # demo_send_message()
    # demo_login_by_credential()
