# -*- coding: utf-8 -*-

import os
import io
import re
import json
import time
import random
import asyncio
import logging
import hashlib
import unittest
import functools
import threading
import mimetypes
import concurrent.futures
from pprint import pprint
from urllib.parse import urlparse, unquote
from collections import OrderedDict

import aiohttp
import requests
import async_timeout
from lxml import etree
from pyqrcode import QRCode
from requests.utils import cookiejar_from_dict


def set_logger(name, level=logging.INFO):
    formatter = logging.Formatter('[%(levelname)1.1s %(asctime)s '
                                  '%(module)s:%(lineno)d] %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.formatter = formatter
    _logger = logging.getLogger(name)
    _logger.addHandler(stream_handler)
    _logger.setLevel(level)
    return _logger


logger = set_logger('wechat')


class NamedVKDict(object):
    """
    usage:
    >>> country = NamedVKDict({'CHINA': 0, 'AMERICA': 1, 'BRITAIN': 2})
    >>> country.CHINA
    >>> 0
    >>> country[0]
    >>> 'CHINA'
    """
    def __init__(self, value):
        self._attr = value
        self._index = {v: k for k, v in value.items()}

    def __getattr__(self, value):
        if value in self._attr:
            return self._attr[value]
        else:
            raise AttributeError

    def __getitem__(self, value):
        return self._index[value]


def fix_emoji(val):
    """
    _emoji_debugger is for bugs about emoji match caused by wechat
    backstage like :face with tears of joy: will be replaced with
    :cat face with tears of joy:
    """
    def _emoji_debugger(val):
        s = val.replace('<span class="emoji emoji1f450"></span',
                         '<span class="emoji emoji1f450"></span>')

        def __fix_miss_match(m):
            return '<span class="emoji emoji%s"></span>' % ({
                '1f63c': '1f601', '1f639': '1f602', '1f63a': '1f603',
                '1f4ab': '1f616', '1f64d': '1f614', '1f63b': '1f60d',
                '1f63d': '1f618', '1f64e': '1f621', '1f63f': '1f622',
                }.get(m.group(1), m.group(1)))
        return WeChatMeta.RE['emoji'].sub(__fix_miss_match, s)

    def _emoji_formatter(m):
        s = m.group(1)
        if len(s) == 6:
            return ('\\U%s\\U%s'%(s[:2].rjust(8, '0'), s[2:].rjust(8, '0')))\
                .encode('utf8').decode('unicode-escape', 'replace')
        elif len(s) == 10:
            return ('\\U%s\\U%s'%(s[:5].rjust(8, '0'), s[5:].rjust(8, '0')))\
                .encode('utf8').decode('unicode-escape', 'replace')
        else:
            return ('\\U%s'%m.group(1).rjust(8, '0'))\
                .encode('utf8').decode('unicode-escape', 'replace')
    val = _emoji_debugger(val)
    val = WeChatMeta.RE['emoji'].sub(_emoji_formatter, val)
    return val


##############
# Exceptions #
##############

class WeChatError(Exception):
    pass


class LoginFailedError(WeChatError):
    pass


class MultiListenThreadError(WeChatError):
    pass


class MessageDataCorruptionError(WeChatError):
    pass


class WeChatMeta(object):
    APP_ID = 'wx782c26e4c19acffb'  # Got from itChat

    SEND_MESSAGE_URL = '/webwxsendmsg'
    SEND_IMAGE_URL = '/webwxsendmsgimg'
    SEND_VIDEO_URL = '/webwxsendvideomsg'
    SEND_FILE_URL = '/webwxsendappmsg'
    UPDATE_GROUP_URL = '/webwxupdatechatroom'
    CREATE_GROUP_URL = '/webwxcreatechatroom'
    SET_PIN_URL = '/webwxoplog'

    FILE_MESSAGE_TEMPLATE = (
        "<appmsg appid='{}' sdkver=''><title>{}</title><des></des><action>"
        "</action><type>6</type><content></content><url></url><lowurl>"
        "</lowurl><appattach><totallen>{}</totallen><attachid>{}</attachid>"
        "<fileext>{}</fileext></appattach><extinfo></extinfo></appmsg>"
    )

    GROUP_PREFIX = '@@'
    INVITE_BY_MYSELF = '你'
    MP_FLAG = 'gh_'
    LOGIN_URI = 'https://login.weixin.qq.com'
    COOKIE_DOMAIN = '.qq.com'
    TIME_FORMAT = '%a %b %d %Y %H:%M:%S GMT+0800 (CST)'

    URL = {
        'uuid': LOGIN_URI + '/jslogin',
        'push_login': LOGIN_URI + '/cgi-bin/mmwebwx-bin/webwxpushloginurl',
        'login_status': LOGIN_URI + '/cgi-bin/mmwebwx-bin/login',
        'qr_code': LOGIN_URI + '/l/',
        'upload_media': '/webwxuploadmedia',
        'sync_check': '/synccheck',
        'web_sync': '/webwxsync',
        'web_init': '/webwxinit',
        'web_status': '/webwxstatusnotify',
        'get_contacts': '/webwxgetcontact',
        'bget_contacts': '/webwxbatchgetcontact',
        'send_message': '/webwxsendmsg',
        'send_image': '/webwxsendmsgimg',
        'send_video': '/webwxsendvideomsg',
        'send_file': '/webwxsendappmsg',
        'update_group': '/webwxupdatechatroom',
        'create_group': '/webwxcreatechatroom',
        'set_pin': '/webwxoplog',
        'group_avatar': '/webwxgetheadimg',
        'user_avatar': '/webwxgeticon',
    }

    RE = {
        'uuid': re.compile(r'QRLogin\.uuid = "(?P<uuid>\S+)"'),
        'login_status': re.compile(r'window\.code=(?P<status>\d+)'),
        'main_uri': re.compile(r'window.redirect_uri="(?P<main_uri>\S+)"'),
        'uin': re.compile(r'<username>(?P<uin>[^<]*?)<'),
        'sync_check': re.compile(r'synccheck=\{retcode:"(?P<retcode>\d+)",'
                                 r'selector:"(?P<selector>\d+)"\}'),
        'group_msg': re.compile(u'(?P<username>@[0-9a-z]+):<br/>'
                                u'(@(?P<nickname>.*?)\u2005)?'
                                u'(?P<content>.*)'),
        'invite': re.compile(u'("(?P<invite_by>.*?)")?\u9080\u8bf7"'
                             u'(?P<invitee>.*?)"加入了群聊'),
        'remove': re.compile(u'"(?P<nickname>.*?)"移出了群聊'),
        'emoji': re.compile(r'<span class="emoji emoji(.{1,10})"></span>'),
    }


MESSAGE_TYPE = NamedVKDict({
    'TEXT': 1,
    'IMAGE': 3,
    'FILE': 6,
    'CONTACT_CARD': 42,
    'VIDEO': 43,
    'SHARE': 49,
    'INITIALIZE': 51,
    'SYSTEM': 10000,
})


class Contact(object):
    RAW_FIELD = ['UserName', 'NickName', 'MemberList', 'DisplayName']

    def __init__(self, raw_contact, account, is_group=False):
        self.__bool = bool(raw_contact)
        if not self.__bool:
            return

        member_list = raw_contact.get('MemberList', [])

        self.account = account
        self.user_id = raw_contact['UserName']
        self.nickname = fix_emoji(raw_contact['NickName'])
        self.display_name = fix_emoji(raw_contact.get('DisplayName', ''))
        self.is_owner = self._is_owner(member_list)
        self.members = self.process_members(member_list)
        self.is_group = is_group

    @property
    def avatar(self):
        return self.account.get_avatar(self.user_id)

    def process_members(self, members):
        return {m['UserName']: Contact(m, self.account) for m in members}

    def _is_owner(self, members):
        if not members:
            return False
        return members[0]['UserName'] == self.account.username

    @classmethod
    def is_data_corruption(cls, raw_contact):
        if not raw_contact:
            return True
        for field in cls.RAW_FIELD:
            if field not in raw_contact:
                return True
        return True

    def as_dict(self):
        return {
            'user_id': self.user_id,
            'account': {
                'username': self.account.username,
                'nickname': self.account.nickname,
                'uin': self.account.uin,
            },
            'nickname': self.nickname,
            'display_name': self.display_name,
            'avatar_md5': hashlib.md5(self.account.get_avatar(self.user_id))
                          .hexdigest()
        }

    def __bool__(self):
        return self.__bool


class WeChatClient(object):
    HEADERS = {
        'ContentType': 'application/json; charset=UTF-8',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/58.0.3029.110 Safari/537.36',
    }

    CHUNK_SIZE = 1024 * 512  # 512KB

    def __init__(self, credential=None):
        self.login = False
        self._alive = False
        self.uuid = None
        self.login_info = {}
        self.invite_start_count = 40

        self.session = requests.Session()
        self.session.headers = self.HEADERS

        self.friends = {}
        self._groups = {}
        self.mp = {}
        self.uin_username_map = {}

        self.logout_callback = []
        self.message_callback = {}
        self.credential_update_callback = []
        self.group_update_callback = {}

        self.uin = None
        self.username = None
        self.nickname = None
        self.alias = None

        self._listen_thread = None
        self.listening = False

        if credential:
            self._load_credential(credential)

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
    def groups(self):
        return list(self._groups.values())

    def logout(self):
        self._alive = False
        self.login = False
        old_listen_thread = self._listen_thread
        del old_listen_thread
        self._listen_thread = None
        for cb in self.logout_callback:
            cb(self)

    def save_group(self, group):
        if not group:
            return
        self._run_callback(self.group_update_callback, group)
        self._groups[group.user_id] = group

    def update_group(self, group):
        if not group:
            return
        username = group['UserName']
        if group['MemberList'] and isinstance(group['MemberList'], list):
            if group['MemberList'][0]['UserName'] == self.username:
                group['isOwner'] = True

            group['MemberList'] = {
                m['UserName']: m for m in group['MemberList']
            }
        else:
            group['MemberList'] = {}

        self._run_callback(self.group_update_callback, group)

        if username in self._groups:
            self._groups[username].update(group)
        else:
            self._groups[username] = group

    def _push_login(self):
        uin = self.login_info['wxuin']
        resp = self.session.get(WeChatMeta.URL['push_login'],
                                params={'uin': uin})
        result = resp.json()
        if 'uuid' in result and str(result.get('ret')) == '0':
            self.uuid = result['uuid']
            return True
        else:
            return False

    def _batch_get_contact(self, usernames, groups=None):
        url = self.login_info['main_uri'] + WeChatMeta.URL['bget_contacts']
        params = {'type': 'ex', 'r': int(time.time())}

        if not groups:
            request_list = [
                {'UserName': username, 'EncryChatRoomId': ''}
                for username in usernames
            ]
        else:
            assert len(usernames) == len(groups), \
                'Username length not equal to Chatrooms length'
            request_list = [
                {'UserName': username, 'EncryChatRoomId': group_id}
                for username, group_id in zip(usernames, groups)
            ]
        data = {
            'BaseRequest': self.login_info['base_request'],
            'Count': len(usernames),
            'List': request_list,
        }
        resp = self.session.post(url, params=params, json=data)
        return self._decode_content(resp.content)

    def _build_username_req(self, user_ids, group_id):
        if not group_id:
            request_list = [
                {'UserName': user, 'EncryChatRoomId': ''}
                for user in user_ids
            ]
        else:
            request_list = [
                {'UserName': user, 'EncryChatRoomId': group_id}
                for user in user_ids
            ]
        return {
            'url': self.login_info['main_uri'] + WeChatMeta.URL['bget_contacts'],
            'params': {'type': 'ex', 'r': int(time.time())},
            'data': json.dumps({
                'BaseRequest': self.login_info['base_request'],
                'Count': len(user_ids),
                'List': request_list,
            })
        }

    def _get_username_info(self, username, singleton=True):
        if not isinstance(username, (list, set, tuple)):
            username = [username]
        else:
            singleton = False

        def fetch_member_info(members, group_id):
            """fetch 50 contacts info each time"""
            member_list = []
            for i in range(1, len(members) // 50 + 2):
                batch_members = members[(i - 1) * 50: i * 50]
                result = self._batch_get_contact(
                    batch_members, [group_id] * len(batch_members)
                )
                member_list.extend([m for m in result['ContactList']])
            return member_list

        groups = self._batch_get_contact(username)['ContactList']
        for group in groups:
            members = [m['UserName'] for m in group['MemberList']]
            # modify group in-place
            group['MemberList'] = fetch_member_info(members, group['UserName'])
        if not groups:
            return {} if singleton else []
        return groups[0] if singleton else groups

    @staticmethod
    def _decode_content(content):
        return json.loads(content.decode('utf-8', 'replace'))

    ##################
    # login & logout #
    ##################

    def login_by_qrcode(self, timeout=180, thread=False, callback=None):
        def polling():
            start_time = time.time()
            while not self.login:
                if time.time() - start_time > timeout:
                    return self.login
                self.login = self._polling_login()
                time.sleep(0.1)

            self._login_init()
            self._alive = True

            if callback:
                self._run_callback([callback])
            self.listen_message()
            return self.login

        if not thread:
            return polling()

        polling_thread = threading.Thread(target=polling)
        polling_thread.setDaemon(True)
        polling_thread.start()

    def print_cli_qrcode(self):
        self.uuid = self.get_login_uuid()
        qr_code = QRCode(WeChatMeta.URL['qr_code'] + self.uuid)
        qr_code.svg('uca-url.svg', scale=6)
        print(qr_code.terminal(quiet_zone=1))

    @classmethod
    def get_login_uuid(cls):
        resp = requests.get(
            WeChatMeta.URL['uuid'],
            params={'appid': WeChatMeta.APP_ID, 'fun': 'new'}
        )
        result = WeChatMeta.RE['uuid'].search(resp.text)
        assert result, 'Failed get uuid from {}'.format(WeChatMeta.URL['uuid'])
        return result.group('uuid')

    @classmethod
    def generate_qrcode(cls, uuid):
        qr_storage = io.BytesIO()
        qr_code = QRCode(WeChatMeta.URL['qr_code'] + uuid)
        qr_code.svg(qr_storage, scale=10)
        return qr_storage.getvalue()

    def get_qrcode(self):
        self.uuid = self.get_login_uuid()
        return self.generate_qrcode(self.uuid)

    def _polling_login(self):
        if not self.uuid:
            return False
        timestamp = int(time.time())
        params = {
            'uuid': self.uuid,
            'loginicon': True,
            'tip': 0,
            'r': timestamp / 1579,  # Magic number: 1579, from ItChat
            '_': timestamp
        }
        resp = self.session.get(WeChatMeta.URL['login_status'], params=params)
        result = WeChatMeta.RE['login_status'].search(resp.text)
        if not result:
            return False

        status = result.group('status')
        if status != '200':
            return False
        else:
            self._extract_login_credential(resp.text)
            return True

    def _extract_login_credential(self, content):
        result = WeChatMeta.RE['main_uri'].search(content)
        if not result:
            raise LoginFailedError('Failed extract redirect uri '
                                   'after login success')
        redirect_uri = result.group('main_uri')
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
            br = credit['base_request'] = {'DeviceID': credit['deviceid']}
            credit['skey'] = br['Skey'] = resp_xml.xpath('//skey')[0].text
            credit['wxsid'] = br['Sid'] = resp_xml.xpath('//wxsid')[0].text
            credit['wxuin'] = resp_xml.xpath('//wxuin')[0].text
            br['Uin'] = int(credit['wxuin'])
            credit['pass_ticket'] = unquote(
                resp_xml.xpath('//pass_ticket')[0].text
            )
            self.uin = credit['wxuin']
        except TypeError:
            self.login_info = {}
            raise LoginFailedError(
                'Failed extract login credential from login xml'
            )

    def _web_init(self):
        url = self.login_info['main_uri'] + WeChatMeta.URL['web_init']

        resp = self.session.post(
            url, params={'r': int(time.time())},
            json={'BaseRequest': self.login_info['base_request']}
        )

        result = self._decode_content(resp.content)
        credit = self.login_info
        credit['sync_check_key'] = result['SyncKey']
        self.username = fix_emoji(result['User']['UserName'])
        self.nickname = fix_emoji(result['User']['NickName'])
        self.invite_start_count = int(result['InviteStartCount'])
        self.save_credential()

    def _get_initialize_contacts(self):
        url = self.login_info['main_uri'] + WeChatMeta.URL['web_status']
        params = {
            'lang': 'zh_CN',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['base_request'],
            'Code': 3,
            'FromUserName': self.username,
            'ToUserName': self.username,
            'ClientMsgId': int(time.time()),
        }
        resp = self.session.post(url, params=params, json=data)
        return resp.json()['BaseResponse']['Ret'] == 0

    def _get_all_contacts(self):
        url = self.login_info['main_uri'] + WeChatMeta.URL['get_contacts']

        def fetch_fragment(seq=0):
            contacts = []
            params = {
                'r': int(time.time()),
                'seq': seq,
                'skey': self.login_info['skey'],
            }

            resp = self.session.get(url, params=params)
            data = self._decode_content(resp.content)
            contacts.extend(data.get('MemberList', []))
            new_seq = data.get('Seq', 0)
            if new_seq != 0:
                contacts.extend(fetch_fragment(new_seq))
            else:
                return contacts

        all_contacts = fetch_fragment()
        self._process_contacts_change(all_contacts)

    def _login_init(self):
        self._web_init()
        self._get_initialize_contacts()
        self._get_all_contacts()

    def export_credential(self):
        return {
            'cookies': self.session.cookies.get_dict(),
            'login_info': self.login_info,
            'username': self.username,
            'nickname': self.nickname,
            'uin': self.uin,
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

        success, message, contacts = self._fetch_server_change()
        if success:
            self.login = True
            self._alive = True
            self._login_init()
            self.listen_message()
            return True
        else:
            return False

    #################
    # Contacts data #
    #################

    def get_group_by_username(self, username, force_remote=False):
        if force_remote or username not in self._groups:
            group = self._query_entity(username)
            if not group:
                return None
            self.save_group(group)
        return self._groups[username]

    def get_group_by_nickname(self, nickname):
        for group_id, group in self._groups.items():
            if group.nickname == nickname:
                return group

    def get_group_member(self, group_id, user_id):
        group = self.get_group_by_username(group_id)
        if not group:
            return None
        return group.members.get(user_id)

    @classmethod
    def _process_fetch(cls, session, req):
        return cls._decode_content(session.post(**req).content)

    def _query_entity(self, username):
        result = self._query_entities([username])
        return result[0] if result else {}

    def _query_entities(self, user_ids):
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        def package_req(items, group_id=None):
            reqs = []
            for i in range(len(items)//50 + 1):
                seg = items[i*50: (i+1) * 50]
                reqs.append(self._build_username_req(seg, group_id))
            return reqs

        def do_request(reqs, groups=None):
            with concurrent.futures.ProcessPoolExecutor() as executor:
                result = list(executor.map(
                    self._process_fetch, [self.session] * len(reqs), reqs)
                )
            return zip(result, groups) if groups else result

        # FIXME: async request work not meeting expectations
        async def _fetch(req):
            cookies = self.session.cookies.get_dict()
            try:
                with async_timeout.timeout(100):
                    async with aiohttp.ClientSession(
                            loop=loop, cookies=cookies,
                            headers=self.HEADERS) as session:
                        async with session.post(**req) as res:
                            res = await res.text(encoding='utf-8')
                            return json.loads(res)
            except asyncio.TimeoutError as err:
                logger.error('Failed get req: {} response, '
                             'err: {}'.format(req, err))
            except Exception as err:
                logger.error('*** Terrible things happened ***, '
                             'error: {}'.format(err))

        def do_async_request(reqs, groups=None):
            futures = [_fetch(r) for r in reqs]
            result = loop.run_until_complete(asyncio.gather(*futures))
            return zip(result, groups) if groups else result

        resp = do_request(package_req(user_ids))
        entities = [g for r in resp if resp for g in r.get('ContactList') if g]
        entities = {g['UserName']: Contact(g, self, True) for g in entities}
        if not entities:
            logger.error('Aysnc request failed: raw resp: {}'.format(resp))

        req_queue = []
        group_queue = []
        for group_id, group in entities.items():
            members = list(group.members.keys())
            sub_req = package_req(members, group_id)
            req_queue.extend(sub_req)
            group_queue.extend([group_id] * len(sub_req))
            group.members = {}
        if not req_queue:
            return list(entities.values())

        resp = do_request(req_queue, group_queue)
        for member, group_id in resp:
            group = entities[group_id]
            if member:
                for m in member['ContactList']:
                    m = Contact(m, self)
                    group.members[m.user_id] = m
        return list(entities.values())

    def _process_contacts_change(self, contacts):
        for contact in contacts:
            user = contact['UserName']
            if contact.get('KeyWord') == WeChatMeta.MP_FLAG:
                self.mp[user] = contact
            elif contact['UserName'].startswith(WeChatMeta.GROUP_PREFIX):
                if contact['MemberList']:
                    c = Contact(contact, self)
                    self.save_group(c)
                else:
                    self.save_group(self._query_entity(user))
            else:
                self.friends[user] = contact

    def get_avatar(self, user_id):
        params = {
            'username': user_id,
            'seq': int(time.time() * 4.36),   # 4.36: magic number by myself
            'skey': self.login_info['skey'],
        }
        if user_id.startswith(WeChatMeta.GROUP_PREFIX):
            path = WeChatMeta.URL['group_avatar']
        else:
            path = WeChatMeta.URL['user_avatar']
        url = self.login_info['main_uri'] + path
        resp = self.session.get(url, params=params)
        return resp.content

    ##################
    # handle message #
    ##################

    def _process_new_message(self, messages):
        for msg in messages:
            try:
                msg = self._reform_raw_msg(msg)
                if msg:
                    self._run_callback(self.message_callback, msg)
            except Exception:
                logger.exception('Failed process raw message')

    def _handle_private_msg(self, msg):
        # TODO: implement
        pass

    def _handle_group_msg(self, from_user, to_user):
        group = self.get_group_by_username(to_user)
        if not group or from_user not in group.members:
            print('from', from_user, 'to', to_user, 'group', group)
            raise MessageDataCorruptionError

        user = group.members[from_user]
        return {
            'from_user': from_user,
            'from_nickname': user.display_name or user.nickname,
            'to_user': to_user,
            'to_nickname': group.nickname,
        }

    def _handle_initialize_msg(self, msg):
        users = msg['StatusNotifyUserName'].split(',')
        group_ids = [u for u in users
                     if u.startswith(WeChatMeta.GROUP_PREFIX)]
        for group in self._query_entities(group_ids):
            self.save_group(group)

    def _handle_system_msg(self, msg, to_user):
        invite = WeChatMeta.RE['invite'].search(msg['Content'])
        if not invite:
            return {}
        group = self.get_group_by_username(to_user)
        if not group:
            return {}
        new = {
            'invite_by_nickname': invite.group('invite_by'),
            'invitee_nickname': invite.group('invitee'),
            'invite_by': '',
            'invitee': '',
            'member_count': len(group.members),
        }
        if new['invite_by_nickname'] == WeChatMeta.INVITE_BY_MYSELF:

            me = group['MemberList'][self.username]
            new['invite_by_nickname'] = me['DisplayName'] or \
                                        self.nickname
            new['invite_by'] = self.username

        group = self.get_group_by_username(to_user)
        for member_id, member in group['MemberList'].items():
            display_name = member['DisplayName'] or member['NickName']
            if not new['invite_by'] and \
                    display_name == new['invite_by_nickname']:
                new['invite_by'] = member_id
                continue
            if not new['invitee'] and \
                    display_name == new['invitee_nickname']:
                new['invitee'] = member_id
            if new['invite_by'] and new['invitee']:
                break

        return {'new_member': new}

    def _reform_raw_msg(self, raw_msg):
        msg_type = raw_msg.get('MsgType')
        if msg_type == MESSAGE_TYPE.INITIALIZE:
            self._handle_initialize_msg(raw_msg)
            return

        try:
            content_type = MESSAGE_TYPE[msg_type].lower()
        except KeyError:
            content_type = 'other'

        new_msg = {
            'is_at_me': False,
            'message_type': 'private',
            'content': raw_msg['Content'],
            'new_member': None,
            'content_type': content_type,
        }

        to_user, from_user = raw_msg['ToUserName'], raw_msg['FromUserName']
        if from_user.startswith(WeChatMeta.GROUP_PREFIX):
            to_user, from_user = from_user, to_user

        if not to_user.startswith(WeChatMeta.GROUP_PREFIX):
            self._handle_private_msg(raw_msg)
            return None
        else:
            new_msg['message_type'] = 'group'
            if msg_type == MESSAGE_TYPE.TEXT:
                content = raw_msg['Content']
                matched = WeChatMeta.RE['group_msg'].search(content)
                if matched:
                    new_msg['content'] = matched.group('content')
                    from_user = matched.group('username')
                    me = self.get_group_member(to_user, self.username) or {}
                    my_nickname = me.display_name or self.nickname
                    if matched.group('nickname') == my_nickname:
                        new_msg['is_at_me'] = True
            elif msg_type == MESSAGE_TYPE.SYSTEM:
                new_msg.update(self._handle_system_msg(raw_msg, to_user))

            new_msg.update(self._handle_group_msg(from_user, to_user))
        return new_msg

    ############
    # Callback #
    ############

    @classmethod
    def _run_callback(cls, callbacks, *args, **kwargs):
        if isinstance(callbacks, dict):
            callbacks = callbacks.values()
        for cb in callbacks:
            try:
                cb(*args, **kwargs)
            except Exception as err:
                logger.error('Failed run callback {}, args: {}, kwargs: '
                             '{}, error: {}'.format(cb, args, kwargs, err))

    def save_credential(self):
        for cb in self.credential_update_callback:
            cb(self.uin, self.export_credential())

    ################
    # Send message #
    ################

    def _upload_media_by_url(self, url, media_type, to_user):
        resp = requests.get(url)
        file_size = len(resp.content)
        file_md5 = hashlib.md5(resp.content).hexdigest()
        file_type = mimetypes.guess_type(url)[0] or \
                    'application/octet-stream'

        upload_media_request = json.dumps(OrderedDict([
            ('UploadType', 2),
            ('BaseRequest', self.login_info['base_request']),
            ('ClientMediaId', int(time.time() * 1e4)),
            ('TotalLen', file_size),
            ('StartPos', 0),
            ('DataLen', file_size),
            ('MediaType', 4),
            ('FromUserName', self.username),
            ('ToUserName', to_user),
            ('FileMd5', file_md5),
        ]), separators=(',', ':'))

        result = None
        params = {'f': 'json'}
        chunks = (file_size - 1) // self.CHUNK_SIZE + 1
        last_chunk = 0
        for chunk in range(1, chunks+1):
            last_modified = time.strftime(WeChatMeta.TIME_FORMAT)
            data_ticket = self.session.cookies.get(
                'webwx_data_ticket', domain=WeChatMeta.COOKIE_DOMAIN
            )
            chunk_data = resp.content[self.CHUNK_SIZE * last_chunk:
                                      self.CHUNK_SIZE * chunk]
            files = OrderedDict([
                ('id', (None, 'WU_FILE_0')),
                ('name', (None, os.path.basename(url))),
                ('type', (None, file_type)),
                ('lastModifiedDate', (None, last_modified)),
                ('size', (None, str(file_size))),
                ('mediatype', (None, media_type)),
                ('uploadmediarequest', (None, upload_media_request)),
                ('webwx_data_ticket', (None, data_ticket)),
                ('pass_ticket', (None, self.login_info['pass_ticket'])),
                ('filename', (os.path.basename(url), chunk_data, file_type))
            ])
            last_chunk = chunk
            if chunks != 1:
                files['chunk'] = (None, str(chunk))
                files['chunks'] = (None, str(chunks))

            upload_url = self.login_info['upload_uri'] + \
                         WeChatMeta.URL['upload_media']
            resp = self.session.post(upload_url, params=params, files=files)
            try:
                result = resp.json()['MediaId']
            except (TypeError, ValueError):
                result = None
        return result

    def _send(self, to_user, msg_type, url, content=None, media_id=None):
        params = {
            'fun': 'async', 'f': 'json',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        timestamp = int(time.time() * 1e4)
        current_user = self.username
        data = {
            'BaseRequest': self.login_info['base_request'],
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

    def send_message(self, to_user, msg_type, payload=None, media_id=None):
        to_user = self._handle_group_id(to_user) or to_user

        assert payload or media_id, \
            'Requires at least one argument of payload and media_id'
        try:
            msg_type = getattr(MESSAGE_TYPE, msg_type.upper())
        except KeyError:
            raise ValueError('Unsupported message type: {}'.format(msg_type))

        if msg_type == MESSAGE_TYPE.TEXT:
            url = self.login_info['main_uri'] + WeChatMeta.SEND_MESSAGE_URL
            result = self._send(to_user, msg_type, url, content=payload)
            return result['BaseResponse']['Ret'] == 0

        if msg_type == MESSAGE_TYPE.IMAGE:
            media_type = 'pic'
            path = WeChatMeta.SEND_IMAGE_URL
        elif msg_type == MESSAGE_TYPE.VIDEO:
            media_type = 'video'
            path = WeChatMeta.SEND_VIDEO_URL
        elif msg_type == MESSAGE_TYPE.FILE:
            media_type = 'doc'
            path = WeChatMeta.SEND_FILE_URL
        else:
            raise ValueError('Unsupported message type: {}'.format(msg_type))

        media_id = self._upload_media_by_url(payload, media_type, to_user)
        assert media_id, 'Failed upload file: {}'.format(payload)

        url = self.login_info['main_uri'] + path

        if msg_type == MESSAGE_TYPE.FILE:
            content = self._build_file_message_content(payload, media_id)
            media_id = None
        else:
            content = None

        result = self._send(to_user, msg_type, url,
                            media_id=media_id, content=content)
        return result['BaseResponse']['Ret'] == 0

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
            ('BaseRequest', self.login_info['base_request']),
            ('ClientMediaId', int(time.time() * 1e4)),
            ('TotalLen', file_size),
            ('StartPos', 0),
            ('DataLen', file_size),
            ('MediaType', 4),
            ('FromUserName', self.username),
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
                      WeChatMeta.URL['upload_media']
                resp = self.session.post(url, params=params, files=files)
                try:
                    result = resp.json()['MediaId']
                except (TypeError, ValueError):
                    result = None
        return result

    def _load_credential(self, credential):
        self.login_info = credential['login_info']
        self.session.cookies = cookiejar_from_dict(credential['cookies'])
        self.uin = self.login_info['wxuin']
        self.nickname = credential['nickname']
        self.username = credential['username']

    def register_credential_update_callback(self, callback, *args, **kwargs):
        self.credential_update_callback.append(
            functools.partial(callback, *args, **kwargs))

    def create_group(self, member_list, name=''):
        """
        :param member_list: member username list
        :param name: group name
        :return: group info dict
        """
        url = self.login_info['main_uri'] + WeChatMeta.CREATE_GROUP_URL
        params = {
            'pass_ticket': self.login_info['pass_ticket'],
            'r': int(time.time()),
        }
        data = {
            'BaseRequest': self.login_info['base_request'],
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
            self._get_initialize_contacts()
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
            'BaseRequest': self.login_info['base_request'],
        }
        resp = self.session.post(url, params=params, json=data)
        return resp.json()['BaseResponse']['Ret'] == 0

    def get_groups(self, uins=None, usernames=None, nicknames=None):
        if not self.groups:
            username_uin_map = {v: k for k, v in self.uin_username_map.items()}
            usernames = list(self.uin_username_map.values())
            usernames = [u for u in usernames if u and u.startswith('@@')]
            groups = self._query_entity(usernames)
            for group in groups:
                username = group['UserName']
                group['Uin'] = username_uin_map.get(username, 0)
                self.update_group(group)

        result = []
        if uins:
            usernames = [self.uin_username_map.get(uin) for uin in uins]

        if usernames:
            for username in usernames:
                result.append(self._groups.get(username))
                return result

        if nicknames:
            for nickname in nicknames:
                for group in self.groups:
                    if group['NickName'] == nickname:
                        result.append(group)
                        break
            return result

        return self.groups

    def _handle_group_id(self, group_id):
        if group_id.startswith('@@'):
            return group_id

        username = self.uin_username_map.get(group_id)
        if username:
            return username

        for group in self.groups:
            if group['NickName'] == group_id:
                return group['UserName']

    def delete_group_member(self, group_id, member_list):
        username = self._handle_group_id(group_id)
        if not username:
            logger.error('Failed delete members, invalid uin: {}'.format(
                group_id))
            return False

        url = self.login_info['main_uri'] + WeChatMeta.UPDATE_GROUP_URL
        params = {
            'fun': 'delmember',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['base_request'],
            'ChatRoomName': username,
            'DelMemberList': ','.join(member_list),
        }
        resp = self.session.post(url, params=params, json=data)
        self.save_group(self._query_entity(username))
        return resp.json()['BaseResponse']['Ret'] == 0

    def add_group_number(self, group_id, member_list):
        username = self._handle_group_id(group_id)
        if not username or username not in self._groups:
            logger.error('Failed delete group members,'
                         ' invalid group_id: {}'.format(group_id))
            return False

        url = self.login_info['main_uri'] + WeChatMeta.UPDATE_GROUP_URL
        params = {'pass_ticket': self.login_info['pass_ticket']}
        data = {
            'BaseRequest': self.login_info['base_request'],
            'ChatRoomName': username,
        }

        members = ','.join(member_list)
        group = self._groups.get(username)

        if len(group['MemberList']) > self.invite_start_count:
            params['fun'] = 'invitemember'
            data['InviteMemberList'] = members
        else:
            params['fun'] = 'addmember'
            data['AddMemberList'] = members

        resp = self.session.post(url, params=params, json=data)
        self.save_group(self._query_entity(username))
        return resp.json()['BaseResponse']['Ret'] == 0

    def update_group_nickname(self, group_id, nickname):
        username = self._handle_group_id(group_id)
        if not username:
            logger.error('Failed update group nickname,'
                         ' invalid group_id: {}'.format(group_id))
            return False

        url = self.login_info['main_uri'] + WeChatMeta.UPDATE_GROUP_URL
        params = {
            'fun': 'modtopic',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['base_request'],
            'ChatRoomName': username,
            'NewTopic': nickname,
        }
        resp = self.session.post(
            url, params=params,
            data=json.dumps(data, ensure_ascii=False).encode('utf8', 'ignore'),
        )
        self.save_group(self._query_entity(username))
        return resp.json()['BaseResponse']['Ret'] == 0

    #################
    # Group manager #
    #################

    def del_group_member(self, group_id, member_ids):
        url = self.login_info['main_uri'] + WeChatMeta.URL['update_group']
        params = {
            'fun': 'delmember',
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['base_request'],
            'ChatRoomName': group_id,
            'DelMemberList': ','.join(member_ids),
        }
        resp = self.session.post(url, params=params, json=data)
        self.save_group(self._query_entity(group_id))
        return resp.json()['BaseResponse']['Ret'] == 0

    ##################
    # Listen message #
    ##################

    def listen_message(self, retries=3, thread=True):
        def fetch_event():
            _, messages, contacts = self._fetch_server_change()
            self._process_new_message(messages)
            self._process_contacts_change(contacts)

        def receive_loop(_retries):
            fetch_event()
            while self._alive:
                try:
                    check_data = self._sync_check()
                    if check_data > 0:
                        fetch_event()
                    elif check_data == 0:
                        _retries = retries
                    elif _retries > 0:
                        _retries -= 1
                    else:
                        return self.logout()
                    time.sleep(1)
                except (requests.ConnectionError, requests.Timeout,
                        requests.HTTPError) as err:
                    logger.error('Error in listen thread: {}'.format(err))

        if self.listening:
            return
        self.listening = True

        if not thread:
            return receive_loop(retries)

        if self._listen_thread:
            raise MultiListenThreadError
        self.listen_thread = threading.Thread(target=receive_loop,
                                              args=(retries,))
        self.listen_thread.setDaemon(True)
        self.listen_thread.start()

    def _fetch_server_change(self):
        url = self.login_info['main_uri'] + WeChatMeta.URL['web_sync']
        params = {
            'sid': self.login_info['wxsid'],
            'skey': self.login_info['skey'],
            'pass_ticket': self.login_info['pass_ticket'],
        }
        data = {
            'BaseRequest': self.login_info['base_request'],
            'SyncKey': self.login_info['sync_check_key'],
            'rr': ~int(time.time()),
        }
        resp = self.session.post(url, params=params, json=data)
        result = self._decode_content(resp.content)
        self.login_info['sync_check_key'] = result['SyncCheckKey']
        self.login_info['synckey'] = '|'.join([
            '{}_{}'.format(item['Key'], item['Val'])
            for item in result['SyncCheckKey']['List']
        ])
        self.save_credential()
        success = result['BaseResponse']['Ret'] == 0
        return success, result['AddMsgList'], result['ModContactList']

    def _sync_check(self):
        url = self.login_info['web_sync_uri'] + WeChatMeta.URL['sync_check']
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
        resp = self.session.get(url, params=params)
        matched = WeChatMeta.RE['sync_check'].search(resp.text)
        if not matched or matched.group('retcode') != '0':
            logger.debug('unexpected sync check result')
            return -1
        else:
            return int(matched.group('selector'))


class WeChatUnitTest(unittest.TestCase):
    def test_get_login_uuid(self):
        uuid = WeChatClient.get_login_uuid()
        self.assertIsInstance(uuid, str)


class WeChatDemo(object):
    def __init__(self):
        self.client = WeChatClient()

    @staticmethod
    def msg_callback(msg):
        pprint(msg)

    def run(self):
        client = self.client
        client.message_callback = [self.msg_callback]
        client.print_cli_qrcode()
        client.login_by_qrcode(timeout=120)
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
        client.listen_message(thread=False)
        while True:
            logger.info('Waiting for event...')
            time.sleep(30)


if __name__ == '__main__':
    WeChatDemo().run()
