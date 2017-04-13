# -*- coding: utf-8 -*-

import io
import json
import time
import random
import multiprocessing as mp
from urllib.parse import urlparse

import requests
from lxml import etree
from pyqrcode import QRCode


from wechat.util import WeChatError, LoginFailedError, logger
from wechat.meta import WeChatMeta


class Account(object):
    def __init__(self):
        self.uin = None
        self.nickname = None
        self.username = None
        self.alias = None


class APIClient(object):
    def __init__(self, account):
        self.account = account
        self.session = requests.Session()
        self.login_info = {}
        self.urls = {}

    @staticmethod
    def _process_response(resp, deserialize=False, regex=None):
        if deserialize:
            try:
                return resp.json()
            except:
                print('error happened')
                return json.loads(resp.text.decode('utf-8', 'replace'))
        elif regex:
            matched = regex.search(resp.text)
            return matched.groupdict() if matched else {}
        else:
            return resp.text

    def _extract_login_info(self, resp):
        result = self._process_response(resp, regex=WeChatMeta.RE['main_uri'])
        assert result.get('main_uri'), 'Failed extract main_uri'

        main_uri = result['main_uri']
        parsed_uri = urlparse(main_uri[:main_uri.rfind('/')])
        essentials = (parsed_uri.scheme, parsed_uri.netloc, parsed_uri.path)

        self.urls['main_uri'] = '{}://{}{}'.format(*essentials)
        self.urls['upload_uri'] = '{}://file.{}{}'.format(*essentials)
        self.urls['sync_check_uri'] = '{}://webpush.{}{}'.format(*essentials)

        # request main_uri
        content = self.request(main_uri, allow_redirects=False)
        resp_xml = etree.fromstring(content)

        credit = self.login_info
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
            raise LoginFailedError(
                'Failed extract login credential from login xml'
            )

        # request web init uri
        web_init_url = self.urls['main_uri'] + WeChatMeta.URL['web_init']
        result = self.request(
            web_init_url, deserialize=True, params={'r': int(time.time())},
            method='POST', json={'BaseRequest': credit['BaseRequest']}
        )
        try:
            credit['InviteStartCount'] = int(result['InviteStartCount'])
            credit['SyncKey'] = result['SyncKey']
            self.account.username = result['User']['UserName']
            self.account.nickname = result['User']['NickName']
        except KeyError:
            raise LoginFailedError('Failed in processing web init')

    def request(self, url, method='GET', exception=False, deserialize=False,
                regex=None, raw_resp=False, **kwargs):
        try:
            fetch = getattr(self.session, method.lower())
        except AttributeError:
            raise WeChatError('Invalid request method: {}'.format(method))

        try:
            resp = fetch(url, **kwargs)
            if raw_resp:
                return resp
            else:
                return self._process_response(resp, deserialize, regex)
        except (ConnectionError, TypeError, ValueError) as err:
            if exception:
                raise
            else:
                logger.warning('Failed request {}, error: {}'.format(url, err))
                return None

    def get_uuid(self):
        url = WeChatMeta.LOGIN_URI + WeChatMeta.URL['uuid']
        result = self.request(
            url, exception=True, regex=WeChatMeta.RE['uuid'],
            params={'appid': WeChatMeta.APP_ID, 'fun': 'new'}
        )
        return result.get('uuid')

    @staticmethod
    def get_qr_code(uuid, console=True):
        login_url = WeChatMeta.LOGIN_URI + WeChatMeta.URL['qr_code'] + uuid
        qr_code = QRCode(login_url)
        if console:
            print(qr_code.terminal(quiet_zone=1))
        else:
            qr_storage = io.BytesIO()
            qr_code.svg(qr_storage, scale=10)
            return qr_storage.getvalue()

    def is_login_finished(self, uuid):
        url = WeChatMeta.LOGIN_URI + WeChatMeta.URL['login_status']
        timestamp = int(time.time())
        resp = self.request(url, raw_resp=True, params={
            'uuid': uuid,
            'loginicon': True,
            'tip': 0,
            'r': timestamp / 1579,
            '_': timestamp
        })

        result = self._process_response(
            resp, regex=WeChatMeta.RE['login_status']
        )

        if not result.get('status') == '200':
            return False
        else:
            self._extract_login_info(resp)
            return True

    def sync_check(self):
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
        url = self.urls['sync_check_uri'] + WeChatMeta.URL['sync_check']
        result = self.request(url, params=params,
                              regex=WeChatMeta.RE['sync_check'])
        if not result.get('retcode') != 0:
            logger.warning('Unexpected sync check result, '
                           'maybe connection was broke.')
            return None
        else:
            return result.get('selector')

    def fetch_server_change(self):
        url = self.urls['main_uri'] + WeChatMeta.URL['web_sync']
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
        result = self.request(url, method='POST', params=params,
                              json=data, deserialize=True)
        self.login_info['SyncKey'] = result['SyncCheckKey']
        self.login_info['synckey'] = '|'.join([
            '{}_{}'.format(item['Key'], item['Val'])
            for item in result['SyncCheckKey']['List']
        ])
        print(result)
        return result


class WeChat(object):
    def __init__(self):
        self.alive = False
        self.logged_in = False

        self.account = Account()
        self.client = APIClient(self.account)
        self.listener = Listener(self.client)

    def login(self, timeout=180):
        client = self.client

        uuid = client.get_uuid()
        client.get_qr_code(uuid)

        begin = time.time()
        while not self.logged_in and time.time() - begin < timeout:
            self.logged_in = client.is_login_finished(uuid)
        if self.logged_in:
            self.listener.listen()
        return self.logged_in

    def logout(self):
        pass

    def send_message(self):
        pass

    @classmethod
    def load(cls):
        return cls()


class Listener(object):
    def __init__(self, client):
        self.client = client

    def polling(self):
        while True:
            print(self.client.sync_check())
            time.sleep(1)
            self.client.fetch_server_change()

    def listen(self):
        self.client.fetch_server_change()
        p = mp.Process(target=self.polling)
        p.daemon = True
        p.start()
