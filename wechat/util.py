# -*- coding: utf-8 -*-

import logging


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


logger = set_logger('wechat')


class WeChatError(Exception):
    pass


class LoginFailedError(WeChatError):
    pass
