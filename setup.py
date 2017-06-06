# -*- coding: utf-8 -*-

from distutils.core import setup


setup(
    name='barbossa',
    version='0.1.0',
    description='WeChat client implement in Python3',
    author='Leo Howell',
    author_email='leohowell.com@gmail.com',
    url='https://leohowell.github.io/barbossa/',
    packages=['wechat'],
    install_requires=[
        'requests',
        'aiohttp',
        'async_timeout',
        'lxml',
        'pyqrcode',
    ],
    extras_require={
        'demo': ['bottle'],
    }
)

