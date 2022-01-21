#!/usr/bin/env python

from distutils.core import setup

setup(name='dhslave',
    version='0.1',
    description='Tools to emulate large number of random DHCP clients',
    author='Sergey Khalavchuk',
    author_email='skhalavchuk@intrasystems.ua',
    url='https://github.com/megaexception/dhslave',
    packages=['dhslave'],
    entry_points={
        'console_scripts': [
            'dhslave=dhslave:main',
        ],
    },
    install_requires=['scapy>=2.4'],
)
