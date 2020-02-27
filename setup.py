#!/usr/bin/env python
# coding: utf-8

# In[4]:


import re
import ast
import os.path
import sys
from setuptools import setup, find_packages


# In[5]:


_version_re=re.compile(r'__version__\s+=\s+(.*)')
with open('flaws2/__about__.py', 'rb') as f:
    DETECT_VERSION = str(ast.literal_eval(_version_re.search(
        f.read().decode('utf-8')).group(1)))

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__)))


# In[ ]:


# addint eh src/ directory to the sys.path to be able to import ourselves

sys.path.insert(0, ROOT)

install_requirements = [
    'boto3>=1.12.6'
]

setup(
    name='flaws2',
    version=DETECT_VERSION,
    long_description='Tool to identify potentially compromised AWS credentials',
    packages=find_packages(),
    install_requires=install_requirements,
    entry_points= {
        'console_scripts': [
            'flaws2 = flaws3.cli:cli',
        ]
    })

