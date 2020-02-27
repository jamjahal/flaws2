#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import os
import logging

log = logging.getLogger('detect')
log.setLevel(os.environ.get('DETECT_LOG_LEVEL', 'DEBUG'))

