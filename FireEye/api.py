#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import hashlib
import hmac
import email
from datetime import datetime, date, timedelta

class FireEyeApi():

    def __init__(self, config):
        
        """
        Python API for FireEye
        :param config: FireEye configuration from config.py
        :type config: dict
        """

        self.url = config['url']
        self.public_key = config['fe_public_key']
        self.private_key = config['fe_private_key']
        self.proxies = config['proxies']
        self.accept_version = '2.5'

    def exec_query(self, endpoint):
        time_stamp = email.utils.formatdate(localtime=True)
        accept_header = 'application/json'
        new_data = endpoint + self.accept_version + accept_header + time_stamp

        key = bytearray()
        key.extend(map(ord, self.private_key))
        hashed = hmac.new(key, new_data.encode('utf-8'), hashlib.sha256)

        headers = {
            'Accept': accept_header,
            'Accept-Version': self.accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }
        r = requests.get(self.url + endpoint, headers=headers, proxies=self.proxies)

        if r.status_code == 200:
            return r.status_code, r.json()
        else:
            return r.status_code, r.text
        
    def response(self, status, content):
        
        """
        :param status: str = success/failure
        :type status: string
        :paran content: data to return
        :type content: dict
        :return: 
        :rtype: dict

        """
        
        return {'status':status, 'data': content}

    def get_incident(self, id):
        
        """
        Fetch FireEye incident
        :param id: incident id
        :return: response 
        :rtype: requests.get
        
        """
        req = '/report/%s' % id
        status_code, data = self.exec_query(req)
        if status_code == 200:
            return self.response("success", data)
        else:
            return self.response("failure", data)

    def find_incidents(self, since):
        
        """
        Fetch FireEye incidents since last `since` minutes
        :type since: int
        :rtype: request.post
        """

        now = int((datetime.now() - timedelta(minutes=since)).timestamp())

        req = '/report/index?since=%d' % now
        status_code, data = self.exec_query(req)
        if status_code == 200:
            return self.response("success", data)
        else:
            return self.response("failure", data)

