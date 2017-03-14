#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
sys.path.append('../')
import os.path
import re
import socket
import unittest
import subprocess
import multiprocessing
import signal
import configparser
import logging
import logging.config
from time import sleep
from httpclient import HttpClient
from twitter_db import DataBese


class Test_serv(unittest.TestCase):

    def setUp(self):
        logging.config.fileConfig(
            os.path.join(os.getcwd(), "logging.conf"))
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        my_headers = [('User-Agent', 'Mozilla/4.0'), ('X-From', 'UA')]
        my_user_pass = ('kiril', 'supersecret')

        self.client = HttpClient(
            connect_timeout=5,         # socket timeout on connect
            transfer_timeout=3,        # socket timeout on send/recv
            max_redirects=10,
            set_referer=True,
            keep_alive=3,               # Keep-alive socket up to N requests
            headers=my_headers,         # send custom headers
            http_version="1.1",         # use custom http/version
            auth=my_user_pass,          # http auth
            retry=5,
            retry_delay=5)             # wait betweet tries

        #
        # Enter the path to the cookies file in setting file
        #
        dictionary = self.client.configure_from_file(
            os.path.join(self.file_path, "http_client_setting.ini"))
        self.client.logger = logging.getLogger("httpclient_test")
        os.chdir("../")
        self.children = multiprocessing.Value('i', 0)

        self.p = multiprocessing.Process(target=self.process,
                                         args=(self.children, ),
                                         daemon=False)
        self.p.start()
        self.pid = self.p.pid
        print("slave >> " + str(self.pid))
        print("head  >> " + str(os.getpid()))
        print("child >> " + str(self.children.value))
        self.config = configparser.ConfigParser()
        self.config.read(os.path.join(self.file_path,
                                      "..", "setting", "setting.ini"))
        print(os.path.join(self.file_path, "..", "setting", "setting.ini"))
        self.ip = self.config['ip_port_setting']["ip"]
        self.port = self.config['ip_port_setting']["port"]
        self.domen = self.ip + ":" + self.port
        self.data_base = DataBese(
            os.path.join(self.file_path, "..", "setting", "setting.ini"))

    def process(self, child_pid):
        children = subprocess.Popen(["python3", "twitter.py"], shell=False)
        child_pid.value = children.pid
        print("OLOLO >> ", child_pid.value)

    def tearDown(self):
        sleep(1)
        print("slave >> " + str(self.pid))
        print("head  >> " + str(os.getpid()))
        print("child >> " + str(self.children.value))

        os.kill(self.children.value, signal.SIGINT)
        print("IS_ALIVE >> ", self.p.is_alive())
        self.p.terminate()

        try:
            os.kill(self.children.value, signal.SIGINT)
        except Exception as e:
            print("try to kill child", self.children.value, " but Exception")
            print(e.args)
        try:
            os.kill(self.pid, signal.SIGINT)
        except Exception as e:
            print("try to kill ", self.pid, " but Exception")
            print(e.args)
        print("Delete database ", self.config['database']["DB"])
        print(os.getcwd())
        os.remove(self.config['database']["DB"])

    def test_page(self):
        sleep(1)
        # Register new user
        # And check cookies
        res = self.client.post('http://' + self.domen + '/auth',
                               data={'register_email': 'test_ser@ukr.net',
                                     'password': 'password'})
        user_list = list(dict(self.data_base.read_auth_from_sql()).values())
        self.assertIn('test_ser@ukr.net', user_list)
        self.assertIn("." + self.domen, res.cook_dick)

        # Push new posr to twitter
        #
        res = self.client.post('http://' + self.domen + '/',
                               data={'type_post': 'post_post',
                                     'text': 'Some new post 0'})
        res = self.client.post('http://' + self.domen + '/',
                               data={'type_post': 'post_post',
                                     'text': 'Some new post 1'})
        post_data_list = [
            el[1] for el in self.data_base.read_data_from_sql(
                'test_ser@ukr.net')]
        self.assertIn('Some new post 1', post_data_list)
        self.assertIn('Some new post 0', post_data_list)

        # Try push POST with WRONG cookie
        # New post not in database
        res = self.client.post('http://' + self.domen + '/',
                               cookie={
                                   "twit": "ce538b70a7c30f98ab056cd2dc1151b9"},
                               data={'type_post': 'post_post',
                                     'text': 'BLA BLA BLA'})
        post_data_list = [
            el[1] for el in self.data_base.read_data_from_sql(
                'test_ser@ukr.net')]
        self.assertNotIn('BLA BLA BLA', post_data_list)

        # delete_post
        #
        res = self.client.post('http://' + self.domen + '/',
                               data={'type_post': 'delete_post',
                                     'elem': '1'})
        post_data_list = [
            el[1] for el in self.data_base.read_data_from_sql(
                'test_ser@ukr.net')]
        self.assertNotIn('Some new post 0', post_data_list)

        # Test filter data
        #
        #
        self.fiter_test_data("<script>alert('test');</script>")
        self.fiter_test_data("<h1>LALKA</h1")
        self.fiter_test_data("<script>alert('INVALID USER &');</script>")
        self.fiter_test_data("<h2>'</h2>")
        self.fiter_test_data('''<h3>'"&<></h3>''')

        # Exit
        #
        res = self.client.post('http://' + self.domen + '/',
                               data={'type_post': 'exit'})
        self.assertNotIn("." + self.domen, res.cook_dick)
        post_data_list = [
            el[1] for el in self.data_base.read_data_from_sql(
                'test_ser@ukr.net')]
        self.assertNotIn('Some new post 0', post_data_list)

        # Enter with erong e-mail and pass
        # Message which say that e-mail or pass is Incorect
        #
        res = self.client.post('http://' + self.domen + '/auth',
                               data={'enter_email': 'test_ser@ukr.net',
                                     'password': 'wrong_password'})
        self.assertIn(
            b"There is incorrect e-mail or password. Try again", res.body)

        # Try register user with same e-mail
        #
        #
        res = self.client.post('http://' + self.domen + '/auth',
                               data={'register_email': 'test_ser@ukr.net',
                                     'password': 'new_password'})
        user_list = list(dict(self.data_base.read_auth_from_sql()).values())
        self.assertIn(b'There is user with this e-mail. Try another', res.body)

    def fiter_test_data(self, test_str):
        print(test_str)
        res = self.client.post('http://' + self.domen + '/',
                               data={'type_post': 'post_post',
                                     'text': test_str})

        db_elem = self.data_base.read_data_from_sql('test_ser@ukr.net')
        post_data_list = [el[1] for el in db_elem]
        for elem in post_data_list:
            print(elem)
            for symbols in ["<", ">", "'", '"']:
                self.assertNotIn(symbols, elem)


if __name__ == '__main__':
    unittest.main()
