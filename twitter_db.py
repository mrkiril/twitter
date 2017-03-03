#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import os.path
import logging
import logging.config
import configparser
import sqlite3
import datetime
import string
import hashlib
import random
import urllib.parse 
import time


class DataBese(object):

    """ Main class of this server.
        It contain serve_forever methods.
        Which can take request to the socket and give
        an opportunity to send some response to it
        
    """

    def __init__(self, setting_file_path):
        self.logger = logging.getLogger(__name__)
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        self.setting_file_path = setting_file_path
        self.conn, self.c = self.setting_connect()
        self.entry_data_to_sql()
        self.entry_auth_to_sql()

    def setting_connect(self):
        config = configparser.ConfigParser()
        config.read(self.setting_file_path)
        if "database" in config:
            conf = config['database']
            if 'DB' in conf:                
                conn = sqlite3.connect(conf["DB"])
                c = conn.cursor()
                self.logger.info("Data base setting is ok")
                return(conn, c)

            else:
                self.logger.error("Setting file is broken. Can't find DB options in setting file.")
                self.logger.error(str(self.setting_file_path))
                raise AttributeError("There is no DB options in file")
        else:
            self.logger.info("There is no database options in setting file")
            self.logger.error(str(self.setting_file_path))
            raise AttributeError("There is no 'database' options in setting file")

    def entry_data_to_sql(self):
        self.c.execute(
            'CREATE TABLE IF NOT EXISTS datatable(datestamp TEXT, message TEXT, user_id TEXT)')
        self.conn.commit()

    def add_data_to_sql(self, user_id, message):
        date = str(datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        self.c.execute("INSERT INTO datatable (datestamp, message, user_id) VALUES (?, ?, ?)",
                       (date, message, user_id))
        self.conn.commit()

    def read_data_from_sql(self, user_id):        
        self.c.execute(
            'SELECT datestamp, message, ROWID FROM datatable WHERE user_id == "' + user_id+'"')
        arr = []
        for row in self.c.fetchall():
            arr.append(row)
        return arr

    def update_data_to_sql(self, user_id, message):
        date = str(datetime.datetime.fromtimestamp(
             time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        self.c.execute('UPDATE datatable SET message = "' + str(message) +
                       '"" datestamp = "' + str(date) +
                       '"" WHERE user_id == "' + str(user_id)+'"')
        self.conn.commit()

    def delete_data_from_sql(self, user_id, row_id):
        self.c.execute('DELETE FROM datatable WHERE user_id == "' + str(user_id) +
                       '" AND ROWID == ' + str(row_id))
        self.conn.commit()

    def entry_auth_to_sql(self):
        self.c.execute(
            'CREATE TABLE IF NOT EXISTS usertable(user TEXT, password TEXT, cookiessum TEXT)')
        self.conn.commit()

    def add_auth_to_sql(self, user, password):
        print("ADD USER >> ", user)
        # date = str(datetime.datetime.fromtimestamp(unix).strftime('%Y-%m-%d %H:%M:%S'))
        a = string.ascii_lowercase + string.digits
        tocken = ''.join([random.choice(a) for i in range(8)])
        coockies = user + password + tocken
        m = hashlib.md5()
        m.update(coockies.encode())
        cookiessum = m.hexdigest()
        self.c.execute("INSERT INTO usertable (user, password, cookiessum) VALUES (?, ?, ?)",
                       (user, password, cookiessum))
        self.conn.commit()
        return cookiessum

    def read_auth_from_sql(self):
        self.c.execute('SELECT cookiessum, user FROM usertable')
        arr = []
        for row in self.c.fetchall():
            arr.append(row)
        return arr

    def is_user_and_pass_in_base(self, user, password):
        self.c.execute(
            'SELECT cookiessum, user FROM usertable '
            'WHERE user == "'+user+'" AND password == "'+password+'"')  
        tup =  self.c.fetchall()
        if not tup:
            return None
        else:
            return tup[0]

    def is_user_in_base(self, user):
        self.c.execute(
            'SELECT cookiessum, user FROM usertable WHERE user == "'+user+'"')  
        tup =  self.c.fetchall()
        if not tup:
            return None
        else:
            return tup[0]


    def is_auth_by_summ(self, cookiessum):
        self.c.execute(
            'SELECT user FROM usertable '
            'WHERE cookiessum == "'+cookiessum+'"')  
        tup =  self.c.fetchall()        
        if not tup:
            return None
        else:
            return tup[0][0]































