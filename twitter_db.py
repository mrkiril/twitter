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
                mes = "Setting file is broken."
                mes += " Can't find DB options in setting file."
                self.logger.error(mes)
                self.logger.error(str(self.setting_file_path))
                raise AttributeError("There is no DB options in file")
        else:
            self.logger.info("There is no database options in setting file")
            self.logger.error(str(self.setting_file_path))
            raise AttributeError(
                "There is no 'database' options in setting file")

    def entry_data_to_sql(self):
        q = 'CREATE TABLE IF NOT EXISTS datatable'
        q += '(datestamp TEXT, message TEXT, user_id TEXT)'
        self.c.execute(q)
        self.conn.commit()

    def add_data_to_sql(self, user_id, message):
        date = str(datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        q = "INSERT INTO datatable (datestamp, message, user_id)"
        q += " VALUES (?, ?, ?)"
        self.c.execute(q, (date, message, user_id))
        self.conn.commit()

    def read_data_from_sql(self, user_id):
        q = 'SELECT datestamp, message, ROWID '
        q += 'FROM datatable WHERE user_id == ?'
        self.c.execute(q, (user_id, ))
        arr = []
        for row in self.c.fetchall():
            arr.append(row)
        return arr

    def update_data_to_sql(self, user_id, message):
        date = str(datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        q = 'UPDATE datatable SET message = ? datestamp = ? WHERE user_id == ?'
        self.c.execute(q, (str(message), str(date), str(user_id)))
        self.conn.commit()

    def delete_data_from_sql(self, user_id, row_id):
        q = 'DELETE FROM datatable WHERE user_id == ? AND ROWID == ?'
        self.c.execute(q, (user_id, row_id))
        self.conn.commit()

    def entry_auth_to_sql(self):
        q = 'CREATE TABLE IF NOT EXISTS usertable'
        q += '(user TEXT, password TEXT, cookiessum TEXT)'
        self.c.execute(q)
        self.conn.commit()

    def add_auth_to_sql(self, user, password):
        a = string.ascii_lowercase + string.digits
        tocken = ''.join([random.choice(a) for i in range(8)])
        coockies = user + password + tocken
        m = hashlib.md5()
        m.update(coockies.encode())
        cookiessum = m.hexdigest()
        q = "INSERT INTO usertable (user, password, cookiessum) "
        q += "VALUES (?, ?, ?)"
        self.c.execute(q, (user, password, cookiessum))
        self.conn.commit()
        return cookiessum

    def read_auth_from_sql(self):
        self.c.execute('SELECT cookiessum, user FROM usertable')
        arr = []
        for row in self.c.fetchall():
            arr.append(row)
        return arr

    def is_user_and_pass_in_base(self, user, password):
        q = 'SELECT cookiessum, user FROM usertable '
        q += 'WHERE user == ? AND password == ?'
        self.c.execute(q, (user, password))
        tup = self.c.fetchall()
        if not tup:
            return None
        else:
            return tup[0]

    def is_user_in_base(self, user):
        q = 'SELECT cookiessum, user FROM usertable WHERE user == ?'
        self.c.execute(q, (user, ))
        tup = self.c.fetchall()
        if not tup:
            return None
        else:
            return tup[0]

    def is_auth_by_summ(self, cookiessum):
        q = 'SELECT user FROM usertable WHERE cookiessum == ?'
        self.c.execute(q, (cookiessum, ))
        tup = self.c.fetchall()
        if not tup:
            return None
        else:
            return tup[0][0]
