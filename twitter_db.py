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
        self.conn_str = self.setting_connect()
        self.entry_data_to_sql()
        self.entry_auth_to_sql()
        self.entry_session_to_sql()

    def setting_connect(self):
        config = configparser.ConfigParser()
        config.read(self.setting_file_path)
        if "database" in config:
            conf = config['database']
            if 'DB' in conf:
                self.logger.info("Data base setting is ok")
                return conf["DB"]

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
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = '''CREATE TABLE IF NOT EXISTS datatable(
                                                    datestamp TEXT NOT NULL,
                                                    message TEXT NOT NULL,
                                                    user_id TEXT NOT NULL)'''
        c.execute(q)
        conn.commit()
        c.close()
        conn.close()

    def add_data_to_sql(self, user_id, message):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        date = str(datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        q = "INSERT INTO datatable (datestamp, message, user_id)"
        q += " VALUES (?, ?, ?)"
        c.execute(q, (date, message, user_id))
        conn.commit()
        c.close()
        conn.close()

    def read_data_from_sql(self, user_id):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = 'SELECT datestamp, message, ROWID '
        q += 'FROM datatable WHERE user_id == ?'
        c.execute(q, (user_id, ))
        arr = []
        for row in c.fetchall():
            arr.append(row)
        c.close()
        conn.close()
        return arr

    def update_data_to_sql(self, user_id, message):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        date = str(datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        q = 'UPDATE datatable SET message = ? datestamp = ? WHERE user_id == ?'
        c.execute(q, (str(message), str(date), str(user_id)))
        conn.commit()
        c.close()
        conn.close()

    def delete_data_from_sql(self, user_id, row_id):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = 'DELETE FROM datatable WHERE user_id == ? AND ROWID == ?'
        c.execute(q, (user_id, row_id))
        conn.commit()
        c.close()
        conn.close()

    def entry_auth_to_sql(self):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = '''CREATE TABLE IF NOT EXISTS usertable(
                    user TEXT NOT NULL UNIQUE,
                    password BLOB NOT NULL,
                    salt BLOB NOT NULL)'''
        c.execute(q)
        conn.commit()
        c.close()
        conn.close()

    def add_auth_to_sql(self, user, password, salt):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        try:
            q = "INSERT INTO usertable (user, password, salt) "
            q += "VALUES (?, ?, ?)"
            c.execute(q, (user, password, salt))
            conn.commit()
        except sqlite3.IntegrityError as e:
            c.close()
            conn.close()
            return False
        else:
            c.close()
            conn.close()
            return True

    def read_auth_from_sql(self):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        c.execute('SELECT salt, user FROM usertable')
        arr = []
        for row in c.fetchall():
            arr.append(row)
        c.close()
        conn.close()
        return arr

    def is_user_in_base(self, user):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = 'SELECT user, salt, password FROM usertable WHERE user == ?'
        c.execute(q, (user, ))
        tup = c.fetchall()
        if not tup:
            c.close()
            conn.close()
            return False
        else:
            c.close()
            conn.close()
            return tup[0]

    def entry_session_to_sql(self):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = '''CREATE TABLE IF NOT EXISTS sessiontable(
                    session_hash TEXT NOT NULL UNIQUE,
                    expires TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    session_data TEXT NOT NULL)'''
        c.execute(q)
        conn.commit()
        c.close()
        conn.close()

    def add_session_to_sql(self, session_hash, expires,
                           user_id, ip_address, session_data):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        try:
            q = '''INSERT INTO sessiontable (session_hash, expires,
            user_id, ip_address, session_data) '''
            q += "VALUES (?, ?, ?, ?, ?)"
            c.execute(q, (session_hash, expires,
                          user_id, ip_address, session_data))
            conn.commit()
        except sqlite3.IntegrityError as e:
            c.close()
            conn.close()
            return False
        else:
            c.close()
            conn.close()
            return True

    def is_session_in_base(self, ses_id):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = 'SELECT user_id, expires FROM sessiontable WHERE session_hash == ?'
        c.execute(q, (ses_id, ))
        tup = c.fetchall()
        if not tup:
            c.close()
            conn.close()
            return False
        else:
            c.close()
            conn.close()
            return tup[0]

    def update_session_expires_to_sql(self, user_id, expires, ses_id):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        q = 'UPDATE sessiontable SET expires = ? '
        q += 'WHERE user_id == ? AND session_hash == ?'
        c.execute(q, (expires, user_id, ses_id))
        conn.commit()
        c.close()
        conn.close()

    def delete_session_from_sql(self, user_id, ses_id):
        conn = sqlite3.connect(self.conn_str)
        c = conn.cursor()
        print("DEL SESSION")
        q = 'DELETE FROM sessiontable WHERE user_id == ? AND session_hash == ?'
        c.execute(q, (user_id, ses_id))
        conn.commit()
        c.close()
        conn.close()
