#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os.path
import os
import sys
import re
import logging
import logging.config
import configparser
import sqlite3
import string
import datetime
import urllib.parse
import hashlib
import binascii
import random
import json
from httpserver import BaseServer
from httpserver import HttpResponse
from httpserver import HttpErrors
from twitter_db import DataBese
from time import sleep
from urllib.parse import quote_plus
from urllib.parse import unquote_plus


class Twitter(BaseServer):

    """ Class of a base class that implements
        configure method of the list of pages.
        And methods which this pages returned
        Attributes:
            ip: server ip
            port: server port
            And logger of library can call'd like self.logger
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        self.setting_file_path = os.path.join(
            self.file_path, "setting", "setting.ini")

        self.ip, self.port = self.setting_connect()
        self.domen = 'http://' + str(self.ip) + ":" + str(self.port)
        super(Twitter, self).__init__(self.ip, self.port)

    def filter_twit(self, twit):
        twit = unquote_plus(twit)
        return self.filter_out_data(twit)

    def filter_out_data(self, twit):
        html_dick = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            "‘": "&lsquo;",
            "’": "&rsquo;",
            '“': "&ldquo;",
            '”': "&rdquo;",
            "'": "&apos;",
            '"': "&quot;"
        }
        twit = "".join([s for s in twit if ord(s) > 31])
        twit = twit[:100]
        twit = re.sub(r'\s+', ' ', twit)
        twit = re.sub('\s+', ' ', twit)
        twit = re.sub('^ ', '', twit)
        twit = re.sub(' $', '', twit)
        for k, v in html_dick.items():
            twit = twit.replace(k, v)
        return twit

    def main_page(self, request):
        print("MAIN PAGE MODE")
        print("IP >> ", self.ip)
        if "twit" not in request.COOKIE:
            self.logger.debug("Theere is no Cookies")
            self.logger.debug("Redirect to auth/")
            return self.redirect_to("/auth")

        user_id = self.is_really_auth(request.COOKIE["twit"])
        if not user_id:
            self.logger.debug("Redirect to auth/")
            self.logger.debug("COOKIES not find in base. GOTO ")
            return self.redirect_to("/auth")

        if request.method == "GET":
            self.logger.debug("Main Page GET")
            self.logger.debug("return_user_page")
            self.logger.debug("for user:" + str(user_id))
            data = self.return_user_page(user_id)
            return HttpResponse(data.encode(), content_type='html')

        if request.method == "POST":
            self.logger.debug("Main Page POST")
            if request.POST["type_post"] == "post_post":
                self.logger.debug("POST_POST")
                if "text" not in request.POST:
                    return self.redirect_to("/auth")
                self.data_base.add_data_to_sql(
                    user_id,
                    self.filter_twit(request.POST["text"]))

                data = self.return_user_page(user_id)
                return HttpResponse(data.encode(), content_type='html')

            if request.POST["type_post"] == "delete_post":
                self.logger.debug("DELETE_POST")
                self.data_base.delete_data_from_sql(
                    user_id=user_id,
                    row_id=request.POST["elem"])
                data = self.return_user_page(user_id)
                return HttpResponse(data.encode(), content_type='html')

            if request.POST["type_post"] == "exit":
                self.logger.debug("EXIT")
                self.delete_ses(user_id=user_id,
                                ses_id=request.COOKIE["twit"])
                date = datetime.datetime(1970, 1, 1, 0, 0)
                return HttpResponse(b'',
                                    status_code="301",
                                    content_type='html',
                                    location="/auth",
                                    set_cookies={"twit": "lalala"},
                                    cookies_expires=date)

    def auth(self, request):
        if "twit" in request.COOKIE:
            ses_id = request.COOKIE["twit"]
            user_id = self.is_really_auth(ses_id)
            if user_id:
                return self.redirect_to("/")

        if request.method == "POST":
            if "register_email" in request.POST:
                salt = self.create_salt()
                pass_sha = self.create_pass_str(request.POST["password"], salt)
                auth_status = self.data_base.add_auth_to_sql(
                    request.POST["register_email"],
                    pass_sha,
                    salt)

                if auth_status:
                    ses_id = self.add_new_ses_id_to_db(
                        user_id=request.POST["register_email"],
                        user_ip=request.user_ip,
                        session_data={})
                    return HttpResponse(b"",
                                        status_code="301",
                                        content_type='html',
                                        location="/",
                                        cookies_expires=self.cook_exp(),
                                        set_cookies={"twit": ses_id})

                if not auth_status:
                    data = self.return_auth_page()
                    message = self.message_auth(
                        "3",
                        "There is user with this e-mail. Try another")
                    data = re.sub(
                        "<!-- MESSAGE WRONG REGISTER-->", message, data)
                    return HttpResponse(data.encode(),
                                        status_code="200",
                                        content_type='html')

            if "enter_email" in request.POST:
                is_user = self.data_base.is_user_in_base(
                    request.POST["enter_email"])
                data = ''
                print("IS USER")
                print(is_user)
                if is_user:
                    user_id, salt, db_pass = is_user
                    if not self.is_pass_eq_pass(
                            enter_pass=request.POST["password"],
                            db_pass=db_pass,
                            salt=salt):
                        data = self.return_auth_page()
                        message = self.message_auth(
                            "3",
                            "There is incorrect e-mail or password. Try again")
                        data = re.sub("<!-- MESSAGE -->", message, data)
                        return HttpResponse(data.encode(),
                                            status_code="200",
                                            content_type='html')

                    ses_id = self.add_new_ses_id_to_db(
                        user_id=user_id,
                        user_ip=request.user_ip,
                        session_data={})
                    return HttpResponse(data.encode(),
                                        status_code="301",
                                        content_type='html',
                                        location="/",
                                        cookies_expires=self.cook_exp(),
                                        set_cookies={"twit": ses_id})

                if not is_user:
                    data = self.return_auth_page()
                    message = self.message_auth(
                        "3",
                        "There is incorrect e-mail or password. Try again")
                    data = re.sub("<!-- MESSAGE -->", message, data)
                    return HttpResponse(data.encode(),
                                        status_code="200",
                                        content_type='html')

        if request.method == "GET":
            data = self.return_auth_page()
            return HttpResponse(data.encode(),
                                status_code="200",
                                content_type='html')

    def styles(self, request):
        path = os.path.join(os.getcwd(), request.path[1:])
        with open(path, "rb") as fp:
            data = fp.read()

        if b"bootstrap.js" in request.text:
            return HttpResponse(data,
                                content_type='application/javascript')
        elif b"favicon.ico" in request.text:
            return HttpResponse(data, content_type='image/x-icon')
        else:
            return HttpResponse(data, content_type='text/css')

    def redirect_to(self, loc):
        data = ""
        return HttpResponse(data.encode(),
                            status_code="301",
                            content_type='html',
                            location=loc)

    def is_pass_eq_pass(self, enter_pass, db_pass, salt):
        if db_pass == self.create_pass_str(enter_pass, salt):
            return True
        else:
            return False

    def cook_exp(self):
        y = datetime.datetime.utcnow().year
        return datetime.datetime(y + 1, 12, 31, 23, 59)

    def delete_ses(self, user_id, ses_id):
        self.data_base.delete_session_from_sql(user_id, ses_id)

    def add_new_ses_id_to_db(self, user_id, session_data, user_ip):
        time = datetime.datetime.utcnow().strftime("%A, %d-%b-%Y %H:%M:%S")
        while True:
            print("add_new_ses_id_to_db")
            ses_id = ''.join(
                [random.choice(string.hexdigits) for i in range(16)])
            ses_status = self.data_base.add_session_to_sql(
                session_hash=ses_id,
                expires=time,
                user_id=user_id,
                ip_address=user_ip,
                session_data=json.dumps(session_data))
            if ses_status:
                return ses_id

    def create_salt(self):
        return os.urandom(8)

    def create_pass_str(self, password, salt):
        # salt = os.urandom(8)    # 64-bit salt
        dk = hashlib.pbkdf2_hmac('sha256',
                                 password.encode(),
                                 salt,
                                 1000)
        sha = binascii.hexlify(dk)
        return sha

    def is_really_auth(self, ses_id):
        """
        Cheak user in session dictionary
        """
        print("In really auth mode")
        user_obj = self.data_base.is_session_in_base(ses_id)
        if user_obj:
            user_id, ses_expiries = user_obj
            print("User id", user_id)
            time_template = "%A, %d-%b-%Y %H:%M:%S"
            dt_obj = datetime.datetime.strptime(ses_expiries, time_template)
            dt_now = datetime.datetime.utcnow()
            print(dt_now)
            print(dt_now - dt_obj)
            dt_delta = dt_now - dt_obj
            if dt_delta.total_seconds() > 1000:
                print("DEl mode COOK IS INVALID")
                self.data_base.delete_session_from_sql(user_id, ses_id)
                return False
            else:
                dt_obj = datetime.datetime.utcnow()
                dt = str(dt_obj.strftime("%A, %d-%b-%Y %H:%M:%S"))
                self.data_base.update_session_expires_to_sql(
                    user_id=user_id,
                    expires=dt,
                    ses_id=ses_id)
                return user_id
        else:
            return False

    def return_auth_page(self):
        with open("authorisation.html", "r") as fp:
            text = fp.read()
        text = re.sub("DOMEN", self.domen + "/auth", text)
        return text

    def return_user_page(self, user_id):
        """
        If cookie is in request
        1. Do request to db and take all twit of user
        2. Create page
        """
        with open("forms.html", "r") as fp:
            text = fp.read()
        text = re.sub("DOMEN", self.domen + "/", text)
        arr = self.data_base.read_data_from_sql(user_id)
        for ar in arr:
            date, twit, row_id = ar
            add_twit_text = self.add_new_html_twit(user_id, twit, date, row_id)
            text = re.sub("<!-- /.blog-post -->", add_twit_text, text)

        return text

    def message_registr(self, lv, user_message):
        # 1  alert-success
        # 2  alert-info
        # 3  alert-warning
        # 4  alert-danger
        level = {"1": "alert-success",
                 "2": "alert-info",
                 "3": "alert-warning",
                 "4": "alert-danger"}
        text = '''
        <div class="alert ''' + level[lv] + ''' alert-dismissable">
            <button type="button" class="close" data-dismiss="alert"
                                         aria-hidden="true">&times;</button>
          <strong>Warning!</strong> ''' + user_message + '''
        </div><!-- MESSAGE WRONG REGISTER-->'''
        return text

    def message_auth(self, lv, user_message):
        # 1  alert-success
        # 2  alert-info
        # 3  alert-warning
        # 4  alert-danger
        level = {"1": "alert-success",
                 "2": "alert-info",
                 "3": "alert-warning",
                 "4": "alert-danger"}
        text = '''
        <div class="alert ''' + level[lv] + ''' alert-dismissable">
        <button type="button" class="close" data-dismiss="alert"
        aria-hidden="true">&times;</button>
        <strong>Warning!</strong> ''' + user_message + '''
        </div><!-- MESSAGE -->'''
        return text

    def add_new_html_twit(self, username, twit, date, row_id):
        text = '''
        <div class="blog-post">
        <div class="row">
        <div class="col-xs-6 col-sm-6 col-md-6 col-lg-6">
            <p class="blog-post-meta">DATE <a href="#">USERNAME</a></p>
        </div>
        <div align="right" class="col-xs-6 col-sm-6 col-md-6 col-lg-6">
            <form name="f1" method="POST" action="DOMEN">
                <input type="hidden" name="type_post" value="delete_post">
                <button type="submit" name="elem" value="INDEX"
                                        class="btn btn-default btn-del">
                <span class="glyphicon glyphicon-remove"></span>
                </button>
            </form>
        </div>
        </div>
        <p>MESSAGE</p>
        </div><!-- /.blog-post -->'''
        text = re.sub("DATE", date, text)
        text = re.sub("INDEX", str(row_id), text)
        text = re.sub("DOMEN", self.domen + "/", text)
        text = re.sub("MESSAGE", twit, text)
        return text

    def configure(self):
        self.add_route(r'^/$', self.main_page,
                       ["GET", "POST", "PUT", "DELETE"])
        self.add_route(r'^/form/.*$', self.styles)
        self.add_route(r'^/auth.*$', self.auth, ["GET", "POST"])

    def setting_connect(self):
        config = configparser.ConfigParser()
        config.read(self.setting_file_path)
        if "ip_port_setting" in config:
            conf = config['ip_port_setting']
            if 'ip' in conf and 'port' in conf:
                self.logger.info("Serv setting is ok")
                return(conf["ip"], int(conf["port"]))

            else:
                self.logger.info(
                    "Setting file is broken."
                    " Try start server on default setting 127.0.0.1:8080")
                return("127.0.0.1", int("8080"))
        else:
            self.logger.info(
                "Setting file is broken."
                " Try start server on default setting 127.0.0.1:8080")
            return("127.0.0.1", int("8080"))

try:
    logging.config.fileConfig(
        os.path.join(os.getcwd(), "setting", "logging.conf"))

    app = Twitter()
    app.logger.info("start >> " + str(os.getpid()))
    app.logger.info(str(app.ip) + " : " + str(app.port))

    # DB
    app.data_base = DataBese(app.setting_file_path)

    app.serve_forever()
    app.logger.info("Cry Baby")


except OSError as e:
    app.logger.error(str(e))

except AttributeError as e:
    app.logger.error("Sorry, but can't start app")
    app.logger.error(str(e))
