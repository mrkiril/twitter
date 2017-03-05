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
import datetime
import string
import hashlib
import random
import datetime
import urllib.parse
from httpserver import BaseServer
from httpserver import HttpResponse
from httpserver import HttpErrors
from twitter_db import DataBese
from time import sleep


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
        self.session_toc_user = {}

    def main_page(self, request):
        print("MAIN PAGE LALALA")
        print(request.method)
        print(request.COOKIE)
        if "twit" not in request.COOKIE:
            self.logger.debug("Theere is no Cookies")
            self.logger.debug("Redirect to auth/")
            return self.redirect_to("/auth")

        cookiessum = request.COOKIE["twit"]
        user = self.is_really_auth(cookiessum)
        print("USER IS >>> ", user)
        if user is None:
            self.logger.debug("Redirect to auth/")
            self.logger.debug("COOKIES not find in base. GOTO ")
            return self.redirect_to("/auth")

        if request.method == "GET":
            self.logger.debug("Main Page GET")
            self.logger.debug("return_user_page")
            self.logger.debug("for user:"+ str(user))
            self.session_toc_user[cookiessum] = user
            data = self.return_user_page(user)
            return HttpResponse(data.encode(), content_type='html')

        if request.method == "POST":
            self.logger.debug("Main Page POST")
            print(request.POST)
            if request.POST["type_post"] == "post_post":
                self.logger.debug("POST_POST")
                if "text" not in request.POST:
                    return self.redirect_to("/auth")
                self.data_base.add_data_to_sql(user, request.POST["text"])
                data = self.return_user_page(user)
                return HttpResponse(data.encode(), content_type='html')
            if request.POST["type_post"] == "delete_post":
                self.logger.debug("DELETE_POST")
                self.data_base.delete_data_from_sql(
                    user_id=user,
                    row_id=request.POST["elem"])
                data = self.return_user_page(user)
                return HttpResponse(data.encode(), content_type='html')

            if request.POST["type_post"] == "exit":
                self.logger.debug("EXIT")
                date = datetime.datetime.utcnow()
                data = ""
                return HttpResponse(data.encode(),
                                    status_code="301",
                                    content_type='html',
                                    location="/auth",
                                    set_cookies={"twit": "lalala"},
                                    cookies_expires=date)

    def auth(self, request):
        print("AUTH LALALA")
        if "twit" in request.COOKIE:
            cookiessum = request.COOKIE["twit"]
            cook_user = self.is_really_auth(cookiessum)
            print("USER IS >>> ", cook_user)
            if cook_user is not None:
                return self.redirect_to("/")

        if request.method == "POST":
            if "register_email" in request.POST:
                print("Registration")
                print(request.POST)
                register_user = self.data_base.is_user_in_base(
                    request.POST["register_email"])
                if register_user is None:
                    print("user in base")
                    cookies = self.data_base.add_auth_to_sql(
                        request.POST["register_email"],
                        request.POST["password"])
                    data = ""
                    return HttpResponse(data.encode(),
                                        status_code="301",
                                        content_type='html',
                                        location="/",
                                        set_cookies={"twit": cookies})

                if register_user is not None:
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
                print("Authorisation")
                print(request.POST)
                enter_user = self.data_base.is_user_and_pass_in_base(
                    request.POST["enter_email"], request.POST["password"])
                data = ''
                if enter_user is not None:
                    cookies = enter_user[0]
                    user = enter_user[1]
                    self.session_toc_user[cookies] = user
                    data = ""
                    return HttpResponse(data.encode(),
                                        status_code="301",
                                        content_type='html',
                                        location="/",
                                        set_cookies={"twit": cookies})

                if enter_user is None:
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

    def is_really_auth(self, cookiessum):
        if cookiessum not in self.session_toc_user:
            user = self.data_base.is_auth_by_summ(cookiessum)
            if user is None:
                return None
            else:
                return user
        if cookiessum in self.session_toc_user:
            return self.session_toc_user[cookiessum]

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
        print("ARR")

        print(arr)
        for ar in arr:
            date, twit, row_id = ar
            twit = urllib.parse.unquote_plus(twit)
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
                    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
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
                    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
                  <strong>Warning!</strong> ''' + user_message + '''
                </div><!-- MESSAGE -->'''
        return text

    def add_new_html_twit(self, username, twit, date, row_id):
        text = '''  <div class="blog-post"> 
                        <div class="row">
                            <div class="col-xs-6 col-sm-6 col-md-6 col-lg-6">
                                <p class="blog-post-meta">DATE <a href="#">USERNAME</a></p>
                            </div>
                            <div align="right" class="col-xs-6 col-sm-6 col-md-6 col-lg-6">
                                <form name="f1" method="POST" action="DOMEN">
                                    <input type="hidden" name="type_post" value="delete_post">
                                    <button type="submit" name="elem" value="INDEX" class="btn btn-default btn-del"><span class="glyphicon glyphicon-remove"></span></button>
                                </form>
                            </div>
                        </div>
                        <p>MESSAGE</p>
                    </div><!-- /.blog-post -->'''
        # date = str(datetime.datetime.fromtimestamp(
        #    unix).strftime('%Y-%m-%d %H:%M:%S'))
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
        if "DEFAULT" in config:
            conf = config['DEFAULT']
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
