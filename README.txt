Description
===========

Python simple twitter server
first you must have Git in your pc. If not you can easy do this run command "apt-get install git"
profit!

Run your virtualenv or pyvenv mashine.
Next step do only from virtualenv or pyvenv
	0) in file setting/setting.ini in [ip_port_setting] block you can set ip and port which will be listening server
	1) And in same file in [database] block set the path to the database. Without this path serv will not start
	2) run requirements.txt file by command "pip install -r requirements.txt" to set all the required libraries
	3) if you want start server need run command "python3 search_serv.py"

Default Settings IP = 127.0.0.1, port = 8080, if you did not change it, type in the browser bar 127.0.0.1:8080 otherwise your parameters, which would go to the start page.

Test file you can find in twitter/test run like "python3 test_twitter.py"
