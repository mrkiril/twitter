Twitter WEB SERVER
=============================

Thank you for choosing this server.


INSTALLATION
------------

After installation you shall see the following files and directories:

      form/                css/ js/ fonts/ auxiliary folders
      setting/             setting files
      tests/               test files
      authorisation.html   auth page
      forms.html	   main page
      README               this file
      requirements.txt     requirements that must necessarily be established
      twitter.py	   main file
      twitter_db.py        Manipulation with DB


REQUIREMENTS
------------

The minimum requirement you must have Git in your pc.
If not, you can easily do this call "apt-get install git"
profit!


QUICK START
-----------

Run your virtualenv or pyvenv mashine.
Next step do only from virtualenv or pyvenv:

	0) In file setting/setting.ini in [ip_port_setting] block you can set ip and port.
	   They give you access to server.
	
	1) And in same file in [database] block set the path to the database. 
           Without this path server will not start. 
           if file is not exist, server will create it.
	
	2) Run requirements.txt call "pip install -r requirements.txt" to set all the required libraries
	
        3) If you want start server need call "python3 search_serv.py". 
	   But you should be in the location directory of this file


