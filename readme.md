Create virtual environment from requirements
activate the environment

For Linux and macOS, this is all done as follows:

(venv) $ export FLASK_APP=application.py

(venv) $ export FLASK_DEBUG=1

And for Microsoft Windows:

(venv) $ set FLASK_APP=application.py

(venv) $ set FLASK_DEBUG=1


After that set the Email and Password.

to get the passwoed

follow the steps:

1.Go to your Google Account.

2.Select Security.

3.Under "Signing in to Google," select 2-Step Verification.

4.At the bottom of the page, select App passwords.

5.Enter a name that helps you remember where you’ll use the app password.

6.Select Generate.

7.To enter the app password, follow the instructions on your screen. The app password is the 16-character code that generates on your device.

8.Select Done.


copy the password. and follow these steps:

If you are on Linux or macOS, you can set

these variables as follows:

(venv) $ export MAIL_USERNAME=<Gmail username>

(venv) $ export MAIL_PASSWORD=<Gmail password>



or Microsoft Windows users, the environment variables are set as follows:

(venv) $ set MAIL_USERNAME=<Put your email here>

(venv) $ set MAIL_PASSWORD=<Put the copied password here>














after that to run the application, Type flask run in command prompt
(venv) $ flask run
