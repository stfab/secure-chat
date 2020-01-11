secure-chat
===========

.. inclusion-marker-do-not-remove

secure-chat is mainly a TCP clientserver with RSA and OAEP encryption support.
It comes with a simple tkinter GUI (App.py) that provides the modules functions.

Its goal is to provide a simple but secure solution to chat with another person.
Two peers create a RSA keypair each as described in the docs and exchange their publickeys.
Afterwards they can send each other encrypted messages and decrypt those they receive.
All that is required is to know eachothers host address.

.. note::

   * Never use the keys provided in this repository as they are publicly available and therefore insecure.
   * Within the same network it is enough to know the IP addresses and ports of the machines used.
   * If you chat on the web the IP of your gateway will change sometimes. 
     Therefore you have to communicate eachothers addresses on another way (e.g. phone) or implement some kind of DNS with a webdomain.
   * On the web you also have to make sure your NAT roots your server to a port that it shows on the web.
     Else another person can not connect to your server. 

Installation
------------

#. Install Python 3.7+
#. Install the packet manager pip.
#. `pip install -r requirements.txt`

Start the App
-------------

Start the app with `python src/App.py`.

Test
----

You need to install the automation tool tox first via `pip install tox`.

Just run `tox` in the main directory.

Build the Docs
--------------

You need to install the automation tool tox first via `pip install tox`.

Run `tox -e build-docs` in the main directory.