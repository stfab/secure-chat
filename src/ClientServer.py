from socket import AF_INET, socket, SOCK_STREAM, timeout
from socketserver import TCPServer, BaseRequestHandler
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey.RSA import import_key

import threading
import os


class TCPHandler(BaseRequestHandler):
    """Handle accepted requests of a TCP server.
    
    :param socket.socket request: Accepted socket connection by the server.
    :param tuple(str,int) client_adress: Address tuple of the client that made a request.
    :param socketserver.TCPServer server: Server instance that accepted the request and invoked the handler.
    
    """

    def handle(self):
        """Receive unencrypted incoming requests, write them to the stream and send the received bytes back."""

        try:
            self.received = self.request.recv(1024)
            if self.received != b'':
                self.server.stream.insert(
                    0, "%s wrote: %s\n" %
                    (self.client_address[0], self.received.decode("utf8").strip()))
                self.request.send(self.received)
        except UnicodeDecodeError:
            self.server.stream.insert(
                0, "Failed to decode a message from %s. Maybe it was encrypted." %
                (self.client_address[0]) + '\n')

    def finish(self):
        """Called after handle. Close the socket if the request was handled."""

        self.request.close()


class DecryptTCPHandler(BaseRequestHandler):
    """Handle accepted requests of a TCP server.
    
    :param socket.socket request: Accepted socket connection by the server.
    :param tuple(str,int) client_adress: Address tuple of the client that made a request.
    :param socketserver.TCPServer server: Server instance that accepted the request and invoked the handler.
    
    .. note::
        The encryption uses RSA and OAEP padding. This means it provides no authenticity. 
        If you receive a message it could be sent by anyone that has your publickey.
        Never send an unencrypted message if someone requests to do so.
        A middleman attacker would need a privatekey to read a message you send if it is encrypted. 
        
    """
    
    def handle(self):
        """Receive encrypted incoming requests, write them to the stream and send the received bytes back."""

        try:
            self.received = self.request.recv(1024)
            if self.received != b'':
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../my_keystore/privatekey.pem")) as f:
                    keypair = import_key(f.read())
                decryptor = PKCS1_OAEP.new(keypair)
                self.received_encrypted = decryptor.decrypt(self.received)
                self.server.stream.insert(
                    0, "%s wrote: %s\n" %
                    (self.client_address[0], self.received_encrypted.decode("utf8").strip()))
                self.request.send(self.received)
        except UnicodeDecodeError as e:
            self.server.stream.insert(
                0, "Failed to decode a message from %s. Maybe it was encrypted." %
                (self.client_address[0]) + '\n')
        except ValueError as e:
            self.server.stream.insert(
                0, "Failed to decrypt a message from %s. Maybe it was not encrypted." %
                (self.client_address[0]) + '\n')

    def finish(self):
        """Called after handle. Close the socket if the request was handled."""

        self.request.close()


class TCPClientServer():
    """Initialize a TCPClientServer with a message store called stream."""

    def __init__(self):

        self.stream = []

    def post(self, address, message, publickey_file=None):
        """Post a message to certain address.

        * Connect to a TCP server
        * If a publickey is provided, encrypt the message as bytes with it.
        * Send the message bytes.
        * Wait for message callback.
        * Check if the received callback is equal with sent bytes to verify that the message was received correctly.

        :param tuple(str,int) address: Combination of IP address and port of the receiver.
        :param str message: UTF-8 encoded message string that should be sent.
        :param str publickey_file: Filepath of a RSA publickey to encrypt the message. Default is None, so the message is sent unencrypted.

        .. note::
            The message you encrypt can be of variable length, but not longer than the RSA modulus (in bytes) 
            minus 2, minus twice the hash output size. If you use RSA 2048 and SHA-256, the 
            longest message you can encrypt is 190 byte long.
        
        To create a RSA keypair use the following snippet.
        Put your privatekey into the my_keystore folder and give the publickey to your chat partner.
        Never give anyone a access to your privatekey as they would be able to read all messages encrypted for you!
        If possible exchange publickeys physically and check that your partner and you got the right keys.

        .. code-block:: python

            from Crypto.PublicKey import RSA

            keyPair = RSA.generate(3072)
            pubKey = keyPair.publickey()
            pubKeyPEM = pubKey.exportKey()
            with open("publickey.pem","w+") as f:
                f.write(pubKeyPEM.decode('ascii'))
            privKeyPEM = keyPair.exportKey()
            with open("privatekey.pem","w+") as f:
                f.write(privKeyPEM.decode('ascii'))
        
        """

        try:
            message_bytes = bytes(message, "utf8")
            self.client_socket = socket(AF_INET, SOCK_STREAM)
            self.client_socket.connect(address)
            if publickey_file:
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), publickey_file)) as f:
                    publickey = import_key(f.read())
                encryptor = PKCS1_OAEP.new(publickey)
                message_bytes = encryptor.encrypt(message_bytes)
            self.client_socket.send(message_bytes)
            received = self.client_socket.recv(1024)
            if not received == message_bytes:
                raise ConnectionError(
                    "Sent and received message do not match.")
            self.client_socket.close()
            return 0
        except ConnectionRefusedError as e:
            self.stream.insert(0, str(e) + '\n')
            self.client_socket.close()
            return 1
        except ConnectionError as e:
            self.stream.insert(0, str(e) + '\n')
            self.client_socket.close()
            return 2
        except ValueError as e:
            self.stream.insert(
                0,
                "The provided message was too large for encryption. Try to send it in smaller pieces." +
                '\n')
            self.client_socket.close()
            return 3

    def serve(self, address, decrypt=False):
        """Serve on a certain address for incoming requests.

        :param tuple(str,int) address: Combination of IP address and port to serve on.
        :param bool decrypt: If true the server uses the DecryptTCPHandler and tries to decrypt incoming requests with a privatekey.

        """

        try:
            if decrypt:
                self.server = TCPServer(address,
                                        DecryptTCPHandler,
                                        bind_and_activate=True)
            else:
                self.server = TCPServer(address,
                                        TCPHandler,
                                        bind_and_activate=True)
            self.server.stream = self.stream
            self.stream.insert(0, "Start serving!\n")
            t = threading.Thread(target=self.server.serve_forever)
            t.start()
            return 0
        except Exception as e:
            self.stream.insert(0, str(e) + '\n')
            self.server._BaseServer__shutdown_request = True
            self.server.socket.close()
            return 1

    def stop_serve(self):
        """Stop the server."""

        try:
            self.server._BaseServer__shutdown_request = True
            self.server.socket.close()
            self.stream.insert(0, "Server closed!\n")
            return 0
        except Exception as e:
            self.stream.insert(0, str(e) + '\n')
            return 1
