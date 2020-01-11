import unittest
from ClientServer import TCPClientServer
import time


class Test(unittest.TestCase):

    def setUp(self):
        self.sender = TCPClientServer()
        self.listener = TCPClientServer()

    def test_serve(self):
        self.assertEqual(self.sender.serve(("localhost", 3000)), 0)
        self.assertEqual(self.sender.stop_serve(), 0)

    def test_message_can_not_be_sent_without_connection(self):
        self.assertEqual(self.sender.serve(("localhost", 3000)), 0)
        self.assertEqual(self.sender.stop_serve(), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost", 3000), "hello world"), 1)
        self.assertNotIn("hello world\n", self.sender.stream)

    def test_server_shutdown(self):
        self.assertEqual(self.listener.serve(("localhost", 3000)), 0)
        self.assertEqual(self.listener.stop_serve(), 0)
        self.assertIn("Start serving!\n", self.listener.stream)
        self.assertIn('Server closed!\n', self.listener.stream)

    def test_send_and_recieve(self):
        self.assertEqual(self.sender.serve(("localhost", 3000)), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost", 3000), "hello world"), 0)
        self.assertEqual(self.sender.stop_serve(), 0)
        self.assertIn('127.0.0.1 wrote: hello world\n', self.sender.stream)

    def test_send_encrypted_and_recieve_decrypted(self):
        self.assertEqual(
            self.sender.serve(
                ("localhost", 3000), decrypt=True), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost",
                 3000),
                "hello world",
                "../ext_keystore/publickey.pem"),
            0)
        self.assertEqual(self.sender.stop_serve(), 0)
        time.sleep(0.2)
        self.assertIn('127.0.0.1 wrote: hello world\n', self.sender.stream)

    def test_send_and_recieve_decrypted(self):
        self.assertEqual(
            self.sender.serve(
                ("localhost", 3000), decrypt=True), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost", 3000), "hello world"), 2)
        self.assertEqual(self.sender.stop_serve(), 0)
        time.sleep(0.2)
        self.assertIn(
            'Failed to decrypt a message from 127.0.0.1. Maybe it was not encrypted.\n',
            self.sender.stream)

    def test_send_encrypted_and_recieve(self):
        self.assertEqual(self.sender.serve(("localhost", 3000)), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost",
                 3000),
                "hello world",
                "../ext_keystore/publickey.pem"),
            2)
        self.assertEqual(self.sender.stop_serve(), 0)
        time.sleep(0.2)
        self.assertIn(
            "Failed to decode a message from 127.0.0.1. Maybe it was encrypted.\n",
            self.sender.stream)

    def test_send_and_recieve2(self):
        self.assertEqual(self.listener.serve(("localhost", 3000)), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost", 3000), "hello world"), 0)
        self.assertEqual(self.listener.stop_serve(), 0)
        self.assertIn('127.0.0.1 wrote: hello world\n', self.listener.stream)

    def test_dual_send_and_recieve(self):
        self.assertEqual(self.listener.serve(("localhost", 3002)), 0)
        self.assertEqual(self.sender.serve(("localhost", 3001)), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost", 3002), "hello world"), 0)
        self.assertEqual(
            self.listener.post(
                ("localhost", 3001), "hello world"), 0)
        self.assertEqual(self.sender.stop_serve(), 0)
        self.assertEqual(self.listener.stop_serve(), 0)
        self.assertIn('127.0.0.1 wrote: hello world\n', self.sender.stream)
        self.assertIn('127.0.0.1 wrote: hello world\n', self.listener.stream)

    def test_dual_send_and_recieve_encrypted(self):
        self.assertEqual(
            self.listener.serve(
                ("localhost", 3002), decrypt=True), 0)
        self.assertEqual(
            self.sender.serve(
                ("localhost", 3001), decrypt=True), 0)
        self.assertEqual(
            self.sender.post(
                ("localhost",
                 3002),
                "hello world",
                "../ext_keystore/publickey.pem"),
            0)
        self.assertEqual(
            self.listener.post(
                ("localhost",
                 3001),
                "hello world",
                "../ext_keystore/publickey.pem"),
            0)
        self.assertEqual(self.sender.stop_serve(), 0)
        self.assertEqual(self.listener.stop_serve(), 0)
        time.sleep(0.5)
        self.assertIn('127.0.0.1 wrote: hello world\n', self.sender.stream)
        self.assertIn('127.0.0.1 wrote: hello world\n', self.listener.stream)


if __name__ == "__main__":
    unittest.main()
