from tkinter import *
import threading
import tkinter.scrolledtext
import os
import ClientServer


class App(object):
    """Provides the CLientServer functions in a simple Tkinter GUI.

    * Create a TCPClientServer.
    * Create the Tkinter root.
    * Add the frames with their elements.
    * Start a thread that writes the TCPClientServer.stream to the ScrolledText in the display frame.

    """

    def __init__(self):
        self.client = ClientServer.TCPClientServer()

        self.root = Tk(className="secure-chat")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.serve_frame = Frame(self.root, height=50, width=500)
        self.serve_frame.pack(fill=BOTH)
        self.serverhostlabel = Label(self.serve_frame, text="Server-Host: ")
        self.serverhostlabel.pack(side=LEFT)
        self.serverhost = Entry(self.serve_frame)
        self.serverhost.insert(0, "127.0.0.1")
        self.serverhost.pack(side=LEFT)
        self.serverportlabel = Label(self.serve_frame, text="Server-Port: ")
        self.serverportlabel.pack(side=LEFT)
        self.serverport = Entry(self.serve_frame)
        self.serverport.insert(0, "3000")
        self.serverport.pack(side=LEFT)
        self.decrypted = IntVar()
        self.decryptbutton = Checkbutton(
            self.serve_frame,
            text="decrypt",
            variable=self.decrypted)
        self.decryptbutton.pack(side=RIGHT)
        self.servebutton = Button(
            self.serve_frame,
            text="Serve",
            command=self.serve)
        self.servebutton.pack(side=RIGHT)

        self.display_frame = Frame(self.root, height=400, width=600)
        self.display_frame.pack(fill=BOTH)
        self.text = tkinter.scrolledtext.ScrolledText(
            self.display_frame, state=DISABLED, bg="lightgray")
        self.text.pack(fill=BOTH)

        self.connect_frame = Frame(self.root, height=50, width=500)
        self.connect_frame.pack(fill=BOTH)
        self.hostlabel = Label(self.connect_frame, text="Host: ")
        self.hostlabel.pack(side=LEFT)
        self.host = Entry(self.connect_frame)
        self.host.insert(0, "127.0.0.1")
        self.host.pack(side=LEFT)
        self.portlabel = Label(self.connect_frame, text="Port: ")
        self.portlabel.pack(side=LEFT)
        self.port = Entry(self.connect_frame)
        self.port.insert(0, "3000")
        self.port.pack(side=LEFT)
        self.keylabel = Label(self.connect_frame, text="Publickey: ")
        self.keylabel.pack(side=LEFT)
        self.key = Entry(self.connect_frame)
        self.key.pack(side=LEFT)

        self.post_frame = Frame(self.root, height=50, width=500)
        self.post_frame.pack(fill=BOTH)
        self.entry = tkinter.scrolledtext.ScrolledText(
            self.post_frame, height=5)
        self.entry.pack(fill=X)
        self.postbutton = Button(
            self.post_frame,
            text="Post",
            command=self.post)
        self.postbutton.pack(fill=X)

        self.root.update()

        t = threading.Thread(target=self.stream_to_text)
        t.start()

    def stream_to_text(self):
        """Constantly try to write the string elements inside the clientserver stream to the scrolledtext."""

        while True:
            if len(self.client.stream) > 0:
                self.insert_into_disabled_scrolledtext(
                    self.client.stream.pop())
                self.root.update_idletasks()

    def insert_into_disabled_scrolledtext(self, string):
        """Write a given string to the scrolledtext.

        :param str string: String to write to the scrolledtext.

        """

        self.text.configure(state=NORMAL)
        self.text.insert(tkinter.INSERT, string)
        self.text.configure(state=DISABLED)

    def serve(self):
        """Execute the serve method of the clientserver.

        * Get the host ip, host port and the decrypt flag from the GUI.
        * Execute the serve method of the clientserver.
        * If successful change the button so that it stops serving on click.
        * Disable the decrypt checkbox because it can only be changed while not serving.

        """

        r = self.client.serve((self.serverhost.get(), int(
            self.serverport.get())), self.decrypted.get())
        if r == 0:
            self.servebutton.config(text="Stop Server")
            self.servebutton.config(command=self.stop_serve)
            self.decryptbutton.configure(state=DISABLED)
        self.root.update_idletasks()

    def stop_serve(self):
        """Execute the stop_serve method of the clientserver. """

        r = self.client.stop_serve()
        if r == 0:
            self.servebutton.config(text="Serve")
            self.servebutton.config(command=self.serve)
            self.decryptbutton.configure(state=NORMAL)
        self.root.update_idletasks()

    def post(self):
        """Execute the post method of the clientserver.

        * Get the receiver ip, receiver port and publickey data from the GUI.
        * Execute the post method of the clientserver.
        * If successful delete the text that has been sent.

        """

        if self.client.post((self.host.get(),
                             int(self.port.get())),
                            self.entry.get("1.0", tkinter.END)[:-1],
                            self.key.get()) == 0:
            self.entry.delete("1.0", tkinter.END)
        else:
            self.insert_into_disabled_scrolledtext(
                "Message couldn't get delivered.\n")
        self.root.update_idletasks()

    def close(self):
        """Called on window closing. Exit all running processes."""

        os._exit(1)


if __name__ == "__main__":
    a = App()
    a.root.mainloop()
