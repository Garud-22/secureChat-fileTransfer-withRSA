from tkinter import *
from socket import *
import _thread
import tqdm
import os
from tkinter import filedialog
import rsa
import sys

# initializing the client connection
def initialize_client():
    global server_pubkey
    global prikey

    # generating public and private keys of atleast 1024 bits
    pubkey, prikey = rsa.newkeys(1024)

    # initialize the socket
    s = socket(AF_INET, SOCK_STREAM)

    # configure the details of the server
    host = 'localhost'
    port = 5000

    # connecting to the server
    s.connect((host, port))

    # receiving the public key of the server
    server_pubkey = rsa.PublicKey.load_pkcs1(s.recv(4096))
    print("The server's public key is:\n")
    print(server_pubkey)

    # clearing the input buffer of the socket
    while True:
        data = s.recv(4096).decode()
        if data == "\n":
            break

    # sending the client public key to the server in PEM format
    s.send(pubkey.save_pkcs1("PEM"))

    print("1.Messaging\n2.File transfer\nEnter your choice:")
    ch = str(int(input()))

    # sending the client's choice to the server
    s.send(ch.encode('utf-8'))

    # clearing the output buffer of the socket
    s.send("\n".encode('utf-8'))

    # returning the socket object
    return s, ch

# function to update the chatlog
def updateChat(msg, writtenBy):
    # declaring the global variable
    global chatlog

    # making the chatlog editable
    chatlog.config(state=NORMAL)

    # updating the message in the window
    if writtenBy == 0:
        # if the client has written the message
        chatlog.insert(END, 'Client: ' + msg) # writing the message in the end
    elif writtenBy == 1:
        # if the server has written the message
        chatlog.insert(END, 'Server: ' + msg)

        # making the chatlog uneditable again
        chatlog.config(state=DISABLED)

        # displaying the latest version of the chatlog
        chatlog.yview(END)

# function to send message
def send():
    # declaring the global variable
    global textBox

    # getting the message
    msg = textBox.get("0.0", END) # "0.0" refers to the starting index of the text

    # updating the chatlog
    updateChat(msg, 0) # 0 implies the chatlog is updated as the client
                       # 1 implies the chatlog is updated as the server

    # encrypting the message to be sent with the server's public key
    encData = rsa.encrypt(msg.encode('utf-8'), server_pubkey)

    # print the encrypted data
    print(f"\nThe encrypted data is:\n{encData}")
    
    # send the messgae to the server
    s.send(encData)

    # clearing the textbox
    textBox.delete("0.0", END)

# function to receive message
def receive():
    while 1:
        try:
            # receiving the encrypted data
            encData = s.recv(1024) # 1024 bytes is the buffer size

            # decrypting the encrypted data with the client's private key
            decData = rsa.decrypt(encData, prikey)
            msg = decData.decode('utf-8')

            if msg != "":
                # if some message is received, the chatlog is updated with it
                updateChat(msg, 1)
        except:
            pass

def press(event):
    # send() function is executed when the ENTER key is released
    send()

# GUI function
def GUI():
    # declaring the global variables
    global chatlog
    global textBox

    # initializing tkinter object
    gui = Tk()

    # setting the title for the window
    gui.title("Client Chat")

    # setting size for the window
    gui.geometry("380x430")

    # text space to display messages
    chatlog = Text(gui, bg='white')
    # making the chatlog component uneditable, so that it can only display messages
    chatlog.config(state=DISABLED)

    # button to send messages
    # send() function will be executed when the button is clicked
    sendButton = Button(gui, bg='blue', fg='yellow', text='Send', command=send)

    # textbox to type messages
    textBox = Text(gui, bg='white')

    # placing the components in the window
    chatlog.place(x=6, y=6, height=386, width=370)
    textBox.place(x=6, y=401, height=20, width=265)
    sendButton.place(x=300, y=401, height=20, width=50)

    # binding textbox to use ENTER key for sending message
    # press() function is executed when ENTER key is released
    textBox.bind("<KeyRelease-Return>", press)

    # creating thread to capture messages continuously
    _thread.start_new_thread(receive, ())

    # to keep the window open untill closed by the user
    gui.mainloop()

def fileTransfer():
    global BUFFER_SIZE
    global SEPARATOR

    # getting the complete path of the file we want to send
    root = Tk()
    #root.withdraw()
    filepath = filedialog.askopenfilename()

    # getting the file size in bytes
    filesize = os.path.getsize(filepath)

    # sending the filename and filesize
    s.send(f"{filepath}{SEPARATOR}{filesize}".encode())

    # sending the file
    progress = tqdm.tqdm(range(filesize), f"Sending {os.path.basename(filepath)}", unit="B", unit_scale=True, unit_divisor=1024)

    # using "with" statement ensures that the file is closed when the block is exited
    with open(filepath, "rb") as f:
        while True:
            # reading 64 bytes from the file at a time
            bytes_read = f.read(64)
            if not bytes_read:
                # when file transmitting is done
                break

            # encrypting the data with the server's public key
            encrypted_data = rsa.encrypt(bytes_read, server_pubkey)
            #print("Size of encrypted data is:", sys.getsizeof(encrypted_data))

            # sending the data
            # sendall is used to assure transimission in busy networks
            s.sendall(encrypted_data)
            #print("The encrypted data is:", encrypted_data)

            # updating the progress bar
            progress.update(len(bytes_read))

    # closeing the socket
    s.close()
    

if __name__ == '__main__':
    # making the variables globally accessible
    chatlog = textBox = prikey = server_pubkey = None
    SEPARATOR = "<SEPARATOR>"
    BUFFER_SIZE = 4096 

    s, ch = initialize_client()

    if ch == '1': # when client wants to use the chat application
        GUI() 
    elif ch == '2': # when client wants to do file transfer
        fileTransfer() 