from tkinter import *
from socket import *
import _thread
import tqdm
import os
import rsa

# initializing the server connection
def initialize_server():
    global client_pubkey
    global prikey

    # generating public and private keys of atleast 1024 bits
    pubkey, prikey = rsa.newkeys(1024)

    # initialize the socket
    s = socket(AF_INET, SOCK_STREAM)

    # configure the details of the server
    host = 'localhost'
    port = 5000
    
    # bind the server to the socket
    s.bind((host, port))

    # setting 1 as the maximum number of queued 
    # connections that can be waiting to be accepted
    s.listen(1)
    print(f"-> Listening as {host}:{port}")

    # accepting the connection from client
    conn, addr = s.accept()
    print(f"-> {addr} is connected")

    # sending the server public key to the client in PEM format
    conn.send(pubkey.save_pkcs1("PEM"))

    # clearing the output buffer of the socket
    conn.send(b"\n")

    # receiving the public key of the client
    client_pubkey = rsa.PublicKey.load_pkcs1(conn.recv(4096))
    print("The client's public key is:\n")
    print(client_pubkey)

    # receiving client's choice for file transfer or for messaging
    ch = conn.recv(256).decode('utf-8')

    # clearing the input buffer of the socket
    while True:
        data = conn.recv(100).decode('utf-8')
        if data == "\n":
            break

    # returning the new socket object that represents the 
    # connection between the server and a specific client
    return s, conn, ch

# function to update the chatlog
def updateChat(msg, writtenBy):
    # declaring the global variable
    global chatlog

    # making the chatlog editable
    chatlog.config(state=NORMAL)

    # updating the message in the window
    if writtenBy == 0:
        # if the server has written the message
        chatlog.insert(END, 'Server: ' + msg) # writing the message in the end
    elif writtenBy == 1:
        # if the client has written the message
        chatlog.insert(END, 'Client: ' + msg)

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
    updateChat(msg, 0) # 0 implies the chatlog is updated as the server
                       # 1 implies the chatlog is updated as the receiver

    # encrypting the message to be sent with the client's public key
    encData = rsa.encrypt(msg.encode('utf-8'), client_pubkey)

    # print the encrypted data
    print(f"\nThe encrypted data is:\n{encData}")
    
    # send the messgae to the client
    conn.send(encData)

    # clearing the textbox
    textBox.delete("0.0", END)

# function to receive message
def receive():
    while 1:
        try:
            # receiving the encrypted data
            encData = conn.recv(1024) # 1024 bytes is the buffer size

            # decrypting the encrypted data with the server's private key
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
    gui.title("Server Chat")

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

    # receiving the file details using the client socket
    fileinfo = conn.recv(BUFFER_SIZE).decode()
    filename, filesize = fileinfo.split(SEPARATOR)

    # if filename has absolute path, we remove it
    filename = os.path.basename(filename) # this function returns the final component of a path name

    # converting file size to integer
    filesize = int(filesize)

    folder_name = "path\\of\\folder\\where\\files\\should\\be\\received"

    # receiving the file from the client socket and writing to the file stream
    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(os.path.join(folder_name, filename), "wb") as f: # this statement creates a file with the required file name
        while True:
            # reading 128 bytes at a time from the client socket
            bytes_received = conn.recv(128)
            if not bytes_received:
                # nothing is received, that means file transmitting is done
                break

            # decrypting the data with the server's private key
            decrypted_data = rsa.decrypt(bytes_received, prikey)
 
            # writing to the file the bytes we received
            f.write(decrypted_data)
        
            # updating the progress bar
            progress.update(len(bytes_received))

    # closing the client socket
    conn.close()
    # closing the server socket
    s.close()


if __name__ == '__main__':
    # making the variables globally accessible
    chatlog = textBox = prikey = client_pubkey = None
    BUFFER_SIZE = 4096
    SEPARATOR = "<SEPARATOR>"

    s, conn, ch = initialize_server()

    if ch == '1': # when client wants to use the chat application
        GUI()
    elif ch == '2': # when client wants to do file transfer
        fileTransfer()