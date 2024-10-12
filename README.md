# Encrypted-chat-system
This project implements a secure client-server chat application using Diffie-Hellman key exchange for secure key generation and AES-128-CBC encryption for secure message transmission. The communication between the client and server is encrypted to ensure confidentiality and integrity of messages.
## Features:
### Diffie-Hellman Key Exchange:
The client and server perform a Diffie-Hellman key exchange to generate a shared secret key. This key is used to encrypt and decrypt messages between the client and server.
### AES-128 Encryption:
The application uses AES-128 encryption in CBC (Cipher Block Chaining) mode to securely encrypt messages. The shared secret key from the Diffie-Hellman exchange is used as the AES encryption key.
### Secure Communication:
After key exchange, all messages are encrypted before transmission and decrypted upon reception, ensuring end-to-end security.
### Registration and Login:
The server allows clients to register and login, verifying usernames and passwords before entering into the chat mode.
### Multiple Clients Support:
The server uses forking to support multiple clients simultaneously. Each client establishes a separate, secure session with the server.
## Components:
### Client:
Initiates a connection with the server, performs the Diffie-Hellman key exchange, and encrypts messages using AES before sending them to the server.
### Server:
Accepts client connections, participates in the key exchange, and handles encrypted messages from multiple clients simultaneously. It decrypts incoming messages and responds securely.
## Technologies Used:
#### C++ Sockets: For network communication between the client and server.
#### AES-128-CBC Encryption: To encrypt and decrypt messages securely.
#### Diffie-Hellman Key Exchange: To generate a shared secret between the client and server.
## Prerequisites:
#### OpenSSL or Crypto++: The application assumes the use of a library like OpenSSL for AES encryption and decryption.
#### GCC/G++: For compiling the C++ code.
## How to Use:
#### Clone the repository:
git clone https://github.com/your-repo-name/encrypted-chat.git
#### Compile the client and server programs:
g++ -o client client.cpp -lssl -lcrypto
g++ -o server server.cpp -lssl -lcrypto
#### Start the server:
./server
#### Run the client in a separate terminal:
./client
###### Follow the prompts to either register or login and start a secure chat.
