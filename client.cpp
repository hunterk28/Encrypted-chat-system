#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cmath>
#include <fstream>
using namespace std;

	int sock;

	int calc_mod(int alpha, int a, int p) 
	{
    	int result = 1;
    	alpha = alpha % p;
    	
    	for (int i = 0; i < a; i++) 
    	{
        	result = (result * alpha) % p;
    	}
    	
    	return result;
	}

	int diffie_client(int p, int alpha, int a) 
	{
    	int A, B, key;
    	
    	B = calc_mod(alpha, a, p);  	//Client's public key
    	send(sock, &B, sizeof(B), 0);  	//Send the public key to the server

    	recv(sock, &A, sizeof(A), 0);  	//Receive the server's public key

    	key = calc_mod(A, a, p);  
    	return key;
	}
	
	bool valid_email(const string& email)
	{
		int email_len = email.length();

    	if (email_len >= 10) 
    	{
        	if (strcmp(email.c_str() + email_len - 10, "@gmail.com") == 0) 
        	{
            	return false;
        	}
    	}
    	
    	cout << "\nInvalid Email Address! \n\nEnter email again:" << endl;
    	return true;
	}
	

	string aes_128_cbc_encrypt(const string& plaintext, unsigned char* key, unsigned char* iv) 
	{
    	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // Create a new encryption context

    	unsigned char ciphertext[128];
    	int len;
    	int ciphertext_len;

    	EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);  //Initialize encryption

    	EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext.c_str(), plaintext.length());  //Encrypt
    	ciphertext_len = len;

    	EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);  //Finalize encryption
    	ciphertext_len += len;

    	EVP_CIPHER_CTX_free(ctx);  //Clean up

    	return string((char*)ciphertext, ciphertext_len);  //Return ciphertext as string
	}
	
	string aes_128_cbc_decrypt(const string& ciphertext, unsigned char* key, unsigned char* iv) 
	{
    	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  //Create a new decryption context

    	unsigned char plaintext[128];
    	int len;
    	int plaintext_len;

    	EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);  //Initialize decryption

    	EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char*)ciphertext.c_str(), ciphertext.length());// Decrypt
    	plaintext_len = len;

    	EVP_DecryptFinal_ex(ctx, plaintext + len, &len);  //Finalize decryption
    	plaintext_len += len;

    	EVP_CIPHER_CTX_free(ctx);  //Clean up

    	return string((char*)plaintext, plaintext_len);  //Return decrypted plaintext as string
	}
	
	// Function to generate AES-128 key and IV
	void generate_aes_key_and_iv(int shared_secret, unsigned char* aes_key, unsigned char* iv) 
	{
    	memset(aes_key, 0, 16);  //Clear key
    	memcpy(aes_key, &shared_secret, sizeof(shared_secret));  //Pad shared secret to 16 bytes

    	RAND_bytes(iv, 16);  //Generate random IV
	}

	// Example function for client Diffie-Hellman, AES encryption and send
	void client_send_message(int sock, int shared_secret, string plaintext) 
	{
    	unsigned char aes_key[16];  //Aes key
    	unsigned char iv[16];       //IV for aes

    	generate_aes_key_and_iv(shared_secret, aes_key, iv);  //Generate key and IV

    	// Encrypt the message
    	string ciphertext = aes_128_cbc_encrypt(plaintext, aes_key, iv);

    	// Send the ciphertext and IV to the server   
     	send(sock, iv, 16, 0);  // Send IV first
     	send(sock, ciphertext.c_str(), ciphertext.length(), 0);  //Send ciphertext
	}
	
	/*void generate_aes_key_and_iv1(string shared_secret, unsigned char* aes_key, unsigned char* iv) 
	{
    	memset(aes_key, 0, 16);  //Clear key
    	memcpy(aes_key, &shared_secret, sizeof(shared_secret));  //Pad shared secret to 16 bytes

    	RAND_bytes(iv, 16);  //Generate random IV
	}*/
	
	void generate_aes_key_and_iv1(string shared_secret, unsigned char* aes_key, unsigned char* iv) 
{
    memset(aes_key, 0, 16);  // Clear key
    
    // Ensure the shared secret is not longer than 16 bytes to avoid overflow
    size_t copy_length = min(shared_secret.length(), (size_t)16);
    
    // Copy the shared secret content into the AES key buffer
    memcpy(aes_key, shared_secret.c_str(), copy_length);

    // Generate a random IV
    RAND_bytes(iv, 16);  
}

	// Example function for client Diffie-Hellman, AES encryption and send
	void client_send_message1(int sock, string shared_secret, string plaintext) 
	{
    	unsigned char aes_key[16];  //Aes key
    	unsigned char iv[16];       //IV for aes

    	generate_aes_key_and_iv1(shared_secret, aes_key, iv);  //Generate key and IV

    	// Encrypt the message
    	string ciphertext = aes_128_cbc_encrypt(plaintext, aes_key, iv);

    	// Send the ciphertext and IV to the server   
     	send(sock, iv, 16, 0);  // Send IV first
     	send(sock, ciphertext.c_str(), ciphertext.length(), 0);  //Send ciphertext
	}
	
	string client_receive_message(int sock, string shared_secret) 
	{
    	unsigned char aes_key[16];  //Aes key
    	unsigned char iv[16];       //IV for aes

    	generate_aes_key_and_iv1(shared_secret, aes_key, iv);  //Generate key and IV
    	
    	//char buf[256] = {0};
     	recv(sock, iv, 16, 0); //Receive IV
          
    	char buf[256] = {0};  //Clear buffer
    	recv(sock, buf, sizeof(buf), 0);
    	string ciphertext = buf;  

    	// Decrypt the message
    	string decryptedtext = aes_128_cbc_decrypt(ciphertext, aes_key, iv);
    	return decryptedtext;
    	
	}
	
	void client_reg(int sock, int shared_secret, char buf[256])
	{
			string email, username, pass;
			
			memset(buf, 0, 256);
        	recv(sock, buf, 256, 0);       	        
        	cout << "Server: " << buf << endl;
        
        	cout << "You (Client): ";
        	getline(cin, username);
        	client_send_message(sock, shared_secret, username);
       	
        	memset(buf, 0, 256);
        	recv(sock, buf, 256, 0);       	        
        	cout << "Server: " << buf << endl;
        	
        do
        {     
        	cout << "You (Client): ";
        	getline(cin, email);
        
        }while(valid_email(email));
        
        	client_send_message(sock, shared_secret, email);
        	
        	memset(buf, 0, 256);
        	recv(sock, buf, 256, 0);       	        
        	cout << "Server: " << buf << endl;
        
        	cout << "You (Client): ";
        	getline(cin, pass);
        	client_send_message(sock, shared_secret, pass);
        	
	}
	
	void client_login(int sock, int shared_secret, char buf[256])
	{
			string pass, username;
			
			memset(buf, 0, 256);
        	recv(sock, buf, 256, 0);       	        
        	cout << "Server: " << buf << endl;
        
        	cout << "You (Client): ";
        	getline(cin, username);
        	client_send_message(sock, shared_secret, username);
        	
        	memset(buf, 0, 256);
        	recv(sock, buf, 256, 0);       	        
        	cout << "Server: " << buf << endl;
        
        	cout << "You (Client): ";
        	getline(cin, pass);
        	client_send_message(sock, shared_secret, pass);
		
	}

	void create_socket() 
	{
    	// Create the socket
    	sock = socket(AF_INET, SOCK_STREAM, 0);
    
    	// Setup the address
    	struct sockaddr_in server_address;
    	server_address.sin_family = AF_INET;
    	server_address.sin_addr.s_addr = INADDR_ANY;
    	server_address.sin_port = htons(8080);
    
    	// Connect to the server
    	connect(sock, (struct sockaddr*)&server_address, sizeof(server_address));
	}

	int main() 
	{
		srand(time(NULL));
    	char buf[256];

    	int p = 23;  
    	int alpha = 5;  
    	
    	int flag = 0; 
    	int i=0;
    
    	

    	cout << "\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n";

    	// Create socket and connect to the server
    	create_socket();
		
     	   // Get user input and send it to the server
     	 do
     	 {  
  			i = 0;
     	   	flag = 0; 
     	   	
        	memset(buf, 0, 256);
        	recv(sock, buf, 256, 0);      
        	cout << "Server: " << buf << endl;
  			
        	cout << "You (Client): ";
        	string message;
        	getline(cin, message);
        
        	strcpy(buf, message.c_str());
        	send(sock, buf, sizeof(buf), 0);       

        	// If the client sends "exit", terminate the chat
        	
             
        	// Clear buffer and receive response from server
        	
        	if(message == "1")
        	{
        		int a = (rand()%18)+2;
        	
        		int shared_secret = diffie_client(p, alpha, a);
        		client_reg(sock, shared_secret, buf);
        		
        		flag = 1;
        		
        	}
        	else if(message == "2")
        		{
        			int a = (rand()%21)+2;
        			
        			int shared_secret = diffie_client(p, alpha, a);
        			
        			client_login(sock, shared_secret, buf);
        			memset(buf, 0, 256);
        			recv(sock, buf, 256, 0);	
        			cout << "Server: " << buf << endl;
        			
        			if (strcmp(buf,"\nIncorrect Username or Password\n")==0)
        			{
        				flag = 1;
            		}
            		else
            		{
            			flag = 0;
            			break;
            		}       			
        		
        		}
        		else
        		{
        			flag = 1;
        		}
        		
        	}while(flag == 1);
        	
        	int a = (rand()%21)+2;            		
        	int shared_secret = diffie_client(p, alpha, a);
        	
        	string user, email;		
			ifstream fin;
		
			fin.open("creds.txt", ios::in);
		
			getline(fin, email, ' '); 
			getline(fin, user, ' ');        		
   				
   			string final_key = to_string(shared_secret) + user;  				
   				
   			fin.close();
        		
        	while(true)
        	{
        		cout << "You (Client): ";
        		string texting;
            	getline(cin, texting);
        		client_send_message1(sock, final_key, texting);
        		
        		if (texting == "exit") 
                {
                    cout << "Client disconnected.\n";
                    break;
                }	
        		        		
        		cout << "Server: " << client_receive_message(sock,final_key) << endl;              	
        	}
        	
        

    	// Close the socket after communication
    	close(sock);

    	return 0;
	}

