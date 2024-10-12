#include <iostream>
#include <iomanip>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cmath>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstdlib>
#include <fstream>
#include <openssl/sha.h>
#include <regex>
#include <ctime>


using namespace std;

	//int client_socket;

	int calc_mod(int alpha, int b, int p)
	{
		int result = 1;
    	alpha = alpha % p;
    	
    	for (int i = 0; i < b; i++)
    	{
        	result = (result * alpha) % p;
   		}
   		
    	return result;	
	}
	
	int diffie_server(int client_socket, int p, int alpha, int b)
	{
		int A, B, key;
		
		A = calc_mod(alpha, b, p);
		send(client_socket, &A, sizeof(A), 0);

		recv(client_socket, &B, sizeof(B), 0);
		
		key = calc_mod(B, b, p);
		return key;
		
	}
	
	int diffie_server2(int client_socket, int p, int alpha, int b)
	{
		int A, B, key;
		
		recv(client_socket, &B, sizeof(B), 0);

		A = calc_mod(alpha, b, p);
		send(client_socket, &A, sizeof(A), 0);
				
		key = calc_mod(B, b, p);
		return key;		
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

	// Function to generate AES-128 key and IV
	void generate_aes_key_and_iv(int shared_secret, unsigned char* aes_key, unsigned char* iv) 
	{
    	memset(aes_key, 0, 16);  // Clear key
    	memcpy(aes_key, &shared_secret, sizeof(shared_secret));  //Pad shared secret to 16 bytes
	}

	// Example function for server Diffie-Hellman, AES decryption and receive
	string server_receive_message(int client_socket, int shared_secret) 
	{
    	unsigned char aes_key[16];  //Aes key
    	unsigned char iv[16];       //IV for aes

    	generate_aes_key_and_iv(shared_secret, aes_key, iv);  //Generate key and IV
    	
    	//char buf[256] = {0};
     	recv(client_socket, iv, 16, 0); //Receive IV    
     
    	char buf[256] = {0};  //Clear buffer
    	recv(client_socket, buf, sizeof(buf), 0);
    	string ciphertext = buf;  

    	// Decrypt the message
    	string decryptedtext = aes_128_cbc_decrypt(ciphertext, aes_key, iv);
    	return decryptedtext;
    	
	}
	
	/*void generate_aes_key_and_iv1(string shared_secret, unsigned char* aes_key, unsigned char* iv) 
	{
    	memset(aes_key, 0, 16);  // Clear key
    	memcpy(aes_key, &shared_secret, sizeof(shared_secret));  //Pad shared secret to 16 bytes
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

	// Example function for server Diffie-Hellman, AES decryption and receive
	string server_receive_message1(int client_socket, string shared_secret) 
	{
    	unsigned char aes_key[16];  //Aes key
    	unsigned char iv[16];       //IV for aes

    	generate_aes_key_and_iv1(shared_secret, aes_key, iv);  //Generate key and IV
    
     	recv(client_socket, iv, 16, 0); //Receive IV
          
    	char buf[256] = {0};  //Clear buffer
    	recv(client_socket, buf, sizeof(buf), 0);
    	    	
    	string ciphertext = buf;  

    	// Decrypt the message
    	string decryptedtext = aes_128_cbc_decrypt(ciphertext, aes_key, iv);
    	return decryptedtext;
    	
	}	
	
	void server_send_message(int client_socket, string shared_secret, string plaintext) 
	{
    	unsigned char aes_key[16];  //Aes key
    	unsigned char iv[16];       //IV for aes

    	generate_aes_key_and_iv1(shared_secret, aes_key, iv);  //Generate key and IV

    	// Encrypt the message
    	string ciphertext = aes_128_cbc_encrypt(plaintext, aes_key, iv);

    	// Send the ciphertext and IV to the server   
     	send(client_socket, iv, 16, 0);  // Send IV first
     	send(client_socket, ciphertext.c_str(), ciphertext.length(), 0);  //Send ciphertext
	}
	
	string salt_generate()
	{
		int length = 4;
		
		unsigned char salt[4];
		RAND_bytes(salt, sizeof(salt));
		
		stringstream ss;
    	for (int i = 0; i < length; ++i) 
    	{
        	ss << hex << setw(2) << setfill('0') << (int)salt[i];
    	}

    	return ss.str();
	}
	
	string hashing(const string& password, const string& salt)
	{
		string combined = password + salt;  					// Combine password and salt
    	unsigned char hash[SHA256_DIGEST_LENGTH];  				// Array to hold the hash
    	SHA256(reinterpret_cast<const unsigned char*>(combined.c_str()), combined.size(), hash);  // Compute SHA-256 hash

    	ostringstream oss;
    	for (unsigned char c : hash) 
    	{
        	oss << hex << setw(2) << setfill('0') << (int)c;  // Convert hash to hexadecimal string
    	}
    	
    	return oss.str();
	}
	
	bool username_exist(const string& username) 
	{
    	ifstream fin;
		
		fin.open("creds.txt", ios::in);
		string line;
		
		regex pattern(username);           	//Create regex pattern from the username
		
		while(getline(fin, line))
		{
			if(regex_search(line, pattern))
			{
				fin.close();
				return true;		      	//Username exist
			}
		}
		
		fin.close();
		return false;		
	}
	
		
	bool registeration(const string& email, const string& username, const string& password)
	{
		if (username_exist(username)) 
		{
        	return true;  
    	}
		
		
		string salt = salt_generate();
		string hashed_password = hashing(password, salt);
						
		ofstream fout;
		fout.open("creds.txt", ios::app);
		
    	fout << email << " " << username << " " << hashed_password << " " << salt << "\n";
    	
    	fout.close();
    	
        return false;					
	}
	

	bool login(const string& username, const string& password)
	{
		string user, email, pass, salt;		
		ifstream fin;
		
		fin.open("creds.txt", ios::in);
		
		while(getline(fin, email, ' ') ,getline(fin, user, ' '), getline(fin, pass, ' '), getline(fin,salt, '\n'))
        {        	
	        if(username == user)                   //Comparining ID and Password.
          	{
          		string hashed_pass = hashing(password, salt);
          	
          		if(hashed_pass == pass)
          		{
          			fin.close();
  	           		return true; 
          		} 		
          	}
      	}      	
      	fin.close();
      	return false;      			
	}
	
	void register_login(int client_socket, char buf[256], char message[256])
	{	
    	
    	int p = 23;
    	int alpha = 5;
    	
    	int flag; 
    	int i;
    	
    	do
    	{
    		cout << "Hello" << endl;
			flag = 0;
			i = 0;
			string x = "\nEnter:\n\n1.Register\n2.Login\n";
			strcpy(message, x.c_str());
			send(client_socket, message, strlen(message), 0);
    	
    		memset(buf, 0, 256);
        	recv(client_socket, buf, 256, 0); 
        	string choice = buf;
    		cout << "Client: " << buf << endl;
   
   		if(choice == "1")
   		{
   			int b = (rand()%20)+2;
   			
   			int key = diffie_server(client_socket, p, alpha, b);
   			string password, email, username;
    	
    		//cout << "You (Server): ";
    		string response = "Enter username:";
    		strcpy(message, response.c_str()); 
    		send(client_socket, message, strlen(message), 0);
    	
			username = server_receive_message(client_socket, key);						//Receiving message from client and decrypting it
		
			//cout << "You (Server): ";
    		string r_email = "Enter email:";
    		strcpy(message, r_email.c_str()); 
    		send(client_socket, message, strlen(message), 0);
    	
			email = server_receive_message(client_socket, key);						//Receiving message from client and decrypting it
		
			//cout << "You (Server): ";
    		string r_pass = "Enter password:";
    		strcpy(message, r_pass.c_str()); 
    		send(client_socket, message, strlen(message), 0);
    	
			password = server_receive_message(client_socket,key);
    		
			if(registeration(email, username, password))
			{
				string error_message = "\nUsername already exists\n";
        		send(client_socket, error_message.c_str(), error_message.size(), 0);
        		
        		flag = 1;
			}
			else
			{
				string error_message = "\nRegisteration Successful\n";
        		send(client_socket, error_message.c_str(), error_message.size(), 0);
        	
        		flag = 1;
			}
		}
		else if(choice == "2")
			{							
				int b = (rand()%18)+2;
   			
   				int key = diffie_server(client_socket, p, alpha, b);
   				string password, username;
   				
   				string response = "Enter username:";
    			strcpy(message, response.c_str()); 
    			send(client_socket, message, strlen(message), 0);
    	
				username = server_receive_message(client_socket, key);	
				
				string r_pass = "Enter password:";
    			strcpy(message, r_pass.c_str()); 
    			send(client_socket, message, strlen(message), 0);
    	
				password = server_receive_message(client_socket, key);	
				
				if(login(username, password))
				{
					i = 0;
					
					string error_message = "\nLogin Successful\n";
        			send(client_socket, error_message.c_str(), error_message.size(), 0);
					
					break;
        			
				}
				else
				{
					i = 1;
					
					string error_message = "\nIncorrect Username or Password\n";
        			send(client_socket, error_message.c_str(), error_message.size(), 0);
    		        			
				}
   				
			}
			else
			{
				flag = 1;
				i = 1;
			}
			
		
		}while(flag == 1 || i == 1);
		
		return;					
	}
	
	//void server_chat(int client_socket, char buf[256], char message[256])
	//{
		
	//}

int main() 
{
	srand(time(NULL));
    char buf[256];
    char message[256];
    
    int p = 23;
    int alpha = 5;
    
    cout << "\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n";
    
    // create the server socket
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    // define the server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // bind the socket to the specified IP and port
    bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    listen(server_socket, 5);

    while (1) {
        // accept incoming connections
        int client_socket;
        client_socket = accept(server_socket, NULL, NULL);

        // create a new process to handle the client
        pid_t new_pid;
        new_pid = fork();
        if (new_pid == -1) 
        {
            // error occurred while forking
            cout << "Error! Unable to fork process.\n";
        } 
        else if (new_pid == 0) 
        {
            // child process handles the client
            
          	 register_login(client_socket, buf, message);

            	int b = (rand()%20)+2;
   				int normal_key = diffie_server2(client_socket, p, alpha, b);

   				
   				string user, email, pass, salt;		
				ifstream fin;
		
				fin.open("creds.txt", ios::in);
		
				getline(fin, email, ' '); 
				getline(fin, user, ' ');        		
   				
   				string final_key = to_string(normal_key) + user;  				
   				
   				fin.close();

			while (true) 
            {  
                        	
            	string chat = server_receive_message1(client_socket,final_key);
            	cout << "Client: " << chat << endl;
            	
            	if (chat == "exit") 
                {
                    cout << "Client disconnected.\n";
                    break;
                }	
            	
            	cout << "You (Server): ";
            	string response;
            	getline(cin, response);
        		server_send_message(client_socket, final_key, response);
                            	
                
            }

            // Close the client socket after communication
            close(client_socket);
            exit(0);
        }        
        else 
        {
            // parent process continues accepting clients
            close(client_socket);
        }
    }

    close(server_socket);

    return 0;
}
