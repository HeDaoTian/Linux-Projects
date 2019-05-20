#include <stdio.h> //Declarations used in most input and output operations;
#include <stdlib.h>
#include <sys/types.h> //Defines a number of data types used in system calls
#include <sys/socket.h> //Defines a number of structures needed for sockets;
#include <netinet/in.h> //Contains constants and structures needed for Internet domain addresses. 
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void error(char *msg) // Displays an error message on stderr and then aborts the program
{
    perror(msg);
    exit(1);
}

int str_cmp (char a[]) //Compares the message from the keyword "Bye!", return 0 if the message is "End Session"
{
    if (a[0] == 'E'){
        if(a[1] == 'n')
            if(a[2] == 'd')
                if (a[3] == ' ')
                    if(a[4] == 'S')
                        if(a[5] == 'e')
                            if(a[6] == 's')
                                if(a[7] == 's')
                                    if(a[8] == 'i')
                                        if(a[9] == 'o')
                                            if(a[10] == 'n')
                                                //if(a[11] == '\0')
                        return 0;
    }
    else
        return -1;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char *argv[])
{

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    unsigned char decryptedtext[128];

    int decryptedtext_len;

    int sockfd, newsockfd, portno, clilen;
    /* sockfd and newsockfd, are array subscripts into the file descriptor table. They store the values returned by the socket system call and the accept system call.portno stores the port number on which the server accepts connections.
		clilen stores the size of the address of the client, which is needed for the
		accept system call.
    */
    
    char buffer[256]; //The server reads characters from the socket connection into the buffer char.
    
    struct sockaddr_in serv_addr, cli_addr; //client and server address structures, using the sockaddr_ in Internet address structure. This structure is defined in netinet/in.h.
    
    int n; //The number of characters read or written by the read() and write() calls
    
    if (argc < 2) { //check that the user has provided a port number argument and displays an error message
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0); //Create new streaming IPV4 socket. 0 indicates default protocol, which is TCP. Returns file descriptor table entry
    
    if (sockfd < 0) //Checks for errors in the creation of the socket. A negative file descriptor table usually indicates an error.
        error("ERROR opening socket");
    
    bzero((char *) &serv_addr, sizeof(serv_addr)); //Set all values in a buffer to zero, bzero(buf_addr,buf_size)
    
    portno = atoi(argv[1]); //Retrieves the port no provided as a string and converts it to an integer
    serv_addr.sin_family = AF_INET; //Assign values to the variable serv_addr, which is a structure of type struct sockaddr_in
    serv_addr.sin_port = htons(portno); //Converts a port number in host byte order to a port number in network byte order.
    serv_addr.sin_addr.s_addr = INADDR_ANY; //IPv4 address of the server, which is obtained from the symbolic constant INADDR_ANY.
    
    if (bind(sockfd, (struct sockaddr *) &serv_addr, //Bind operation and error checking. Second parameter is cast into right type
    sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    
    listen(sockfd,5); //Socket listens for new connections. 2nd argument is the number of connections that can be waiting while the process is handling a particular connection
    
    clilen = sizeof(cli_addr);
    
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen); //Causes the process to block until a new client request comes in
    
    if (newsockfd < 0)
        error("ERROR on accept");
    
    int cmp; //Variable to hold the result of message checking
    do{
	bzero(decryptedtext,128);
        bzero(buffer,256); //Initialize buffer
        n = read(newsockfd,buffer,255); //Read up to 255 bytes into buffer. Returns no. of xters read. Blocks until client writes
              

        if (n < 0) error("ERROR reading from socket"); //Check for errors while reading
        //printf("Here is the ciphertext: %s\n",buffer); //Print message to stdout
	printf("Ciphertext is:\n");
  	BIO_dump_fp (stdout, (const char *)buffer, strlen((char *)buffer));

	printf("Its length: %d\n", strlen((char *)buffer));
	
	decryptedtext_len = decrypt(buffer, strlen((char *)buffer), key, iv, decryptedtext);
	
	decryptedtext[decryptedtext_len]='\0';

	printf("Here is the decrypted text: %s\n",decryptedtext); //Print message to stdout

        
        cmp = str_cmp(decryptedtext);//check if the message is "Bye!"
    
        n = write(newsockfd,"I got your message",18); //Acknowledge the message
        if (n < 0) error("ERROR writing to socket"); //Checks for errors in writing
    }while (cmp != 0); //Allow to receive an unlimited amount of messages if the message isn't "Bye!", otherwise exit

    return 0; //Terminates
}

