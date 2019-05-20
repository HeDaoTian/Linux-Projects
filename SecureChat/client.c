#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> //Defines the structure hostent
#include <string.h>
#include <unistd.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


void error(char *msg) //Same error function as in server
{
    perror(msg);
    exit(0);
}

int str_cmp (char a[]) //Compares the message from the keyword "bye", return 0 if the message is "End Session"
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

    int ciphertext_len;
    unsigned char ciphertext[128];

    int sockfd, portno, n;
    struct sockaddr_in serv_addr; //The address of the server that client wants to connect to
    struct hostent *server; //Defines the variable server as a pointer to a structure of type hostent
    char buffer[256];
    
    if (argc < 3)
    {
        fprintf(stderr,"usage %s hostname port\n", argv[0]);
        exit(0);
     }
    
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (sockfd < 0)
        error("ERROR opening socket");
    
    server = gethostbyname(argv[1]); //Client attempts to get the hostent structure for the server
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    
    bzero((char *) &serv_addr, sizeof(serv_addr)); //Initialize serv_addr
    serv_addr.sin_family = AF_INET; //Set the fields in serv_addr
    bcopy((char *)server->h_addr, //void bcopy(char *s1, char *s2, int length). server->h_addr is a character string,
          (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);
    serv_addr.sin_port = htons(portno);
    
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) //Connect to server. function returns 0 on success and âˆ’1 on failure
         error("ERROR connecting");
    
    int cmp;
    
    do{
        printf("Please enter the message: "); //Prompt user for message after connection is successful
        bzero(buffer,256); //Initialize buffer
        fgets(buffer,255,stdin); //Read from stdin into buffer

        
        
        cmp = str_cmp(buffer);

        /* Encrypt the plaintext */
        ciphertext_len = encrypt (buffer, strlen ((char *)buffer), key, iv, ciphertext);	
	
	printf("Here is the ciphertext length: %d\n",ciphertext_len);
        n = write(sockfd,ciphertext,ciphertext_len); //Write buffer into socket. Returns number of characters written
    
        if (n < 0) //Check for writing errors
            error("ERROR writing to socket");
    
        bzero(buffer,256);
        n = read(sockfd,buffer,255); //Reads servers response into buffer
 
               

        if (n < 0)
            error("ERROR reading from socket");
        printf("%s\n",buffer); //Prints servers response to screen
    }while (cmp != 0); //Allow to send an unlimited amount of messages if the message isn't "Bye!", otherwise exit
    return 0; //Exit
}

