#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <strings.h>
#include <sys/sendfile.h>
#include <dirent.h>
extern int errno;
// PORT number
#define PORT 4442
#define SIZE 1024
int remove_directory(char *path) {
   DIR *d = opendir(path);
   size_t path_len = strlen(path);
   int r = -1;

   if (d) {
      struct dirent *p;

      r = 0;
      while (!r && (p=readdir(d))) {
          int r2 = -1;
          char *buf;
          size_t len;

          /* Skip the names "." and ".." as we don't want to recurse on them. */
          if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
             continue;

          len = path_len + strlen(p->d_name) + 2; 
          buf = malloc(len);

          if (buf) {
             struct stat statbuf;

             snprintf(buf, len, "%s/%s", path, p->d_name);
             if (!stat(buf, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode))
                   r2 = remove_directory(buf);
                else
                   r2 = unlink(buf);
             }
             free(buf);
          }
          r = r2;
      }
      closedir(d);
   }

   if (!r)
      r = rmdir(path);

   return r;
}
void write_file(int sd,char* file_name)
{
  int n;
  FILE *fp;
  char buffer[SIZE];
  //opening the file with writing rights
  fp = fopen(file_name, "w");
  if (fp == NULL)
  {
    printf("File does not exists!\n");
  }
  int count = 0;
  //while we hava data to write 
  while (1)
  {
	//reading data from client
    if (read(sd, buffer, sizeof(buffer)) <= 0)
    {
      perror("[-]Error in receiving file.");
      break;
    }
	//if we are not at the EOF
    if (strcmp(buffer, "stop") == 0)
    {
      printf("\ngotta stop..\n");
      break;
    }
	//put the data into file
    fprintf(fp, "%s", buffer);
    count += 1;
    bzero(buffer, SIZE);
  }
  fclose(fp);
}
char *read_file(char *filename)
{
	FILE *file;

	// attempt to open the file in read mode
	file = fopen(filename, "r");

	// if the file fails to open, return NULL as an error return value
	if (file == NULL)
		return NULL;

	// move the file pointer to the end of the file
	fseek(file, 0, SEEK_END);

	// fseek(file) will return the current value of the position indicator,
	// which will give us the number of characters in the file
	int length = ftell(file);

	// move file pointer back to start of file so we can read each character
	fseek(file, 0, SEEK_SET);

	// dynamically allocate a char array to store the file contents, we add 1 to
	// length for the null terminator we will need to add to terminate the string
	char *string = malloc(sizeof(char) * (length + 1));

	// c will store each char we read from the string
	char c;

	// i will be an index into the char array string as we read each char
	int i = 0;

	// keep reading each char from the file until we reach the end of the file
	while ((c = fgetc(file)) != EOF)
	{
		// store char into the char array string
		string[i] = c;

		// increment i so we store the next char in the next index in the char array
		i++;
	}

	// put a null terminator as the final char in the char array to properly
	// terminate the string
	string[i] = '\0';

	// close the file as we are now done with it
	fclose(file);

	// return a pointer to the dynamically allocated string on the heap
	return string;
}
char *get_content_of_ls(char *filename)
{
	char *temporary;
	temporary = (char *)malloc(256 * sizeof(char));
	strcpy(temporary, &filename[4]);

	//deleting the file after getting the result of ls
	char *content_of_file = read_file(temporary);
	remove(temporary);

	return content_of_file;
}
char *get_ls_filename_from_username(char *username)
{
	char *temporary;
	temporary = (char *)malloc(256 * sizeof(char));
	strcpy(temporary, " ls>");
	strcat(temporary, username);
	strcat(temporary, ".txt");

	return temporary;
}
int check_credentials(char **credentials)
{
	MYSQL *conn;
	MYSQL_RES *res;
	MYSQL_ROW row;
	char *server_db = "localhost";
	char *user = "andrei";
	char *password_db = "andreib1234";
	char *database = "accounts";
	conn = mysql_init(NULL);

	if (!mysql_real_connect(conn, server_db, user, password_db,
							database, 0, NULL, 0))
	{
		fprintf(stderr, "%s\n", mysql_error(conn));
		exit(1);
	}

	char query[100];
	strcpy(query, "select count(*) from account where username='");
	strcat(query, credentials[0]);
	strcat(query, "' and password ='");
	strcat(query, credentials[1]);
	strcat(query, "' and blacklisted = 0;");

	if (mysql_query(conn, query))
	{
		fprintf(stderr, "%s\n", mysql_error(conn));
		exit(1);
	}
	res = mysql_use_result(conn);
	row = mysql_fetch_row(res);
	if (strcmp(row[0], "1") == 0)
	{
		printf("User %s logged in succesfully!\n", credentials[0]);
		return 1;
	}
	else
	{
		printf("User tried and failed to login with username %s and password %s!\n", credentials[0], credentials[1]);
		return 0;
	}
}
char *decrypt_password(char *encrypted_password, int key)
{
	for (int i = 0; i < strlen(encrypted_password); i++)
	{
		encrypted_password[i] += key;
	}
	return encrypted_password;
}
char **extract_credentials(char *credentials)
{
	char **temporary = malloc(2 * sizeof(char *));
	int i;
	for (i = 0; i < 3; ++i)
	{
		temporary[i] = (char *)malloc(sizeof(credentials) + 1);
	}
	char *pointer;
	pointer = strtok(credentials, " ");
	i = 0;
	while (pointer != NULL)
	{
		temporary[i++] = pointer;
		pointer = strtok(NULL, " ");
	}
	char *decrypted_password;
	decrypted_password = (char *)malloc(strlen(temporary[1]) * sizeof(char));
	//decrypting the password using the key received via socket
	strcpy(decrypted_password, decrypt_password(temporary[1], atoi(temporary[2])));
	strcpy(temporary[1], decrypted_password);
	return temporary;
}
char *get_filename_for_pwd(char *username)
{
	char *temporary;
	temporary = (char *)malloc(256 * sizeof(char));
	strcpy(temporary, " pwd>");
	strcat(temporary, username);
	strcat(temporary, ".txt");

	return temporary;
}
char *get_content_of_pwd(char *filename)
{
	char *temporary;
	temporary = (char *)malloc(256 * sizeof(char));
	strcpy(temporary, &filename[5]);

	char *content_of_file = read_file(temporary);
	remove(temporary);

	return content_of_file;
}
void send_file(FILE *fp, int clientSocket)
{
	int n;
	char data[SIZE] = {0};
	int count = 0;
	//while we have data to send
	while (1)
	{
		//reading data from file
		if (fgets(data, SIZE, fp) != NULL)
		{
			//if there is still data to send, send it
			if (write(clientSocket, data, sizeof(data)) == -1)
			{
				perror("[-]Error in sending file.");
				break;
			}
			printf("%d-%s", count, data);
			bzero(data, SIZE);
			count += 1;
		}
		else
		{
			printf("\nend of file\n");
			bzero(data, SIZE);
			strcpy(data, "stop");
			if (write(clientSocket, data, sizeof(data)) == -1)
			{
				perror("[-]Error in sending file.");
				break;
			}
			break;
		}
	}
}
int main()
{
	// Server socket id
	int sockfd, ret;

	// Server socket address structures
	/*
	struct sockaddr_in{
		short int sin_family;  familia de adrese (AF_INET) 
		unsigned short int sin_port;  portul (0-65355) 
		struct in_addr sin_addr;  adresa Internet 
		unsigned char sin_zero[8]; bytes neutilizați (zero) 
	}
	struct in_addr{
		unsigned long int s_addr  4 bytes ai adresei IP 
	}
	*/
	struct sockaddr_in serverAddr;

	// Client socket id
	int clientSocket;

	int connection_on = 1;

	char msg[256];

	// Client socket address structures
	struct sockaddr_in cliAddr;

	// Stores byte size of server socket address
	socklen_t addr_size;

	// Child process id
	pid_t childpid;

	// Creates a TCP socket id from IPV4 family
	// AF_INET = communication domanin
	// SOCK_STREAM = socket types(ways to accomplish the communication) (TCP FOR SOCKET_STREAM)
	// 0 = the protocol used for transmission
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// Error handling if socket id is not valid
	if (sockfd < 0)
	{
		printf("Error in connection.\n");
		exit(1);
	}

	printf("Server Socket is created.\n");

	// Initializing address structure with NULL
	memset(&serverAddr, '\0',
		   sizeof(serverAddr));

	// Assign port number and IP address
	// to the socket created


	serverAddr.sin_family = AF_INET;
	//HTONS function converts unsigned short integer  from host byte order to network byte order.
	serverAddr.sin_port = htons(PORT);

	// 127.0.0.1 is a loopback address
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	// Binding the socket id with
	// the socket structure
	// Asocierea socketului cu o adresa
	ret = bind(sockfd,
			   (struct sockaddr *)&serverAddr,
			   sizeof(serverAddr));

	// Error handling
	if (ret < 0)
	{
		printf("Error in binding.\n");
		exit(1);
	}

	// Listening for connections (upto 10)
	// The system core will wait for connection requests directed to the address where the socket is attached
	if (listen(sockfd, 10) == 0)
	{
		printf("Listening...\n\n");
	}
	char *message_from_client;
	message_from_client = (char *)malloc(256 * sizeof(char));

	char *message_to_client;
	message_to_client = (char *)malloc(256 * sizeof(char));
	FILE *fp;
	int cnt = 0;
	int logged_in = 0;
	char **credentials;
	while (1)
	{

		// Accept clients and
		// store their information in cliAddr
		// accepting incoming connection, return the socket descriptor corrsesponding
		// creates new socket that will be used to send/recv data
		// to the client end-point or -1 if error
		clientSocket = accept(
			sockfd, (struct sockaddr *)&cliAddr,
			&addr_size);

		// Error handling
		if (clientSocket < 0)
		{
			exit(1);
		}

		// Displaying information of
		// connected client
		printf("Connection accepted from %s:%d\n",
			   inet_ntoa(cliAddr.sin_addr),
			   ntohs(cliAddr.sin_port));

		// Print number of clients
		// connected till now
		printf("Clients connected: %d\n\n",
			   ++cnt);

		// Creates a child process
		// fork creates a new child process, a copy of the parrent process
		// creating a child procces to handle clients concurent
		// 1 child proces -> 1 client
		if ((childpid = fork()) == 0)
		{

			// Closing the server socket id
			close(sockfd);
			
			//read is used for reading from a tcp socket
			//read is usually a blocking call
			//retrieveing the credentials from client
			if (read(clientSocket, msg, 100) < 0)
			{
				perror("[client]Eroare la read() de la server.\n");
				return errno;
			}
			//preparng credentials for a easier verifiy
			credentials = extract_credentials(msg);
			//checking that credentials match an available account from DB
			//1 - account ok 0 otherwise
			int logged_in = check_credentials(credentials);
			if (logged_in == 1)
			{
				//write sends data via tcp socket
				//write is usually blocking call
				//sending the approval conn to the client
				if (write(clientSocket, "Acces granted!", 256) <= 0)
				{
					perror("[client]Eroare la write() spre server.\n");
					return errno;
				}
				//client handling while conn is on
				while (1)
				{
					//retrieveing the command number from client
					memset(message_from_client, 0, 256);
					read(clientSocket, message_from_client, 256);

					printf("Client send the command with number:%s\n", message_from_client);
					//handling the command
					if (strcmp(message_from_client, "1") == 0)
					{
						char *filename;
						filename = (char *)malloc(256 * sizeof(char));
						//preparing the command
						//name of file -> username of the client
						strcpy(filename, get_ls_filename_from_username(credentials[0]));
						//executing the command
						system(filename);

						memset(message_to_client, 0, 256);
						strcpy(message_to_client, get_content_of_ls(filename));
						//sending the result of ls command back to client
						write(clientSocket, message_to_client, 256);
					}
					else if (strcmp(message_from_client, "2") == 0)
					{
						//reading the folder name from client
						memset(message_from_client, 0, 256);
						read(clientSocket, message_from_client, 256);
						memset(message_to_client, 0, 256);
						//changing the directory
						if (chdir(message_from_client) == 0)
						{
							strcpy(message_to_client, "1");
						}
						else
						{
							strcpy(message_to_client, "0");
						}
						//sending 1 for cd succesfully, 0 otherwise
						write(clientSocket, message_to_client, 256);
					}
					else if (strcmp(message_from_client, "3") == 0)
					{
						//reading the file name clients wants to download
						memset(message_from_client, 0, 256);
						read(clientSocket, message_from_client, 256);
						char *file_to_send;
						file_to_send = (char *)malloc(256 * sizeof(char));

						strcpy(file_to_send, message_from_client);
						//opening the file
						FILE *fp1;
						
						fp1 = fopen(file_to_send, "r");
						if (fp1 == NULL)
						{
							memset(message_to_client, 0, 256);
							strcpy(message_to_client,"Failed!");
							write(clientSocket,message_to_client,256);
							
						}
						else
						{
							memset(message_to_client, 0, 256);
							strcpy(message_to_client,"Success!");
							write(clientSocket,message_to_client,256);

							printf("%s\n", message_from_client);
							//sendig the file
							send_file(fp1, clientSocket);
							//  printf("File sended!");
							fclose(fp1);
						}
					}
					else if (strcmp(message_from_client,"4") == 0)
					{
						//name of file to put to server
						memset(message_from_client, 0, 256);
						read(clientSocket, message_from_client, 256);
						char *file_to_upload;
						file_to_upload = (char *)malloc(256 * sizeof(char));

						strcpy(file_to_upload, message_from_client);
						printf("%sName of file to be uploaded to server:\n",file_to_upload);
						//creating the file on server
						write_file(clientSocket,file_to_upload);
						 
					}
					else if (strcmp(message_from_client, "5") == 0)
					{
						char *file_name;
						file_name = (char *)malloc(256 * sizeof(char));
						//creaing the file where the result of pwd will be put
						strcpy(file_name, get_filename_for_pwd(credentials[0]));
						//executing the command
						system(file_name);

						memset(message_to_client, 0, 256);
						strcpy(message_to_client, get_content_of_pwd(file_name));
						//sending the result to client
						write(clientSocket, message_to_client, 256);
					}
					else if (strcmp(message_from_client, "6") == 0)
					{
						//break the while loop that keeps the comm on
						// setting the logged_in to 0 because client disconnected
						// so that child procces to end
						logged_in = 0;
						memset(message_to_client, 0, 256);
						printf("Client %s disconnected succesfully!", credentials[0]);
						strcpy(message_to_client, "Quit succesfully!");
						write(clientSocket, message_to_client, 256);
						break;
					}
					else if (strcmp(message_from_client, "7") == 0)
					{
						//reading the folder name from client
						memset(message_from_client,0,256);
						read(clientSocket,message_from_client,256);
						char *name_of_directory;
						name_of_directory = (char *)malloc(256 * sizeof(char));

						strcpy(name_of_directory, message_from_client);

						//creating the folder
						//check the result of mkdir
						int check;
						check = mkdir(name_of_directory,0777);
						memset(message_to_client,0,256);
						//sending the message to client
						if (!check){
							strcpy(message_to_client,"Directory created succesfully!");
						}
						else {
							strcpy(message_to_client,"Directory created unsuccesfully!");
						}
						write(clientSocket,message_to_client,256);

					}
					else if (strcmp(message_from_client, "8") == 0)
					{
						//reading the name of the folder wants to delete
						memset(message_from_client,0,256);
						read(clientSocket,message_from_client,256);

						//formating the path string
						// in order to contain the path to the folder to be deleted
						char *name_of_directory;
						name_of_directory = (char *)malloc(256 * sizeof(char));
						strcpy(name_of_directory,message_from_client);



						char* path;
						path = (char *)malloc(256 * sizeof(char));
						memset(path,0,256);

						char *file_name;
						file_name = (char *)malloc(256 * sizeof(char));
						memset(file_name,0,256);

						strcpy(file_name, get_filename_for_pwd(credentials[0]));
						system(file_name);
						strcpy(path, get_content_of_pwd(file_name));

						path[strlen(path)-1]='\0';
						strcat(path,"/");
						strcat(path,name_of_directory);
						printf("%s\n",path);

						//remove_directory functions needs the full path
						//in order to delete the folder
						int check = remove_directory(path);

						printf("%d\n",check);
						memset(message_to_client, 0, 256);

						if(check == -1)
						{
							strcpy(message_to_client,"Folder does not exists!!\n");
						}					
						else
						{
							strcpy(message_to_client,"Folder deleted succesfully!\n");
						}
						write(clientSocket,message_to_client,256);

					}	
				}
			}
			// if the credentials don't match an existing account
			// or an blacklisted account, sending the declined message
			else
			{
				if (write(clientSocket, "Acces declined!", 256) <= 0)
				{
					perror("[client]Eroare la write() spre server.\n");
					return errno;
				}
			}
		}
	}

	// Close the client socket id
	close(clientSocket);
	return 0;
}
