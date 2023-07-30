#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <strings.h>
#define SIZE 1024
extern int errno;
void send_file(FILE *fp, int clientSocket)
{
	int n;
	char data[SIZE] = {0};
	int count = 0;
	while (1)
	{
		if (fgets(data, SIZE, fp) != NULL)
		{
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
void display_meniu()
{
  printf("Choose your command:\n");
  printf("1.List subdirectories(ls)\n");
  printf("2.Change directory(cd)\n");
  printf("3.Download\n");
  printf("4.Upload\n");
  printf("5.Print working directory(pwd)\n");
  printf("6.Quit\n");
  printf("7.Create directory(mkdir)\n");
  printf("8.Remove directory(rmdir)\n");
  printf("Your command:");
}
char *crypt_password(char *password, int key)
{
  for (int i = 0; i < strlen(password); i++)
  {
    password[i] -= key;
  }
  return password;
}
char *format_credentials(char *username, char *password)
{

  printf("Username:");
  scanf("%s", username);
  printf("You entered the username:%s\n", username);

  printf("Password:");
  scanf("%s", password);
  printf("You entered the password:%s\n", password);

  char *temporary;
  temporary = (char *)malloc((strlen(username) + strlen(password) * 2) * sizeof(char));

  strcpy(temporary, username);
  strcat(temporary, " ");

  int key = rand() % 21;
  char int_str[20];
  sprintf(int_str, "%d", key);

  char *crypted_password;
  crypted_password = (char *)malloc(strlen(password) * sizeof(char));
  strcpy(crypted_password, crypt_password(password, key));

  strcat(temporary, crypted_password);
  strcat(temporary, " ");

  strcat(temporary, int_str);
  return temporary;
}
void write_file(int sd,char* file_name)
{
  int n;
  FILE *fp;
  char buffer[SIZE];

  fp = fopen(file_name, "a+");
  if (fp == NULL)
  {
    printf("No such file!");
   
  }
  int count = 0;
  while (1)
  {
    if (read(sd, buffer, sizeof(buffer)) <= 0)
    {
      perror("[-]Error in receiving file.");
      break;
    }
    if (strcmp(buffer, "stop") == 0)
    {
      printf("\ngotta stop..\n");
      break;
    }
    fprintf(fp, "%s", buffer);
    printf("%d-%s", count, buffer);
    count += 1;
    bzero(buffer, SIZE);
  }
  fclose(fp);
}
int main(int argc, char *argv[])
{
  int sd, port;
  // descriptorul de socket
  struct sockaddr_in server;                         // structura folosita pentru conectare
  char username[20], password[20], credentials[100]; // username, password si credentiale(cele doua)
  char directory[15];
  char *f;

  char *message_from_server;
  message_from_server = (char *)malloc(256 * sizeof(char));

  char *command_number;
  command_number = (char *)malloc(10 * sizeof(char));

  char *message_to_server;
  message_to_server = (char *)malloc(256 * sizeof(char));

  int access = 0; // 0 - utilizator nelogat , 1 altfel
  int connection_on = 1;
  FILE *fp;

  int size;
  /* exista toate argumentele in linia de comanda? */
  if (argc != 3)
  {
    printf("[client] Sintaxa: %s <adresa_server> <port>\n", argv[0]);
    return -1;
  }

  /* stabilim portul */
  port = atoi(argv[2]);

  /* cream socketul */
  if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    perror("[client] Eroare la socket().\n");
    return errno;
  }

  /* umplem structura folosita pentru realizarea conexiunii cu serverul */
  /* familia socket-ului */
  server.sin_family = AF_INET;
  /* adresa IP a serverului */
  server.sin_addr.s_addr = inet_addr(argv[1]);
  /* portul de conectare */
  server.sin_port = htons(port);

  /* ne conectam la server */
  if (connect(sd, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
  {
    perror("[client]Eroare la connect().\n");
    return errno;
  }
  //while the client is connected we have exchange of data
  while (connection_on == 1)
  {
    //client not connected
    if (access == 0)
    {
      //formating the credentials
      strcpy(credentials, format_credentials(username, password));
      //sending the credentials 
      if (write(sd, credentials, sizeof(credentials)) <= 0)
      {
        perror("[client]Eroare la write() spre server.\n");
        return errno;
      }
      //reading the response
      if (read(sd, message_from_server, 256) <= 0)
      {
        perror("[client]Eroare la write() spre server.\n");
        return errno;
      }
      //1-access granted
      if (strcmp(message_from_server, "Acces granted!") == 0)
      {
        access = 1;
      }
      //otherwise - access declined
      else
      {
        printf("Login failed! Reconnect and try again");
        connection_on = 0;
      }
    }
    //if the access was granted
    else
    {
      printf("Logged in succesfully!\n");
      //creating while loop for the exchange of data
      while (1)
      {
        //displaying the commands that client can use
        display_meniu();

        memset(command_number, 0, 256);
        scanf("%s", command_number);
        //sending the command number we want to use
        write(sd, command_number, 256);
        memset(message_from_server, 0, 256);

        if (strcmp(command_number, "1") == 0)
        {
          read(sd, message_from_server, 256);
          printf("The subdirectories are:\n%s", message_from_server);
        }
        else if (strcmp(command_number, "2") == 0)
        {
          printf("Enter the directory you want to go:");
          scanf("%s", directory);

          strcpy(message_to_server, directory);
          write(sd, message_to_server, 256);

          memset(message_from_server, 0, 256);
          read(sd, message_from_server, 256);
          if (strcmp(message_from_server, "1") == 0)
          {
            printf("\nChanged directory succesfully!\n");
          }
          else
          {
            printf("\nChanged directory failed!\n");
          }
        }
        else if (strcmp(command_number, "3") == 0)
        {
          char file_to_download[20];
          printf("Name of file you want to download:");
          scanf("%s", file_to_download);

          memset(message_to_server, 0, 256);
          strcpy(message_to_server, file_to_download);
          write(sd, message_to_server, 256);

          memset(message_from_server, 0, 256);
          read(sd, message_from_server, 256);
          if(strcmp(message_from_server,"Failed!") == 0)
          {
            printf("File does not exists!\n");
          }
          else
          {
            write_file(sd,message_to_server);
          }
          
        }
        else if(strcmp(command_number,"4") == 0)
        {
          char file_to_upload[20];
          printf("Name of file you want to upload:");
          scanf("%s", file_to_upload);
          
          memset(message_to_server,0,256);
          strcpy(message_to_server,file_to_upload);
          write(sd,message_to_server,256);

          fp = fopen(file_to_upload, "r");
          if (fp == NULL)
          {
            perror("[-]Error in reading file.");
            exit(1);
          }
          send_file(fp, sd);
          fclose(fp);

        }
        else if (strcmp(command_number, "5") == 0)
        {
          read(sd, message_from_server, 256);
          printf("You are here:%s", message_from_server);
        }
        else if (strcmp(command_number, "6") == 0)
        {

          read(sd, message_from_server, 256);

          if (strcmp(message_from_server, "Quit succesfully!") == 0)
          {
            printf("You quited succesfully! Bye!\n");
            connection_on = 0;
            break;
          }

        }
        else if(strcmp(command_number,"7")==0)
        {
          char name_of_directory[20];
          printf("Name of directory you want to create:");
          scanf("%s", name_of_directory);
          
          memset(message_to_server,0,256);
          strcpy(message_to_server,name_of_directory);
          write(sd,message_to_server,256);

          memset(message_from_server,0,256);
          read(sd,message_from_server,256);

          printf("%s",message_from_server);
        }
        else if(strcmp(command_number,"8")==0)
        {
          char name_of_directory[20];
          printf("Name of directory you want to delete:");
          scanf("%s", name_of_directory);
          
          memset(message_to_server,0,256);
          strcpy(message_to_server,name_of_directory);
          write(sd,message_to_server,256);

          memset(message_from_server,0,256);
          read(sd,message_from_server,256);

          printf("%s",message_from_server);
        }
        else
        {
          printf("Unknown command!\n");
        }

      }
    }
  }
  return 0;
}
