/*
** client.c -- a stream socket client demo
*/
#include <time.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h> //For tests

#define PORT "3490" // the port client will be connecting to 

#define MAXTEXT 1024// max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
// Return line count, but stop once the count exceeds a maximum
int Line_Count(FILE *istream, int line_index) 
{
  int lc = 0;
  int previous = '\n';
  int ch;
  rewind(istream);
  while (line_index > 0 && (ch = fgetc(istream)) != EOF) {
    if (ch == '\n') {
      line_index--;
    }
    if (previous == '\n') {
      lc++;
    }
    previous = ch;
  }
  return lc;
}

char* get_random_spell(FILE *istream, int line_index) 
{
	char *spell = (char*)malloc(MAXTEXT);
  	// printf("%d: <", line_index + 1);
  	Line_Count(istream, line_index);
  	int ch;
  	while ((ch = fgetc(istream)) != EOF && ch != '\n')
	{
		if (isprint(ch)) 
		{
			char input_char = (char)ch;
			strncat(spell, &input_char, 1);
		}		
	}
  	// printf(">\n");
	return spell;
}
int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXTEXT];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 2) {
	    fprintf(stderr,"usage: client hostname\n");
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}


	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	if ((numbytes = recv(sockfd, buf, MAXTEXT-1, 0)) == -1) 
	{
	    perror("recv");
	    exit(1);
	}

	buf[numbytes] = '\0';

	printf("client received: '%s'\n",buf);

	// char command[MAXTEXT];
	// scanf("%[^\n]s",command);
	srand((unsigned) time(NULL)); //random seed
  	FILE *istream = fopen("HarryPotter.txt", "r");
  	assert(istream); // checking if the istream is opened correctly
  	int lc = Line_Count(istream, RAND_MAX);
  	assert(lc && lc < RAND_MAX);
	char* command_spell = (char*)malloc(MAXTEXT);
	char command[MAXTEXT];
	scanf("%[^\n]s",command);
	char* spell_name = get_random_spell(istream, rand() % lc);
	int i=0; /* 0 for regular, 2 for push spell, 6 for enqueue spell */
	if(strcmp(command,"2")==0)
	{
		strcat(command_spell,"PUSH ");
		strcat(command_spell,spell_name);
		i=2;
	}
	else if(strcmp(command,"6")==0)
	{
		strcat(command_spell,"ENQUEUE ");
		strcat(command_spell,spell_name);
		i=6;
	}

	free(spell_name); //we don't need it anymore
	
	if(i==2 || i==6)
		strcpy(command, command_spell);
	free(command_spell); //we don't need it anymore
	// send to the server the command that the client insert
	if ( send(sockfd,command,strlen(command),0)<0)
	{
		puts("send failed");
		return 1;
	}

	// only if its a TOP he needs to print "OUTPUT: ..."
	if ( strcmp(command,"TOP")==0) 
	{

		memset(buf,0,sizeof(buf));
		sleep(5);//sleep of 5 seconds in order to be synced with server
		if ((numbytes = recv(sockfd, buf, MAXTEXT-1, 0)) == -1) 
		{
			perror("recv");
			exit(1);
		}
		else
		{
			buf[numbytes] = '\0';
			strcpy(buf, buf+3); //We are doing this because the new buffer is being concatenated to 'TOP' keyword like this: TOPtext1
			assert(strlen(buf)>=1);
			printf("OUTPUT: %s\n",buf);
		}
		close(sockfd);
	}
	else
	{
		/*Shut down connection to server*/
		sleep(4);
		shutdown(sockfd,SHUT_RDWR);
		close(sockfd);
	}
	
}
