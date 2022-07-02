/*
All this server does is send the string “Hello, world!” out over a stream connection.
All you need to do to test this server is run it in one window, and telnet to it from another with:

$ telnet remotehostname 3490

where remotehostname is the name of the machine you're running it on.*/

/*
** server.c -- a stream socket server demo
*/

/*==============================================================*/

/*For malloc, free, calloc implementations*/
#define NALLOC 1024
#include <limits.h>

/*==============================================================*/

/*For stack, server, client implementations*/
#include <iostream>
#include <stack>
#include "stack_list.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h> //For tests

#define PORT "3490"  //the port users will be connecting to

#define BACKLOG 10   // how many pending connections queue will hold
#define MAXTEXT 1024 // max length for the text 

/*==============================================================*/

/*Here we implemented malloc, free, calloc functions*/

#define malloc(x) our_malloc(x)
#define free(x) our_free(x)
#define calloc(x,y) our_calloc(x,y)

/* This header is stored at the beginning of memory segments in the list. */
union header
{
  struct 
  {
    union header *next;
    unsigned len;
  } meta;
  long x; /* Presence forces alignment of headers in memory. */
};

static union header list;
static union header *first = NULL;

/*free implemenatation*/
void our_free(void* ptr) 
{
  if (ptr == NULL) 
  {
    return;
  }

  union header *iter, *block;
  iter = first;
  block = (union header*)ptr - 1;

  /* Traverse to the spot in the list to insert the freed fragment,
   * such that the list is ordered by memory address (for coalescing). */
    while (block <= iter || block >= iter->meta.next) 
    {
        if ((block > iter || block < iter->meta.next) && iter >= iter->meta.next) 
        {
            break;
        }
        iter = iter->meta.next;
    }

  /* If the new fragment is adjacent in memory to any others, merge
   * them (we only have to check the adjacent elements because the
   * order semantics are enforced). */
    if(block + block->meta.len == iter->meta.next)
    {
        block->meta.len += iter->meta.next->meta.len;
        block->meta.next = iter->meta.next->meta.next;
    } 
    else 
    {
        block->meta.next = iter->meta.next;
    }

    if (iter + iter->meta.len == block) 
    {
        iter->meta.len += block->meta.len;
        iter->meta.next = block->meta.next;
    } 
    else 
    {
        iter->meta.next = block;
    }

    first = iter;
}

/*malloc implemenatation*/
void *our_malloc(size_t size) 
{
  union header *p, *prev;
  prev = first;
  unsigned true_size =
    (size + sizeof(union header) - 1) /
     sizeof(union header) + 1;

  /* If the list of previously allocated fragments is empty,
   * initialize it. */
  if (first == NULL) 
  {
    prev = &list;
    first = prev;
    list.meta.next = first;
    list.meta.len = 0;
  }
  p = prev->meta.next;
  /* Traverse the list of previously allocated fragments, searching
   * for one sufficiently large to allocate. */
  while (1) 
  {
    if (p->meta.len >= true_size) 
    {
      if (p->meta.len == true_size) 
      {
        /* If the fragment is exactly the right size, we do not have
         * to split it. */
        prev->meta.next = p->meta.next;
      } else 
      {
        /* Otherwise, split the fragment, returning the first half and
         * storing the back half as another element in the list. */
        p->meta.len -= true_size;
        p += p->meta.len;
        p->meta.len = true_size;
      }
      first = prev;
      return (void *)(p+1);
    }
    /* If we reach the beginning of the list, no satisfactory fragment
     * was found, so we have to request a new one. */
    if (p == first) 
    {
      char *page;
      union header *block;
      /* We have to request memory of at least a certain size. */
      if (true_size < NALLOC) 
      {
        true_size = NALLOC;
      }
      page = (char*)sbrk((intptr_t) (true_size * sizeof(union header)));
      if (page == (char *)-1) 
      {
        /* There was no memory left to allocate. */
        errno = ENOMEM;
        return NULL;
      }
      /* Create a fragment from this new memory and add it to the list
       * so the above logic can handle breaking it if necessary. */
      block = (union header *)page;
      block->meta.len = true_size;
      free((void *)(block + 1));
      p = first;
    }

    prev = p;
    p = p->meta.next;
  }
  return NULL;
}

/*calloc implemenatation*/
void* our_calloc(size_t num, size_t len) 
{
  void* ptr = malloc(num * len);

  /* Set the allocated array to 0's.*/
  if (ptr != NULL) 
  {
    memset(ptr, 0, num * len);
  }

  return ptr;
}
/*==============================================================*/

/*Rest of assignment (stack and server)*/

pthread_mutex_t lock;

using namespace std;

// global VAR
static StackNode * root = NULL;

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int first_space(const char * command)
{
	for ( int i = 0; i<strlen(command);i++){
		if(command[i] == ' '){
			return i;
		}
	}
	return -1;
}

void stack_status()
{
    StackNode * tempRoot = root;
    puts("STACK STATUS:");
    while(tempRoot!=NULL)
    {
        printf("%s -> ",tempRoot->value);
        tempRoot = tempRoot->next;
    }
    printf("null\n"); 
}

void *handlerThread(void *arg)
{
    int new_fd = *(int*)arg; 
    printf("--------------------------------------- \n");

   
    char msg[] = "Hello, what you want to do?\n1. For PUSH text into the stack, enter PUSH and the text after\n2. For PUSH random spell into the stack, press 2 and then enter\n3. For POP, enter POP command\n4. For seeing the first element in the stack enter TOP command\n5. For ENQUEUE text into the stack's tail, enter ENQUEUE and the text after\n6. For ENQUEUE random spell into the stack's tail,\npress 6 and then enter\n7. For DEQUEUE stack's tail, enter DEQUEUE command\n";

    if (send(new_fd, msg, strlen(msg), 0) == -1)
    {
        perror("send");
    }
    else 
    {
        int read_size;
        char client_message [MAXTEXT];
        /*Gets a message from client*/
        if (recv(new_fd,client_message,sizeof(client_message),0) > 0)
        {
            sleep(1);
            write(new_fd,client_message,strlen(client_message));
            printf("------------------------------------\n");
            printf("Server got client message: %s\n\n", client_message);

        }
        /*getting PUSH keyword from client message*/
        char *push = (char*)malloc(strlen(client_message));
        strncpy(push,client_message,4);

        /*getting POP keyword from client message*/
        char *pop = (char*)malloc(strlen(client_message));
        strncpy(pop,client_message,3);

        /*getting TOP keyword from client message*/
        char *top = (char*)malloc(strlen(client_message));
        strncpy(top,client_message,3);

        /*getting ENQUEUE keyword from client message*/
        char *enq = (char*)malloc(strlen(client_message));
        strncpy(enq,client_message,7);

        /*getting DEQUEUE keyword from client message*/
        char *deq = (char*)malloc(strlen(client_message));
        strncpy(deq,client_message,7);

        int space_location = first_space(client_message);
        
        
        // PUSH
        if ( strcmp(push, "PUSH")==0 && space_location == 4 ) 
        {
            pthread_mutex_lock(&lock); // Lock mutex
            char text[MAXTEXT];
            int j = 0;
            for (int i = space_location+1; i<strlen(client_message); i++)
            {
                text[j++] = client_message[i];
            }
            text[j] = '\0'; //Very important to add null terminator character
            StackNode::push(&root, text);
            printf("PUSH opertion was executed successfully\n");
            stack_status();
        } 

        // POP
        else if(strcmp(pop, "POP")==0 && strcmp(top,client_message) == 0)
        {
            pthread_mutex_lock(&lock); // Lock mutex
            if(root!=NULL)
            {
                char * popped_out = root->value;
                printf("Value retrieved: %s\n",popped_out);
                StackNode::pop(&root);
                printf("POP opertion was executed successfully\n");
                if(root==NULL)
                    printf("The stack is empty now.\n");
            }
            else
                printf("ERROR: the stack is empty, there is nothing to pop out.\n");
            stack_status();
        }
        // TOP
        else if (strcmp(top, "TOP")==0 && strcmp(pop,client_message) == 0)
        {
            pthread_mutex_lock(&lock); // Lock mutex
            StackNode *top_node = StackNode::top(&root);
            char * top_node_text;
            if(top_node==NULL)
            {
                top_node_text = "ERROR: empty stack";
            }
            else
            {
                top_node_text = top_node->value;
                printf("TOP opertion was executed\n");
            }
            stack_status();
            printf("message's text is: %s\n",top_node_text);
            send(new_fd, top_node_text , strlen(top_node_text), 0); //send back to client
        }
        //DEQUEUE
        else if (strcmp(deq, "DEQUEUE")==0 && strcmp(deq,client_message) == 0)
        {
            pthread_mutex_lock(&lock); // Lock mutex
            if(root!=NULL)
            {
                StackNode::dequeue(&root);
                printf("DEQUEUE opertion was executed successfully\n");
                if(root==NULL)
                    printf("The stack is empty now.\n");
            }
            else
                printf("ERROR: the stack is empty, there is nothing to dequeue.\n");
            stack_status();
        }
        //ENQUEUE
        else if (strcmp(enq, "ENQUEUE")==0 && space_location == 7)
        {
            pthread_mutex_lock(&lock); // Lock mutex
            char text[MAXTEXT];
            int j = 0;
            for (int i = space_location+1; i<strlen(client_message); i++)
            {
                text[j++] = client_message[i];
            }
            text[j] = '\0'; //Very important to add null terminator character
            StackNode::enqueue(&root, text);
            printf("ENQUEUE opertion was executed successfully\n");
            stack_status();
        }
        else
        {
            printf("ERROR: server recognized illegal command: %s\n",client_message);
            sleep(2);
        }
        free(push);
        free(pop);
        free(top);
        free(enq);
        free(deq);
        pthread_mutex_unlock(&lock);// Unlock mutex
        sleep(2);
    }
    printf("------------------------------------\n");
    sleep(15); 
    close(new_fd);
    pthread_exit(NULL);
}

StackNode* StackNode::new_node(char * text)
{
    StackNode *node = (StackNode*)malloc(sizeof(StackNode)); //allocating space for our new node in StackNode
    strcpy(node->value,text);
    node->next = NULL;
    assert(node!=NULL);
    return node;
}

// is_empty function to check if the stack 
bool StackNode::is_empty(StackNode ** root)
{

    return (*root == NULL) ? true : false; 
}

void StackNode::push(StackNode ** root, char * text)
{

    StackNode *stack_node = new_node(text);
    if(root == NULL) //Our stack is empty
        *root = stack_node;
    else //root has value
    {
        stack_node->next = *root; // our current root is below our new root
        *root = stack_node; //making sure that the new root is updated
    }
    assert(root != NULL); // After push, our root has value as expected
}

void StackNode::pop(StackNode **root)
{

    // first check if stack is empty
    if (!is_empty(root))
    {
        StackNode *first_elem = *root; // saves the top
        assert(root!=NULL); //Root sure has value, therefore this test will pass
        *root  = (*root)->next; // now the top is the next node afterwads.
        free(first_elem);
    }
}

StackNode* StackNode::top(StackNode ** root)
{
    if(!is_empty(root))
    {
        assert(root!=NULL);
        return *root;
    }
    else 
    {
        return NULL;
    }
}

void StackNode::enqueue(StackNode ** root, char * text)
{
    StackNode *stack_node = new_node(text);
    if(is_empty(root)) //Our stack is empty
        *root = stack_node;
    else //root has value, add it to his next
    {
        /*search for tail and then add new node*/
        StackNode* saved_root = *root;
        while((*root)->next!=NULL)
            *root = (*root)->next;
        (*root)->next = stack_node;
        *root = saved_root; //restore pointer to root
    }
    assert(root != NULL); // After enqueue, our root has value as expected
}

void StackNode::dequeue(StackNode **root)
{

    // first check if stack is empty
    if (!is_empty(root))
    {
        /*search for tail and then add new node*/
        StackNode* node = *root;
        StackNode* prev = *root;
        while(node->next!=NULL)
        {
            prev = node;
            node = node->next;
        }
        if(prev->next == NULL) /*in case we have exactly one node in our stack */
        {
            printf("Value retrieved: %s\n",prev->value);
            *root = NULL;
            free(prev);
        }
        else
        {
            printf("Value retrieved: %s\n",node->value);
            prev->next=NULL; //prev->next = node. but we want to free this node
            free(node);
        }
    }
}
int main(void)
{

    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) 
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    pthread_t tid[BACKLOG];
    int i=0;
    lock = PTHREAD_MUTEX_INITIALIZER; //init mutex
    while(1) 
    {  // main accept() loop
        sin_size = sizeof their_addr;
        // new_fd is the client socket
        
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) 
        {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        //Replace fork with pthread_create - THOSE ARE THE ONLY CHANGES        
        if (pthread_create(&tid[i++], NULL, &handlerThread, &new_fd) != 0)                 
            printf("Failed to create thread\n");       
        if(i==BACKLOG)    
            i=0;


    }
    /*When finished - destroy this mutex*/
    pthread_mutex_destroy(&lock);

    return 0;
}