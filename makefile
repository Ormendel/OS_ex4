CC=g++

FLAGS_SERVER= -Wall -g -pthread
FLAGS_CLIENT = -Wall -g


all: server client

server: server.cpp stack_list.hpp

	$(CC) $(FLAGS_SERVER) server.cpp stack_list.hpp -o server

client: client.cpp

	$(CC) $(FLAGS_CLIENT) client.cpp -o client

.PHONY: clean all

clean:
	rm -f *.o *.a server client
