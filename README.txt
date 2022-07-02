Overall:

The goal in this homework is to understand how the OS implements malloc and free on
multi-threaded system and how we implement mutexes.
The final submission is including a stack server.

References:
    1. malloc, free, calloc implementations:
        https://github.com/clemahieu/malloc/blob/master/malloc.c

Ideas for tests:
    In order to make things more interesting, we wrote a text file of various spells,
    curses, hexes and jinxes from Harry Potter books & movies :) .
    The file's name is called HarryPotter.txt.
    
    source for more details for each spell/curse/hex/jinx:
    https://www.pojo.com/harry-potter-spell-list/

    Several clients can be connected to the server at the same time, but only
    one of them will get the pthread_mutex_lock when performing a command, such as
    TOP, PUSH, POP, ENQUEUE, DEQUEUE.


Submitted by: 311382360 Eran Levy _ 315524389 Or Mendel