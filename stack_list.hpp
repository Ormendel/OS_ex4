#pragma once
#include <iostream>
#define MAXTEXT 1024
namespace std{ 

class StackNode {


    public:
    char value[MAXTEXT]; // The value of a node in the stack
    StackNode *next; // POINTER to the next node

    // functions
    static StackNode* new_node(char * text); // create a new Node 
    static bool is_empty(StackNode ** root);
    static void push(StackNode **root, char * text);
    static void pop(StackNode ** root);
    static StackNode* top(StackNode ** root); // OUTPUT: TEXT...
    
    /*BONUS functions*/
    static void enqueue(StackNode ** root, char * text);
    static void dequeue(StackNode ** root);
};
}