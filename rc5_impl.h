/*
RC5 - 32/12/16 implementation inbuilt.
RC5 - Parameterized implementation.
rc5_impl.h: Header file for RC5 implementation.
Author: Rijo Simon
Start Date: 02.27.2013
For University of Alaska - Fairbanks

Reference: 
1. "The RC5 Encryption Algorithm", by Ronald L. Rivest, MIT Laboratory for Computer Science.
2. "Data dependent rotations, a trustworthy approach for future encryption systems/ciphers: low cost and high performance", by N Sklavos and O Koufopavlou, 
Electrical & Computer Engineering Department, University of Patras, Patras 26500, Greece.
*/

#include <iostream> 	//including iostream.

typedef unsigned long int WORD;		//defining WORD as unsigned long int.

//Class: RC5Crypto
// This class defines an object that has the parameters necessary for
// RC-5 Encryption and Decryption and also the modules that performs
// the math involved in the encryption and decryption process.

class RC5Crypto
{

public:

RC5Crypto();   //Default Constructor
RC5Crypto(int _w, int _r, int _b);		//Parameterized Constructor  which 
										//allows objects with variable w/r/b
int aB();		//Accessor for b
int aW();		//Accessor for w

//Rotation operators.

WORD rotl(WORD x, WORD y);		//left shift
WORD rotr(WORD x, WORD y);		//right shift

WORD * encrypt(WORD plainText[]);		//The encrypt function takes in a plaintext of size 2*WORD
										// returns cyphertext of size 2*WORD after performing encryption.
WORD * decrypt(WORD cypherText[]);		//The decrypt function takes in a cyphertext of size 2*WORD
										// returns plaintext of size 2*WORD after performing decryption.
void key_expansion(unsigned char K[]);  //The key_expansion function expands the entered secret key K to
										// fill the key array S, so that S resembles an array of 2(r+1) random binary
										// words determined by K.
private:

/*
w: size of word in bits.
r: number of rounds.
b: number of bytes in key.
c: number of words in key.
t: size of the table S generated from K.
S: Array that contains the expanded table generated from K.
P, Q: magic constants generated from w. The formulae used for this is defined below.
	  P = Odd((e-2)*2^w)
	  Q = Odd((g-1)*2^w)
	  e = 2.718218828459 (base of natural logarithms)
	  g = 1.618033988749 (golden ratio)
	  Odd(): is the odd integer nearest to x (rounded up if x is an even integer).
*/

int w, r, b, c, t;
WORD * S;
WORD P, Q;



};