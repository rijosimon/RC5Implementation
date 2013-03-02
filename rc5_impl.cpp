/*
RC5 - 32/12/16 implementation inbuilt.
RC5 - Parameterized implementation.
rc5_impl.cpp: Source file for RC5 implementation.
			  Also implements the menu and the modules that would perform the following:
				1. Test Encryption Decryption: runs testEncryptionDecryption()
				2. Analyze Primitive Operations: runs analyzePrimitiveOperations()
				3. Understand data-dependednt rotations: runs dataDependentRotations()
Author: Rijo Simon
Start Date: 02.27.2013
For University of Alaska - Fairbanks

Reference: 
1. "The RC5 Encryption Algorithm", by Ronald L. Rivest, MIT Laboratory for Computer Science.
2. "Data dependent rotations, a trustworthy approach for future encryption systems/ciphers: low cost and high performance", by N Sklavos and O Koufopavlou, 
Electrical & Computer Engineering Department, University of Patras, Patras 26500, Greece.
*/

#include <iostream>		//including iostream
#include "rc5_impl.h"	//including header file for rc5_impl
#include <string>		//inlcuding string library
#include <iomanip>
#include <sstream>

typedef unsigned long int WORD;		//defining WORD as unsigned long int.

//Default Constructor
//Initializes the control block which are default members of the RC5Crypto class
//to parameter values that would run an RC5 - 32/12/16. 

RC5Crypto::RC5Crypto()
{
	w = 32;
	r = 12;
	b=16;
	c=4;
	t=26;
	S = new WORD[t];
	P = 0xb7e15163;
	Q = 0x9e3779b9;
}

//Parameterized Constructor
//Initializes the control block which are default members of the RC5Crypto class
//to parameter values that would run an RC5 - w/r/1b where w, r and b are provided by the user.

RC5Crypto::RC5Crypto(int _w, int _r, int _b)
{
	w = _w;
	r = _r;
	b=_b;
	c=4;
	t=26;
	S = new WORD[t];
	P = 0xb7e15163;   //remeber to calculate the value of P and Q here
	Q = 0x9e3779b9;	  //before implementing the final version with a working parameterized Constructor.	
}

//Returns b.
int RC5Crypto::aB()
{
	return b;
}

//Returns w.
int RC5Crypto::aW()
{
	return w;
}

//Defining rotaion function for left shift
WORD RC5Crypto::rotl(WORD x, WORD y)
{
		return ((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1))));
}

//Defining rotaion function for right shift
WORD RC5Crypto::rotr(WORD x, WORD y)
{
	return ((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1))));
}

//Implementation of encrypt function from class RC5Crypto.
//The encrypt function takes in a plaintext of size 2*WORD
// returns cyphertext of size 2*WORD after performing encryption.
WORD * RC5Crypto::encrypt(WORD plainText[])
{
WORD i, A = plainText[0]+S[0], B = plainText[1]+S[1];
WORD *cypherText = new WORD[2];
for(i =1; i<=r; i++)
{
	A = rotl(A^B, B) + S[2*i];
	B = rotl(B^A, A) + S[2*i + 1];
}
	cypherText[0] = A;
	cypherText[1] = B;
	
	return cypherText;
}

//Implementation of decrypt function from class RC5Crypto.
//The decrypt function takes in a cyphertext of size 2*WORD
// returns plaintext of size 2*WORD after performing decryption.
WORD * RC5Crypto::decrypt(WORD cypherText[])
{
WORD i, B = cypherText[1], A = cypherText[0];
WORD * plainText = new WORD[2];
for (i = r; i>0; i--)
{
	B=rotr(B-S[2*i+1], A)^A;
	A = rotr(A-S[2*i],B)^B;
}
plainText[1] = B-S[1];
plainText[0] = A-S[0];
return plainText;
}

//Implementation of key_expansion function from class RC5Crypto.
//The key_expansion function expands the entered secret key K to
// fill the key array S, so that S resembles an array of 2(r+1) random binary
// words determined by K.
void RC5Crypto::key_expansion(unsigned char K[])
{
WORD i, j, k, u=w/8, A, B, L[c];
for(i = b-1, L[c-1]=0; i!=-1; i--)
{
	L[i/u] = (L[i/u]<<8)+K[i];
}
for(S[0]=P, i=1; i<t; i++)
{
	S[i] = S[i-1]+Q;
}
for(A=B=i=j=k=0; k<3*t; k++, i=(i+1)%t, j=(j+1)%c)
{
	A = S[i] = rotl(S[i] + (A+B), 3);
	B = L[j] = rotl(L[j]+(A+B), (A+B));
}
}

//Function toHex()
//converts an integer to an hex and returns a string hex
std::string toHex(WORD x)
{
std::stringstream stream;
stream<<std::hex<<x;
return stream.str();
}

//Function testEncryptionDecryption()
//The purpose of this function is to test the Encryption-Decryption capability of the RC5 algorithm.
//Asks the user to input the two words of plaintext to encrypt. And then encrypt it and decrypt it back.
//This function displays the correctness of the algorithm implemented here.
void testEncryptionDecryption(){
	WORD plainText1[2];
	WORD *plainText2 = new WORD[2];
	WORD *cypherText = new WORD[2];
	RC5Crypto testObj1;
	unsigned char K[testObj1.aB()];
	std::string keyHolder;
	std::cout<<"Enter two WORDS, (each of maximum size "<<testObj1.aW()<<" bytes) :"<<std::endl;
	std::cout<<"First WORD: ";
	std::cin>>plainText1[0];
	std::cout<<"Second WORD: ";
	std::cin>>plainText1[1];
	std::cout<<"Enter a key "<<testObj1.aB()<<" characters long: ";
	std::cin>>keyHolder;
	for(int tI = 0; tI<testObj1.aB();tI++)
	{
		K[tI] = keyHolder[tI];
	}
	testObj1.key_expansion(K);
	cypherText = testObj1.encrypt(plainText1);
	std::cout<<std::endl<<plainText1[0]<<"( 0x"<<toHex(plainText1[0])<<" ) encrypts to "<<cypherText[0]<<"( 0x"<<toHex(cypherText[0])<<" ) and "<<plainText1[1]<<"( 0x"<<toHex(plainText1[1])<<" ) encrypts to "<<cypherText[1]<<"( 0x"<<toHex(cypherText[1])<<" )"<<std::endl;
	plainText2 = testObj1.decrypt(cypherText);   
	std::cout<<std::endl<<cypherText[0]<<"( 0x"<<toHex(cypherText[0])<<" ) decrypts to "<<plainText2[0]<<"( 0x"<<toHex(plainText2[0])<<" ) and "<<cypherText[1]<<"( 0x"<<toHex(cypherText[1])<<" ) decrypts to "<<plainText2[1]<<"( 0x"<<toHex(plainText2[1])<<" )"<<std::endl;
}

//Function analyzePrimitiveOperations()
// Not implemented yet.
void analyzePrimitiveOperations(){
	//Implement here the outline developed
	// to analyze primitive cryptographic operations using
	// RC-5 Algorithm.
}

//Function dataDependentRotations()
// Not implemented yet.	
void dataDependentRotations() {
	//Implement here the outline developed to
	//represent the inner working of data dependent rotations.
}

//Function main
//Presents the menuo to do one of the following:
//	1. Test Encryption Decryption: runs testEncryptionDecryption()
//	2. Analyze Primitive Operations: runs analyzePrimitiveOperations()
//	3. Understand data-dependednt rotations: runs dataDependentRotations()

int main()
{
	char control;
	do{
	//Printing the menu.
	std::cout<<std::endl<<std::endl<<"Choose from an entry below : \n\nTest Encryption Decryption (Enter E)\nAnalyze Primitive Operations (Enter A)\nUnderstand data-dependent rotations (Enter D)\nEnter 'X' to Exit."<<std::endl;
	std::cout<<std::endl<<"Time to enter a value: ";
	std::cin>>control;
	//Using swith-case to direct menu.
	switch(control)
	{
		case 'A':
		case 'a':
			analyzePrimitiveOperations();
			break;
		case 'E':
		case 'e':
			testEncryptionDecryption();
			break;
		case 'D':
		case 'd':
			dataDependentRotations();
			break;
		case 'X':
		case 'x':
			break;
		default:
			std::cout<<std::endl<<std::endl<<"This is not an acceptable input"<<std::endl;
			break;
			}
	}while(!(control=='X' || control == 'x')); ///Exit the menu if user enters X
	
	return 0; //get out of the main function and end the program.
}