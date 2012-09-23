/*
 * This demo is a c++ implementation of the SHA-1 hash algorithm and it's an imitation of the c version in the RFC3174 decumentation.
 * See RFC3174 in http://www.packetizer.com/rfc/rfc3174/
 */

#include <stdint.h>		//this header defines the types : uint32_t,uint8_t,int_least16_t
#include <string.h>

enum { shaSuccess, shaParamError,  shaProcessError, shaInputTooLong};	//enum the state of sha1 calculating process

#define SHA1HashSize 20		//SHA1 outputs 20 chars as the result
#define SHA1BlockSize 64	//64 chars == 16 word == 512bits
#define SHA1CircularShift(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

class SHA1Context
{
private:
	uint64_t charInputed;	//statistics of the chars inputed
	uint8_t block[SHA1BlockSize];	//storage the chars that currently calculating
	uint32_t H[SHA1HashSize/4];		//the array H[5] that store the outcomes
	uint32_t charsInCurrentBlock;	//this is useful when padding the last block

	int inputCharSequence(uint8_t *messageArray, uint32_t length);	//input 64 chars per time until the sequence ends
	int calculateOneBlock(void);	//calculate the full 512-bits block
	int padTheLastBlock(void);	//pad the last block until it is canonical
	void init();	//init the SHA1Context
public:
	SHA1Context();	//constructor
	~SHA1Context();	//destructor
	int SHA1(uint8_t *message, uint32_t length, uint8_t output[SHA1HashSize]);	//the interface of the SHA1 method
};
