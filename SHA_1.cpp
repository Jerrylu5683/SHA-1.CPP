#include "SHA_1.h"

//80 functions stored in four function pointer
uint32_t f1(uint32_t B, uint32_t C, uint32_t D) { return (B&C)|(~B&D); }
uint32_t f2(uint32_t B, uint32_t C, uint32_t D) { return B^C^D; }
uint32_t f3(uint32_t B, uint32_t C, uint32_t D) { return (B&C)|(B&D)|(C&D); }
uint32_t f4(uint32_t B, uint32_t C, uint32_t D) { return B^C^D; }
uint32_t (*f[])(uint32_t B, uint32_t C, uint32_t D) = { f1, f2, f3, f4};

//the K array used in the 80 loops
static uint32_t K[] = 
{
	0x5A827999,
	0x6ED9EBA1,
	0x8F1BBCDC,
	0xCA62C1D6
};

///
//Description:
//    contructor
///
SHA1Context::SHA1Context()
{
	
}

///
//Description:
//    destructor
///
SHA1Context::~SHA1Context()
{
	charInputed = 0;
	charsInCurrentBlock = 0;

	//message may be sensitive, clear it out
	for(int i = 0; i < SHA1BlockSize; i++)
		block[i] = 0;
}

//init the SHA1Context
void SHA1Context::init()
{
	charInputed = 0;
	charsInCurrentBlock = 0;
	
	//init the array H[5]
	H[0] = 0x67452301;
	H[1] = 0xEFCDAB89;
	H[2] = 0x98BADCFE;
	H[3] = 0x10325476;
	H[4] = 0xC3D2E1F0;
}
///
//Description:
//    input 64 chars per time and calculate the block until the sequence ends
//Parameters:
//	  messageArray: the SHA1 source data
//    length: length of the messageArray
//Returns:
//    SHA-1 error code
///
int SHA1Context::inputCharSequence(uint8_t *messageArray, uint32_t length)
{
	while(length--)	//when length reachs zero, it means input ends and all full blocks calculated, only left the last one 
	{
		block[charsInCurrentBlock++] = *messageArray & 0xFF;	//fetch one char
		charInputed += 8;
		if(charInputed == 0)	//message is too long
			return shaInputTooLong;
		if(charsInCurrentBlock == SHA1BlockSize)
			calculateOneBlock();
		messageArray++;
	}
	return shaSuccess;
}

///
//Description:
//    calculate the full 512-bits block
//Parameters:
//Returns:
//    SHA-1 error code
///
int SHA1Context::calculateOneBlock(void)
{
	uint32_t      Temp;              //Temporary word value
    uint32_t      A, B, C, D, E;     //Word buffers 
	uint32_t      W[80];             //Words that used in 80 loops
	
	//expand the block to 80 words
	for(int t = 0; t < 16; t++)
    {
        W[t] = block[t * 4] << 24;
        W[t] |= block[t * 4 + 1] << 16;
        W[t] |= block[t * 4 + 2] << 8;
        W[t] |= block[t * 4 + 3];
		//printf("%d:%d\n", t, W[t]);
    }
	for(int i = 16; i < 80; i++)	//calculate the next W[]
		W[i] = SHA1CircularShift(1, W[i-3]^W[i-8]^W[i-14]^W[i-16]);
	//init ABCDE
	A = H[0];
	B = H[1];
	C = H[2];
	D = H[3];
	E = H[4];
	//calculate the 80 words with last loop's return
	for(int t = 0; t < 80; t++)
	{
		Temp = SHA1CircularShift(5, A) + f[t/20](B, C, D) + E + W[t] + K[t/20];
		E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = Temp;
	}
	//write the answer back
	H[0] += A;
	H[1] += B;
	H[2] += C;
	H[3] += D;
	H[4] += E;
	charsInCurrentBlock = 0;	//zero the variable charsInCurrentBlock when finished
	return shaSuccess;
}

///
//Description:
//    pad the last block until it is canonical and then finish the sha1 process
//    a block is 64 chars, and at last is 10000000 and 64bit kept for charInputed, that is 9 chars
//    so if the current size is more than 55, a new block needs to be opend.
//Parameters:
//Returns:
//    SHA-1 error code
///
int SHA1Context::padTheLastBlock(void)
{
	if(charsInCurrentBlock > 55)
	{
		block[charsInCurrentBlock++] = 0x80;	//append a 1 after the data
		while(charsInCurrentBlock < 64)
			block[charsInCurrentBlock++] = 0;	//append 0
		calculateOneBlock();	//calculate the current block
		while(charsInCurrentBlock < 56)
			block[charsInCurrentBlock++] = 0;	//put 56 '0' in the block, left 8 chars to put the charInputed
	}
	else
	{
		block[charsInCurrentBlock++] = 0x80;	//append a 1 after the data
		while(charsInCurrentBlock < 56)
			block[charsInCurrentBlock++] = 0;	//append '0' until 8-char size memory left
	}
	//copy the variable charInputed to the last 8-chars of block
	//int64_t *dangerPointer = (int64_t *)(block+charsInCurrentBlock);	
	//*dangerPointer = charInputed;
	block[56] = charInputed >> 56;
	block[57] = charInputed >> 48;
	block[58] = charInputed >> 40;
	block[59] = charInputed >> 32;
	block[60] = charInputed >> 24;
	block[61] = charInputed >> 16;
	block[62] = charInputed >> 8;
	block[63] = charInputed;
	calculateOneBlock();	//calculate the last block
	return shaSuccess;
}

///
//Description:
//    the interface of the SHA1 method
//Parameters:
//	  messageArray: the SHA1 source data
//    length: length of the messageArray
//    output: where the outcome stored
//Returns:
//    SHA-1 error code
///
int SHA1Context::SHA1(uint8_t *message, uint32_t length, uint8_t output[SHA1HashSize])
{
	if(length < 0 || message == 0)	//even messageArray point to "" can been caculated in SHA1
		return shaParamError;
	init();
	if(inputCharSequence(message, length) != shaSuccess)
		return shaProcessError;
	padTheLastBlock();

	/*
	uint8_t *dangerPointer = (uint8_t *)H;
	memcpy(output, dangerPointer, SHA1HashSize);
	*/
	for(int i = 0; i < SHA1HashSize; ++i)
        output[i] = H[i>>2] >> 8 * ( 3 - ( i & 0x03 ) );
	return shaSuccess;
}

///
//Description:
//    the interface of the HMAC-SHA1 method
//Parameters:
//	  text: the HMAC source data
//    textLength: length of the text
//    key: key to encript the text
//    keyLength: the length of the key
//    output: where the outcome stored
//Returns:
//    SHA-1 error code
///
int SHA1Context::HMAC_SHA1(uint8_t *text, uint32_t textLength, uint8_t *key, uint32_t keyLength, uint8_t output[SHA1HashSize])
{
	if(text == 0 || textLength < 0 || key == 0 || keyLength < 0)
		return shaParamError;
	uint8_t k_ipad[SHA1BlockSize];		//key xor ipad
	uint8_t k_opad[SHA1BlockSize];		//key xor opad
	uint8_t keyHashed[SHA1HashSize];	//store the hashed key
	
	//hash the key if the length > SHA1BlockSize(64)
	if(keyLength > SHA1BlockSize)
	{
		SHA1(key, keyLength, keyHashed);
		//memcpy(key, keyHashed, SHA1HashSize);
		key = keyHashed;
		keyLength = SHA1HashSize;
	}

	//the memory stores the k_ipad and text
	uint8_t *k_ipadAppendWithText = new uint8_t[SHA1BlockSize+textLength];
	//the memory stores the k_opad and H(k_ipad, text)
	uint8_t *k_opadAppendWithHash = new uint8_t[SHA1BlockSize+SHA1HashSize];

	for(int i = 0; i < SHA1BlockSize; i++)
	{
		//init ipad and opad
		if(i < keyLength)
		{
			k_ipad[i] = key[i];
			k_opad[i] = key[i];
		}
		else
		{
			k_ipad[i] = 0x00;
			k_opad[i] = 0x00;
		}
		//calculate key XOR ipad, key XOR opad
		k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5C;
		//put into the front of memory for Hash
		k_ipadAppendWithText[i] = k_ipad[i];
		k_opadAppendWithHash[i] = k_opad[i];
	}

	//append the text to k_ipad from position SHA1BlockSize
	strncpy((char *)k_ipadAppendWithText+SHA1BlockSize, (char *)text, textLength);
	SHA1(k_ipadAppendWithText, SHA1BlockSize+textLength, output);

	//apend the hash value to k_opad from position SHA1HashSize
	strncpy((char *)k_opadAppendWithHash+SHA1BlockSize, (char *)output, SHA1HashSize);
	SHA1(k_opadAppendWithHash, SHA1BlockSize+SHA1HashSize, output);

	delete[] k_ipadAppendWithText;
	delete[] k_opadAppendWithHash;
	return shaSuccess;
}