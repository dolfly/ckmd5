#ifndef _MD5_H_
#define _MD5_H_

#define MD5_HASHBYTES 16

typedef unsigned int u32;

typedef struct MD5Context {
	u32 buf[4];
	u32 bits[2];
	unsigned char in[64];
} MD5_CTX;

void   MD5Init(MD5_CTX *context);
void   MD5Update(MD5_CTX *context, unsigned char const *buf,
	       unsigned len);
void   MD5Final(unsigned char digest[MD5_HASHBYTES], MD5_CTX *context);
void   MD5Transform(u32 buf[4], u32 const in[16]);

#endif /* !_MD5_H_ */
