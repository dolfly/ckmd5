#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  if (sizeof(unsigned char) != 1) {
    fprintf(stderr, "configuration error: unsigned char must have size of 1 byte!\n");
    return -1;
  }
  if (sizeof(unsigned int) != 4) {
    fprintf(stderr, "configuration error: unsigned int must have size of 4 bytes!\n");
    return -1;
  }
  return 0;
}
