#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <limits.h>
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_LINE 4096

#include "md5.h"

#define CKMD5_ILLEGAL_NAME 0
#define CKMD5_LONG_NAME 1
#define CKMD5_NO_META 2
#define CKMD5_NFO_NAME 3
#define CKMD5_MD5_NAME 4

extern int errno;

/* strip 'pattern' out of 'src' and copy result into 'dst'. 'dst' has
   maxlen bytes of space. pattern matchins is case-insensitive. */
static int strip_strcase(char *dst, char *src, char *pattern, int maxlen)
{
  int i, j, k;
  int plen, slen;
  int c1, c2;
  int ret = 0;
  char *tmp;

  slen = strlen(src);
  if (slen >= maxlen)
    return 0;

  plen = strlen(pattern);

  i = 0;
  k = 0;

  /* copy dirname first, pattern matching applies only to basename */
  if ((tmp = strrchr(src, (int) '/'))) {
    i = (int) (tmp + 1 - src);
    memcpy(dst, src, i);
    k = i;
  }

  while (i < slen) {

    j = 0;

    /* try to match the pattern from &src[i] */
    while (pattern[j] && (i + j) < slen) {
      c1 = (int) src[i + j];
      c2 = (int) pattern[j];
      if (c2 == '?') {
	if (isdigit(c1)) {
	  j++;
	  continue;
	}
	/* is not a digit, so doesn't match the pattern. */
	break;

      } else if (tolower(c1) == tolower(c2)) {
	j++;
	continue;
      }
      /* chars differ. break comparison. */
      break;
    }

    if (pattern[j]) {
      /* no match => copy */
      dst[k] = src[i];
      i++;
      k++;
    } else {
      /* match => skip the length of pattern in source */
      i += plen;
      ret = 1;
    }
  }

  dst[k] = 0;

  return ret;
}

static int get_meta_file(FILE **metafile, char *fname)
{
  char *slashptr;
  char *dotptr;
  int len;
  int ret;
  char metaname[PATH_MAX];
  FILE *file;

  if ((slashptr = strrchr(fname, (int) '/'))) {
    slashptr++;
  } else {
    slashptr = fname;
  }

  if ((dotptr = strrchr(slashptr, (int) '.'))) {
    if (strcasecmp(dotptr, ".nfo") == 0 || strcasecmp(dotptr, ".md5") == 0) {
      return CKMD5_ILLEGAL_NAME;
    }

    len = (int) (dotptr - fname);
    /* space for .nfo and .md5 extensions */
    if (((int) sizeof(metaname)) < (len + 4 + 1)) {
      return CKMD5_LONG_NAME;
    }

    memcpy(metaname, fname, len);
    metaname[len] = 0;
    strcat(metaname, ".nfo");
    if ((file = fopen(metaname, "r"))) {
      *metafile = file;
      return CKMD5_NFO_NAME;
    }

    memcpy(metaname, fname, len);
    metaname[len] = 0;
    strcat(metaname, ".md5");
    if ((file = fopen(metaname, "r"))) {
      *metafile = file;
      return CKMD5_MD5_NAME;
    }

  } else {

    ret = snprintf(metaname, sizeof(metaname), "%s.md5", fname);
    if (ret >= ((int) sizeof(metaname))) {
      return CKMD5_LONG_NAME;
    }
    if ((file = fopen(metaname, "r"))) {
      *metafile = file;
      return CKMD5_MD5_NAME;
    }
  }
  return CKMD5_NO_META;
}

static int handle_meta_file(char **checksums, FILE *metafile, int is_nfo)
{
  char *c = 0;
  int c_size = 0;
  char *new;
  char line[MAX_LINE];
  int n_checksums = 0;
  int i;
  int len;
  int ndigits;
  char *place;

  while (1) {
    if (!fgets(line, sizeof(line), metafile))
      break;

    len = strlen(line);
    if (line[len - 1] == '\n') {
      line[len - 1] = 0;
      len--;
    }

    if (!is_nfo) {
      if (strspn(line, "0123456789abcdefABCDEF") == 32) {
	/* at least 1 whitespace character or \0 must follow a valid md5sum */
	if (32 < len && !isspace((int) line[32]))
	  continue;

	c_size = c_size ? c_size * 2 : 1;
	new = realloc(c, c_size * 33);
	if (!new) {
	  fprintf(stderr, "not enough memory for checksums\n");
	  return n_checksums;
	}
	c = new;
	place = &c[n_checksums * 33];
	memcpy(place, line, 32);
	place[32] = 0;
	n_checksums++;
	break;
      }
      continue;
    }

    i = 0;
    while (i < len) {
      if (line[i] == 'm' || line[i] == 'M') {
	if (strncasecmp(line + i, "md5", 3) == 0) {
	  i += 3;
	  break;
	}
      }
      i++;
    }

    if (i >= len)
      continue;

    while (i < len && (len - i) >= 32) {
      ndigits = strspn(line + i, "0123456789abcdefABCDEF");
      if (ndigits == 0) {
	i++;
      } else if (ndigits < 32 || ndigits > 32) {
	i += ndigits;
      } else {

	/* at least 1 whitespace character or \0 must follow a valid md5sum */
	if ((i + 32) < len && !isspace((int) line[i + 32])) {
	    i += ndigits;
	    continue;
	}

	c_size = c_size ? c_size * 2 : 1;
	new = realloc(c, c_size * 33);
	if (!new) {
	  fprintf(stderr, "not enough memory for checksums\n");
	  return n_checksums;
	}
	c = new;
	place = &c[n_checksums * 33];
	memcpy(place, line + i, 32);
	place[32] = 0;
	n_checksums++;
	break;
      }
    }
  }

  *checksums = c;
  return n_checksums;
}

static void print_version(void)
{
  fprintf(stderr, "ckmd5-%s by Heikki Orsila <heikki.orsila@iki.fi>\n", VERSION);
}

static void print_help(char *prog)
{
  fprintf(stderr, "ckmd5 usage:\n\n");
  fprintf(stderr, " %s FILE1 FILE2 ...\n", prog);
}

int main(int argc, char **argv)
{
  MD5_CTX c;
  int i, j, ret;
  unsigned char buf[4096];
  char md5sum[33];
  char *fname;
  struct stat st;
  int fd_in;
  FILE *metafile;
  int type;
  char *checksums;
  int n_sums;
  char *place;

  if (argc == 2) {
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
      print_help(argv[0]);
      return 0;
    }
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
      print_version();
      return 0;
    }
  }

  if (argc == 1) {
    print_help(argv[0]);
    return 0;
  }

  for (i = 1; i < argc; i++) {
    fname = argv[i];

    /* try changing extension to .nfo or .md5 */
    type = get_meta_file(&metafile, fname);
    if (type < CKMD5_ILLEGAL_NAME || type > CKMD5_MD5_NAME) {
      fprintf(stderr, "holy shit. ckmd5 is bugs with %s\n", fname);
      continue;
    } else if (type == CKMD5_ILLEGAL_NAME) {
      continue;
    } else if (type == CKMD5_LONG_NAME) {
      fprintf(stderr, "%s: too long a name\n", fname);
      continue;
    } else if (type == CKMD5_NO_META) {
      /* changing extension didn't help. try other tricks. */
      char tempname[PATH_MAX];
      if (strip_strcase(tempname, fname, "-part?", sizeof(tempname))) {
	type = get_meta_file(&metafile, tempname);
      }
    }

    if (type < CKMD5_ILLEGAL_NAME || type > CKMD5_MD5_NAME) {
      fprintf(stderr, "holy shit. ckmd5 is bugs with %s\n", fname);
      continue;
    } else if (type == CKMD5_ILLEGAL_NAME) {
      continue;
    } else if (type == CKMD5_LONG_NAME) {
      fprintf(stderr, "%s: too long a name\n", fname);
      continue;
    } else if (type == CKMD5_NO_META) {
      /* stripping -part? didn't help. try other tricks. */
      char tempname[PATH_MAX];
      if (strip_strcase(tempname, fname, "-cd?", sizeof(tempname))) {
	type = get_meta_file(&metafile, tempname);
      }
    }

    if (type < CKMD5_ILLEGAL_NAME || type > CKMD5_MD5_NAME) {
      fprintf(stderr, "holy shit. ckmd5 is bugs with %s\n", fname);
      continue;
    } else if (type == CKMD5_ILLEGAL_NAME) {
      continue;
    } else if (type == CKMD5_LONG_NAME) {
      fprintf(stderr, "%s: too long a name\n", fname);
      continue;
    } else if (type == CKMD5_NO_META) {
      /* tricks didn't help. continue. */
      fprintf(stderr, "%s: can not find .nfo or .md5 file\n", fname);
      continue;
    }

    checksums = 0;
    n_sums = handle_meta_file(&checksums, metafile, type == CKMD5_NFO_NAME);
    fclose(metafile);

    if (n_sums == 0) {
      printf("checksum not found: %s\n", fname);
      continue;
    }

    fd_in = open(fname, O_RDONLY);

    if (fd_in < 0) {
      fprintf(stderr, "%s: %s: No such file\n", argv[0], fname);
      continue;
    }
    
    if (fstat(fd_in, &st)) {
      continue;
    }
    
    if (!S_ISREG(st.st_mode)) {
      fprintf(stderr, "%s: %s is not a regular file\n", argv[0], fname);
      continue;
    }

    MD5Init(&c);

    while (1) {
      ret = read(fd_in, buf, sizeof(buf));
      if (ret < 0) {
	if (errno != EINTR) {
	  perror("md5test read error");
	  break;
	}
	continue;
      } else if (ret == 0) {
	break;
      }
      MD5Update(&c, buf, ret);
    }

    close(fd_in);

    MD5Final((unsigned char *) buf, &c);

    sprintf(md5sum,
	    "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x",
	    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6],
	    buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13],
	    buf[14], buf[15]);

    place = checksums;
    for (j = 0; j < n_sums; j++) {
      if (strcasecmp(md5sum, place) == 0) {
	if (j == 0) {
	  printf("OK:  %s\n", fname);
	} else {
	  printf("OK:  %s (%d%s checksum in nfo)\n", fname, j + 1, j == 1 ? "nd" : (j == 2 ? "rd" : "th"));
	}
	break;
      } 
      place += 33;
    }

    if (j == n_sums) {
      printf("BAD: %s\n", fname);
    }

    fflush(stdout);
    fflush(stderr);

    free(checksums);
  }
  return 0;
}
