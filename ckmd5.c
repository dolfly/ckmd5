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
#include "version.h"

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

    ret = snprintf(metaname, sizeof(metaname), "%s.md5", fname);
    if (ret >= ((int) sizeof(metaname))) {
      return CKMD5_LONG_NAME;
    }
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


static int open_regular_file(const char *name)
{
  int fd;
  struct stat st;
  fd = open(name, O_RDONLY);

  if (fd < 0) {
    fprintf(stderr, "%s: No such file\n", name);
    return -1;
  }

  if (fstat(fd, &st)) {
    close(fd);
    return -1;
  }

  if (!S_ISREG(st.st_mode)) {
    close(fd);
    fprintf(stderr, "%s is not a regular file\n", name);
    return -1;
  }

  return fd;
}


static void print_version(void)
{
  printf("ckmd5-%s by Heikki Orsila <heikki.orsila@iki.fi>\n", CKMD5_VERSION);
}


static void print_help(char *prog)
{
  printf("ckmd5 usage:\n\n");
  printf(" %s FILE1 FILE2 ...\n\n", prog);
  printf("In addition printing OK / BAD for each checksum found, ckmd5 returns non-zero\n");
  printf("exit code if any of the checked files either didn't have checksum or checksum\n");
  printf("was bad.\n");
}


static int stream_checksum(char *md5str, int fd, size_t md5strlen)
{
  MD5_CTX c;
  unsigned char readbuf[4096];
  unsigned char buf[16];

  int ret = 0;
  ssize_t fret;

  if (md5strlen < 33) {
    fprintf(stderr, "too short a buffer\n");
    exit(-1);
  }

  MD5Init(&c);

  while (1) {
    fret = read(fd, readbuf, sizeof(readbuf));
    if (fret < 0) {
      if (errno != EINTR && errno != EAGAIN) {
	perror("read error");
	ret = 1;
	break;
      }
      continue;
    } else if (fret == 0) {
      break;
    }
    MD5Update(&c, readbuf, fret);
  }

  MD5Final(buf, &c);

  snprintf(md5str, md5strlen,
	   "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x",
	   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6],
	   buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13],
	   buf[14], buf[15]);

  return ret;
}


int main(int argc, char **argv)
{
  int i, j, ret;
  char md5str[33];
  char *fname;
  int fd;
  FILE *metafile;
  int type;
  char *checksums;
  int n_sums;
  char *place;
  int main_ret = 0;

  int check_mode = 0;

  FILE *cf;
  char line[PATH_MAX + 64];
  int linelen;


  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      print_help(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
      print_version();
      return 0;
    }
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--check") == 0) {
      check_mode = 1;
      continue;
    }
    if (strcmp(argv[i], "--") == 0) {
      i++;
      break;
    }
    if (argv[i][0] == '-') {
      fprintf(stderr, "illegal arg: %s\n", argv[i]);
      return 1;
    }
    break;
  }

  if (i == argc) {
    print_help(argv[0]);
    return 0;
  }


  for (; i < argc; i++) {
    fname = argv[i];

    if (check_mode == 0) {
      /* try changing extension to .nfo or .md5 */
      type = get_meta_file(&metafile, fname);
      if (type < CKMD5_ILLEGAL_NAME || type > CKMD5_MD5_NAME) {
	fprintf(stderr, "holy shit. ckmd5 bugs with %s\n", fname);
	main_ret = 1;
	continue;
      } else if (type == CKMD5_ILLEGAL_NAME) {
	continue;
      } else if (type == CKMD5_LONG_NAME) {
	fprintf(stderr, "%s: too long a name\n", fname);
	main_ret = 1;
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
	main_ret = 1;
	continue;
      } else if (type == CKMD5_ILLEGAL_NAME) {
	continue;
      } else if (type == CKMD5_LONG_NAME) {
	fprintf(stderr, "%s: too long a name\n", fname);
	main_ret = 1;
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
	main_ret = 1;
	continue;
      } else if (type == CKMD5_ILLEGAL_NAME) {
	continue;
      } else if (type == CKMD5_LONG_NAME) {
	fprintf(stderr, "%s: too long a name\n", fname);
	main_ret = 1;
	continue;
      } else if (type == CKMD5_NO_META) {
	/* stripping -cd? didn't help. try other tricks. */
	char tempname[PATH_MAX];
	if (strip_strcase(tempname, fname, "-sample", sizeof(tempname))) {
	  type = get_meta_file(&metafile, tempname);
	}
      }
      
      if (type < CKMD5_ILLEGAL_NAME || type > CKMD5_MD5_NAME) {
	fprintf(stderr, "holy shit. ckmd5 is bugs with %s\n", fname);
	main_ret = 1;
	continue;
      } else if (type == CKMD5_ILLEGAL_NAME) {
	continue;
      } else if (type == CKMD5_LONG_NAME) {
	fprintf(stderr, "%s: too long a name\n", fname);
	main_ret = 1;
	continue;
      } else if (type == CKMD5_NO_META) {
	/* tricks didn't help. continue. */
	fprintf(stderr, "%s: can not find .nfo or .md5 file\n", fname);
	main_ret = 1;
	continue;
      }

      checksums = 0;
      n_sums = handle_meta_file(&checksums, metafile, type == CKMD5_NFO_NAME);
      fclose(metafile);
      
      if (n_sums == 0) {
	printf("checksum not found: %s\n", fname);
	main_ret = 1;
	continue;
      }

      fd = open_regular_file(fname);

      if (fd < 0) {
	main_ret = 1;
	continue;
      }

      ret = stream_checksum(md5str, fd, sizeof(md5str));

      close(fd);

      if (ret) {
	main_ret = 1;
	continue;
      }

      place = checksums;
      for (j = 0; j < n_sums; j++) {
	if (strcasecmp(md5str, place) == 0) {
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
	main_ret = 1;
      }

      free(checksums);

    } else {

      cf = fopen(fname, "r");
      if (cf == NULL) {
	main_ret = 1;
	continue;
      }

      while (fgets(line, sizeof(line), cf)) {

	linelen = strlen(line);

	if (linelen < (32 + 2 + 1))
	  continue;

	if (line[linelen - 1] == '\n') {
	  linelen--;
	  line[linelen] = 0;
	}

	if (strspn(line, "0123456789abcdefABCDEF") == 32) {
	  int idx;

	  if (line[32] != ' ')
	    continue;

	  if (line[33] != '*' && line[33] != ' ')
	    continue;

	  idx = 34;

	  /* check that the filename exists */
	  if (line[idx] == 0)
	    continue;

	  line[32] = 0;

	  fd = open_regular_file(&line[idx]);
	  if (fd < 0) {
	    main_ret = 1;
	    continue;
	  }

	  ret = stream_checksum(md5str, fd, sizeof(md5str));
	  close(fd);
	  if (ret) {
	    main_ret = 1;
	    continue;
	  }

	  if (strcasecmp(md5str, line) == 0) {
	    printf("OK:  %s\n", &line[idx]);
	  } else {
	    printf("BAD: %s\n", &line[idx]);
	    main_ret = 1;
	  }
	}
      }

      fclose(cf);
    }

    fflush(stdout);
    fflush(stderr);
  }

  return main_ret;
}
