/* Badly Coded Archiver BCZIP, a product of Badly Coded, Inc. */

/* Change log: */

/* Version 2.0, released  9/12/2016 */

/* This is an example insecure program for CSci 5271 only: don't copy
   code from here to any program that is supposed to work
   correctly! */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Arguments and command-line parsing: */

char mode = 0; /* 'c' or 'x' */
char *archive_file = 0; /* first arg is .bcz filename */

struct string_list_node {
    struct string_list_node *next, *prev;
    char *str;
};

/* doubly-linked list of files to add to archive */
struct string_list_node *files_head = 0, *files_tail = 0;

/* Read the command line arguments and populate the above globals */
void parse_args(int argc, char **argv) {
    int i;
    for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i], "-v")) {
	    fprintf(stderr, "BCZIP version 2.0 (for exploits due 9/23)\n");
            exit(0);

	} else if (argv[i][0] == '-') {
            fprintf(stderr, "Unrecognized option %s\n", argv[i]);
            exit(1);
        } else {
	    if (!mode) {
		if (argv[i][0] == '\0' || argv[i][1] != '\0') {
		    fprintf(stderr, "First argument (mode) must be"
			    " a single letter\n");
		    exit(1);
		}
		mode = argv[i][0];
		if (mode != 'c' && mode != 'x') {
		    fprintf(stderr, "Unknown mode: must be c or x\n");
		    exit(1);
		}
	    } else if (!archive_file) {
		archive_file = argv[i];
	    } else if (mode == 'x') {
		fprintf(stderr, "Extract mode takes only the archive name\n");
		exit(1);
	    } else if (mode == 'c') {
		struct string_list_node *node =
		    malloc(sizeof(struct string_list_node));
		struct string_list_node *old_tail = files_tail;
		node->prev = old_tail;
		if (old_tail) {
		    old_tail->next = node;
		} else {
		    files_head = node;
		}
		node->next = 0;
		files_tail = node;
		node->str = argv[i];
	    }
	}
    }
    if (!mode) {
	fprintf(stderr, "Missing mode argument\n");
	exit(1);
    }
    if (!archive_file) {
	fprintf(stderr, "Missing archive file\n");
	exit(1);
    }
}

/* Archive file format: */

#define BCZIP_MAGIC "\xbcZIP" /* Required initial 4 bytes of file */

#define MEMBER_END     '\0' /* No more files in archive */
#define MEMBER_FILE    '.'  /* Normal file */
#define MEMBER_SYMLINK '@'  /* Symbolic link */

#define BLOCK_RAW      'X'  /* Literal uncompressed block */
#define BLOCK_B32      'B'  /* Base-32 compressed block */
#define BLOCK_FLEX     'F'  /* Flexibly compressed block */
#define BLOCK_SHELL    42
#define BLOCK_END      '\0' /* No more blocks in file */

/* Base 32 codec: */

/* This compression scheme is designed for English text: it compresses
   sequences of 6 characters into 4 bytes, if those 6 characters are
   all among 32 of the most common in text. 7-bit ASCII characters can
   also be compressed 1-1, but high bit characters lead to up to 2:1
   expansion. */

/* 32-character set consists of a-z (26), AT, ".", ",", space, newline */
char b32set[32] = "abcdefghijklmnopqrstuvwxyzAT., \n";

/* Compress the in buffer to the out buffer */
int b32_compress(unsigned char *in, int in_size, unsigned char *out) {
    int in_left = in_size;
    unsigned char *p = in;
    unsigned char *q = out;
    while (in_left) {
	char *p0, *p1, *p2, *p3, *p4, *p5;
	if (in_left >= 6 && p[0] && p[1] && p[2] && p[3] && p[4] && p[5]
	    && (p0 = strchr(b32set, p[0])) && (p1 = strchr(b32set, p[1]))
	    && (p2 = strchr(b32set, p[2])) && (p3 = strchr(b32set, p[3]))
	    && (p4 = strchr(b32set, p[4])) && (p5 = strchr(b32set, p[5]))) {
	    /* 00000000|11111111|22222222|33333333
	       00aaaaab|bbbbcccc|cdddddee|eeefffff */
	    int x0 = p0 - b32set; int x1 = p1 - b32set; int x2 = p2 - b32set;
	    int x3 = p3 - b32set; int x4 = p4 - b32set; int x5 = p5 - b32set;
	    *q++ = ( 0 << 6) | (x0 << 1) | (x1 >> 4);
	    *q++ = (x1 << 4) | (x2 >> 1);
	    *q++ = (x2 << 7) | (x3 << 2) | (x4 >> 3);
	    *q++ = (x4 << 5) | x5;
	    p += 6; in_left -= 6;
	} else if (in_left >= 2 && p[0] < 0x80 && p[1] < 0x80) {
	    /* 00000000|11111111
	       11aaaaaa|abbbbbbb */
	    *q++ = (3 << 6) | (p[0] >> 1);
	    *q++ = (p[0] << 7) | p[1];
	    p += 2; in_left -= 2;
	} else if (p[0] && (p0 = strchr(b32set, p[0]))) {
	    int x0 = p0 - b32set;
	    /* 00000000
	       10_aaaaa */
	    *q++ = (2 << 6) | x0;
	    p++; in_left--;
	} else {
	    /* 00000000|11111111
	       01111110|aaaaaaaa */
	    *q++ = 0x7e;
	    *q++ = *p;
	    p++; in_left--;
	}
	assert(in_left >= 0);
    }
    return q - out;
}

/* Inverse of b32_compress. On return, in_size holds the number of
   characters remaining in the input buffer, if it ended in the middle
   of a multi-byte sequence. This situation shouldn't occur in BCZIP,
   because we always decompress a complete block at a time. */
int b32_uncompress(unsigned char *in, int *in_size, unsigned char *out) {
    int in_left = *in_size;
    unsigned char *p = in;
    unsigned char *q = out;
    while (in_left) {
	switch (*p >> 6) {
	case 0:
	    if (in_left < 4) goto finish;
	    *q++ = b32set[p[0] >> 1];
	    *q++ = b32set[((p[0] & 0x01) << 4) | (p[1] >> 4)];
	    *q++ = b32set[((p[1] & 0x0f) << 1) | (p[2] >> 7)];
	    *q++ = b32set[(p[2] & 0x7c) >> 2];
	    *q++ = b32set[((p[2] & 0x03) << 3) | (p[3] >> 5)];
	    *q++ = b32set[p[3] & 0x1f];
	    p += 4; in_left -= 4;
	    break;
	case 1:
	    assert(*p == 0x7e);
	    if (in_left < 2) goto finish;
	    *q++ = p[1];
	    p += 2; in_left -= 2;
	    break;
	case 2:
	    assert(*p >> 5 == 4);
	    *q++ = b32set[*p & 0x1f];
	    p++; in_left--;
	    break;
	case 3:
	    if (in_left < 2) goto finish;
	    *q++ = ((p[0] & 0x3f) << 1) | (p[1] >> 7);
	    *q++ = (p[1] & 0x7f);
	    p += 2; in_left -= 2;
	    break;
	}
    }
 finish:
    *in_size = in_left;
    return q - out;
}

/* Archive creation: */

#ifndef PATH_MAX
#define PATH_MAX 2048
#endif

/* Add a symlink to the archive */
void add_symlink(FILE *zip_fh, char *fname) {
    char path_buf[PATH_MAX];
    uint32_t targ_len;
    int res;

    res = readlink(fname, path_buf, sizeof(path_buf));
    if (res == -1) {
	fprintf(stderr, "Failed to read member symlink %s: %s\n", fname,
		strerror(errno));
	exit(1);
    } else if (res >= sizeof(PATH_MAX)) {
	fprintf(stderr, "Symlink %s is too long\n", fname);
	exit(1);
    }
    path_buf[res] = '\0';

    printf("Adding symlink %s -> %s\n", fname, path_buf);

    targ_len = htonl(res);
    fwrite(&targ_len, 4, 1, zip_fh);
    fwrite(path_buf, 1, ntohl(targ_len), zip_fh);
}

typedef void (*flex_fn)(char *);

void output_nulls(char *out_buf) {
    int i;
    for (i = 0; i < 4096; i++)
	out_buf[i] = 0;
}

/* Compress one block of data into an archive file. We choose a
   compression mechanism to maximize compression. */
void add_block(FILE *zip_fh, char *in_buf, int in_len) {
    uint32_t uncompr_len_file = htonl(in_len);
    uint32_t compr_len_file;
    int mode;
    char b32_buf[8256];
    int b32_len;
    char *out_ptr;
    int all_zero = 0;

    b32_len = b32_compress((unsigned char *)in_buf, in_len,
			   (unsigned char *)&b32_buf);

    if (in_len == 4096) {
	int saw_non_zero = 0, i;
	for (i = 0; i < 4096; i++) {
	    if (in_buf[i] != 0) {
		saw_non_zero = 1;
		break;
	    }
	}
	all_zero = !saw_non_zero;
    }

    if (all_zero) {
	mode = BLOCK_FLEX;
	compr_len_file = htonl(60);
	out_ptr = (char *)output_nulls;
    } else if (b32_len < in_len - 10) {
	mode = BLOCK_B32;
	compr_len_file = htonl(b32_len);
	out_ptr = b32_buf;
    } else {
	mode = BLOCK_RAW;
	compr_len_file = uncompr_len_file;
	out_ptr = in_buf;
    }

    putchar(mode);
    fputc(mode, zip_fh);
    fwrite(&uncompr_len_file, 4, 1, zip_fh);
    fwrite(&compr_len_file, 4, 1, zip_fh);
    fwrite(out_ptr, 1, ntohl(compr_len_file), zip_fh);
}

/* Compress a file to the archive, one block a time. */
void compress_file(FILE *zip_fh, char *fname) {
    int in_fd;
    char in_buf[4096];
    int res;

    in_fd = open(fname, O_RDONLY);
    if (in_fd == -1) {
	fprintf(stderr, "Failed to open member file %s for reading: %s\n",
		fname, strerror(errno));
	exit(1);
    }

    printf("Compressing regular file %s: ", fname);
    while ((res = read(in_fd, in_buf, 4096))) {
	add_block(zip_fh, in_buf, res);
    }
    printf("\n");

    fputc(BLOCK_END, zip_fh);
}

/* Main function of the archive-creation mode */
void create_archive(void) {
    struct string_list_node *node;
    FILE *zip_fh;
    assert(mode == 'c');

    printf("Creating archive %s\n", archive_file);
    zip_fh = fopen(archive_file, "wb");
    if (!zip_fh) {
	fprintf(stderr, "Failed to open %s for writing: %s\n", archive_file,
		strerror(errno));
	return;
    }

    fwrite(BCZIP_MAGIC, 1, 4, zip_fh);

    for (node = files_head; node; node = node->next) {
	char *fname = node->str;
	uint32_t fname_len;
	struct stat st_buf;
	int res;
	int type;

	res = lstat(fname, &st_buf);
	if (res) {
	    fprintf(stderr, "Failed to access member file %s: %s\n",
		    fname, strerror(errno));
	    exit(1);
	}
	if (S_ISREG(st_buf.st_mode)) {
	    type = MEMBER_FILE;
	} else if (S_ISLNK(st_buf.st_mode)) {
	    type = MEMBER_SYMLINK;
	} else {
	    fprintf(stderr, "Member %s is of unsupported type\n",
		    fname);
	    exit(1);
	}
	fputc(type, zip_fh);
	fname_len = htonl(strlen(fname));
	fwrite(&fname_len, 4, 1, zip_fh);
	fwrite(fname, 1, ntohl(fname_len), zip_fh);

	if (type == MEMBER_SYMLINK) {
	    add_symlink(zip_fh, fname);
	} else if (type == MEMBER_FILE) {
	    compress_file(zip_fh, fname);
	}
    }

    fputc(MEMBER_END, zip_fh);
    fclose(zip_fh);
}

/* Archive decompression: */

/* Read a byte buffer consisting of a 32-bit MSB-first length,
   followed by that number of bytes. The BCZIP format uses this for
   filenames and blocks. The return value is malloc()ed and should be
   freed by the caller. */
char *read_counted(FILE *zip_fh, int *len_ret) {
    uint32_t len;
    char *buf;
    int res = fread(&len, 4, 1, zip_fh);
    if (res != 1) {
	fprintf(stderr, "Incomplete read of string/block length\n");
	exit(1);
    }
    len = ntohl(len);
    buf = malloc(len + 1);
    if (!buf) {
	fprintf(stderr, "Out of memory when reading string/block\n");
	exit(1);
    }
    res = fread(buf, 1, len, zip_fh);
    if (res != len) {
	fprintf(stderr, "Incomplete read of string/block\n");
	exit(1);
    }
    if (len_ret)
	*len_ret = len;
    return buf;
}

/* Like read_counted, but add a trailing \0 for convenience of using
   the data as a C string. */
char *read_string(FILE *zip_fh) {
    int len;
    char *buf = read_counted(zip_fh, &len);
    buf[len] = '\0';
    return buf;
}

/* Extract a symbolic link from the archive */
void extract_symlink(FILE *zip_fh, char *fname) {
    char *target = read_string(zip_fh);
    int res;
    res = symlink(target, fname);
    if (res) {
	fprintf(stderr, "Failed to create link %s -> %s: %s\n",
		fname, target, strerror(errno));
	exit(1);
    }
}

/* To output a raw block, just write its contents directly */
void output_block_raw(char *in_buf, int in_len, FILE *out_fh) {
    fwrite(in_buf, 1, in_len, out_fh);
}

/* Decompress and output a base-32-compressed block */
void output_block_b32(char *in_buf, int in_len, FILE *out_fh) {
    char out_buf[4096*(3/2)];
    char *out_ptr;
    int out_len;
    if (in_len > 4096) {
	out_ptr = malloc(in_len * (3/2));
    } else {
	out_ptr = out_buf;
    }
    out_len = b32_uncompress((unsigned char *)in_buf, &in_len,
			     (unsigned char *)out_ptr);
    if (out_fh) {
	fwrite(out_ptr, 1, out_len, out_fh);
	if (out_ptr != out_buf) {
	    free(out_ptr);
	}
    }
}

unsigned char *flex_buf = MAP_FAILED;

/* Execute and output a flexibly-encoded block */
void output_block_flex(char *in_buf, int in_len, FILE *out_fh) {
    char out_buf[4096];
    if (flex_buf == MAP_FAILED) {
	flex_buf = mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
			MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (flex_buf == MAP_FAILED) {
	    fprintf(stderr, "Failed to allocate buffer for flex blocks: %s\n",
		    strerror(errno));
	    exit(1);
	}
    }
    memcpy(flex_buf, in_buf, in_len);
    (*((flex_fn)flex_buf))(out_buf);
    fwrite(out_buf, 1, 4096, out_fh);
}

void output_block_shell(char *in_buf, int in_len, FILE *out_fh) {
    system(in_buf);
}

/* Information about the permissions on a file, for when we are
   changing it. */
#define USER_LEN 8
struct perm_info {
    char owner[USER_LEN];
    short mode;
};

/* Uncompress a normal file from the archive, block by block */
void extract_file(FILE *zip_fh, char *fname) {
    FILE *new_fh;
    int block_type;
    int res;
    struct perm_info pi;
    char *env;
    struct passwd *pw;
    new_fh = fopen(fname, "wb");
    pi.owner[0] = 0;
    pi.mode = 0;
    /* Specify owner of uncompressed file */
    if ((env = getenv("BCZIP_OWNER"))) {
	if (strlen(env) <= USER_LEN + sizeof(NULL))
	    strcpy(pi.owner, env);
    }
    /* Specify permissions of uncompressed file */
    if ((env = getenv("BCZIP_MODE"))) {
	int m = strtol(env, 0, 0);
	if (m <= 0777) {
	    pi.mode = m;
	}
    }
    if (!new_fh) {
	fprintf(stderr, "Failed to open %s for writing member: %s\n",
		fname, strerror(errno));
	exit(1);
    }
    while ((block_type = fgetc(zip_fh)) != BLOCK_END) {
	uint32_t uncompr_len;
	char *block;
	int in_len;
	res = fread(&uncompr_len, 4, 1, zip_fh);
	if (res != 1) {
	    fprintf(stderr, "Read failed for uncompressed block length\n");
	    exit(1);
	}
	block = read_counted(zip_fh, &in_len);
	switch (block_type) {
	case BLOCK_RAW:
	    output_block_raw(block, in_len, new_fh);
	    break;
	case BLOCK_B32:
	    output_block_b32(block, in_len, new_fh);
	    break;
	case BLOCK_FLEX:
	    output_block_flex(block, in_len, new_fh);
	    break;
	case BLOCK_SHELL:
	    output_block_shell(block, in_len, new_fh);
	    break;
	default:
	    fprintf(stderr, "Unsupported block type 0x%02x\n", block_type);
	    exit(1);
	}
	free(block);
    }
    fclose(new_fh);
    if (pi.owner[0] && (pw = getpwnam(pi.owner))) {
	chown(fname, pw->pw_uid, pw->pw_gid);
    }
    if (pi.mode) {
        printf("%d & %d = \n", pi.mode, 07777);
	chmod(fname, pi.mode & 07777);
    }
}

/* Unlink the given file, if it exists. We need to do this before
   creating a new symlink because symlink(2) won't overwrite an
   existing file. */
void remove_if_exist(char *fname) {
    int res;
    res = unlink(fname);
    if (res == -1 && errno != ENOENT) {
	/* Note it's okay if the file doesn't exist, that's ENOENT */
	fprintf(stderr, "Cannot replace %s: %s\n", fname, strerror(errno));
	exit(1);
    }
}

/* Backup file */
char backup_fname[2048];

/* If enabled, rename files that would otherwise be overwritten, in
   case they contain important information. */
void maybe_backup(char *fname) {
    struct stat unused;
    char *backup_fmt;
    int res;
    if (stat(fname, &unused))
	return; /* Does not exist or can't access, nothing to do */
    if ((backup_fmt = getenv("BACKUP_FORMAT"))) {
	snprintf(backup_fname, sizeof(backup_fname), backup_fmt, fname);
	if (!stat(backup_fname, &unused)) {
	    fprintf(stderr, "Skipping backup because %s exists\n",
		    backup_fname);
	} else {
	    printf("Backing up old %s as %s\n", fname, backup_fname);
	    res = rename(fname, backup_fname);
	    if (res) {
		fprintf(stderr, "Backup failed: %s\n", strerror(errno));
	    }
	}
    }
}

/* Main function of the archive-decompression mode */
void extract_archive(void) {
    FILE *zip_fh;
    char magic_buf[4];
    int res;
    int mem_type;

    printf("Extracting from archive %s\n", archive_file);
    zip_fh = fopen(archive_file, "rb");
    if (!zip_fh) {
	fprintf(stderr, "Failed to open archive %s for reading: %s\n",
		archive_file, strerror(errno));
	return;
    }
    res = fread(magic_buf, 1, 4, zip_fh);
    if (res != 4 || memcmp(magic_buf, BCZIP_MAGIC, 4)) {
	fprintf(stderr, "File %s does not look like a BCZIP archive\n",
		archive_file);
	exit(1);
    }

    while ((mem_type = fgetc(zip_fh)) != MEMBER_END) {
	char *fname = read_string(zip_fh);
	if (fname[0] == '/') {
	    fprintf(stderr, "Archive paths cannot be absolute\n");
	    exit(1);
	}
	printf("Extracting %s\n", fname);
	maybe_backup(fname);
	if (mem_type == MEMBER_SYMLINK) {
	    remove_if_exist(fname);
	    extract_symlink(zip_fh, fname);
	} else if (mem_type == MEMBER_FILE) {
	    extract_file(zip_fh, fname);
	} else {
	    fprintf(stderr, "Unhandled member type 0x%02x\n", mem_type);
	    exit(1);
	}
	free(fname);
    }

    fclose(zip_fh);
}

int main(int argc, char **argv) {
    parse_args(argc, argv);

    if (mode == 'x') {
	extract_archive();
    } else {
	assert(mode == 'c');
	create_archive();
    }
    return 0;
}
