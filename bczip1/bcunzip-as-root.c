#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

const char *bczip = "/usr/bin/bczip";

int main(int argc, char **argv) {
    int zip_fd;
    char temp_dirname[] = "/tmp/bcuzXXXXXX";
    int res;
    char *res_p;
    char dev_fd_buf[80];
    pid_t kid;
    if (argc != 2) {
	fprintf(stderr, "Usage: bcunzip-as-root archive.bcz\n");
	exit(1);
    }
    zip_fd = open(argv[1], O_RDONLY);
    if (zip_fd == -1) {
	fprintf(stderr, "Failed to open %s for reading: %s\n",
		argv[1], strerror(errno));
	exit(1);
    }
    res = fcntl(zip_fd, F_SETFD, 0);
    if (res == -1) {
	fprintf(stderr, "Failed to clear CLOEXEC: %s\n", strerror(errno));
	exit(1);
    }
    res_p = mkdtemp(temp_dirname);
    if (!res_p) {
	fprintf(stderr, "Failed to choose a temporary directory name: %s\n",
		strerror(errno));
	exit(1);
    }
    res = chdir(temp_dirname);
    if (res) {
	fprintf(stderr, "Failed to chdir to /tmp/%s: %s\n",
		temp_dirname, strerror(errno));
	exit(1);
    }
    snprintf(dev_fd_buf, sizeof(dev_fd_buf), "/dev/fd/%d", zip_fd);
    if (!(kid = fork())) {
	/* child process */
	res = execl(bczip, "bczip", "x", dev_fd_buf, (char *)0);
	fprintf(stderr, "Exec of bczip failed: %s\n", strerror(errno));
	exit(1);
    }
    /* parent process */
    wait(&res);
    chmod(".", 0755);
    return 0;
}
