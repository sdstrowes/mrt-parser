#include "input.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int mrt_open(struct mrt_fd **fd_p, bool is_mmap, char *fn)
{
	struct mrt_fd *fd= (struct mrt_fd*)malloc(sizeof(struct mrt_fd));
	if (fd == NULL) {
		fprintf(stderr, "malloc failed: %s\n", strerror(errno));
		return -1;
	}

	*fd_p = fd;
	fd->is_mmap = is_mmap;

	if (is_mmap) {
		// ssize_t      s;

		int file;
		file = open(fn, O_RDONLY);
		if (file == -1) {
			fprintf(stderr, "Could not open file; error: %s\n", strerror(errno));
			free(fd);
			return -1;
		}


		struct stat  sb;
		if (fstat(file, &sb) == -1) {
			fprintf(stderr, "fstat: %s\n", strerror(errno));
			close(file);
			free(fd);
			return -1;
		}
		fd->length = sb.st_size;

		fd->mmap = mmap(NULL, fd->length, PROT_READ, MAP_PRIVATE, file, 0);
		close(file);
		if (fd->mmap == MAP_FAILED) {
			fprintf(stderr, "mmap: %s\n", strerror(errno));
			free(fd);
			return -1;
		}
		madvise(fd->mmap, fd->length, MADV_SEQUENTIAL);
		madvise(fd->mmap, fd->length, MADV_WILLNEED);
		fd->i = 0;
		fd->released = 0;
	}
	else {
		fd->file = gzopen(fn, "r");
		if (fd->file == NULL) {
			fprintf(stderr, "Could not open file; error: %s\n", strerror(errno));
			free(fd);
			return -1;
		}
	}

	return 0;
}

int mrt_read(struct mrt_fd *fd, void *buffer, unsigned int len)
{
	if (fd->is_mmap) {
		if (fd->i + len <= fd->length) { 
			memcpy(buffer, fd->mmap + fd->i, len);
			fd->i += len;
		}
		else {
			return -1;
		}
	}
	else {
		if (gzread(fd->file, buffer, len) != (int)len) {
			if (!gzeof(fd->file)) {
				fprintf(stderr, "gzread error\n");
			}
			return -1;
		}
	}
	return 0;
}

uint8_t *mrt_ptr(struct mrt_fd *fd, uint32_t len)
{
	if (!fd->is_mmap) return NULL;
	if (fd->i + len > fd->length) return NULL;
	uint8_t *ptr = (uint8_t *)(fd->mmap + fd->i);
	fd->i += len;
	return ptr;
}

void mrt_seek(struct mrt_fd *fd, uint32_t delta)
{
	if (fd->is_mmap) {
		if (delta > fd->length - fd->i) {
			fprintf(stderr, "mrt_seek: seek past end of file\n");
			fd->i = fd->length;
		} else {
			fd->i += delta;
		}
	}
	else {
		gzseek(fd->file, delta, SEEK_CUR);
	}
}

void mrt_release(struct mrt_fd *fd)
{
	if (!fd->is_mmap) return;

	static long page_size = 0;
	if (!page_size) page_size = sysconf(_SC_PAGESIZE);

	size_t releasable = (fd->i / (size_t)page_size) * (size_t)page_size;
	if (releasable > fd->released) {
		madvise(fd->mmap + fd->released, releasable - fd->released, MADV_DONTNEED);
		fd->released = releasable;
	}
}

int mrt_close(struct mrt_fd **fd_p)
{
	struct mrt_fd *fd = *fd_p;
	if (fd->is_mmap) {
		munmap(fd->mmap, fd->length);
	}
	else {
		gzclose(fd->file);
	}
	free(fd);

	*fd_p = NULL;

	return 0;
}


