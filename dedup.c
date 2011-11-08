#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "buse.h"

/* We start with an 8 GB toy image file. */
#define IMAGE "image"
#define SIZE (8ull * 1024ull * 1024ull * 1024ull)

/* 4KB block size */
#define BLOCK_SIZE (4 * 1024)

/* We advertise twice as many virtual blocks as we have physical blocks. */
#define NPHYS_BLOCKS (SIZE / BLOCK_SIZE)
#define NVIRT_BLOCKS (2 * NPHYS_BLOCKS)

struct hash_log_entry {
    uint64_t pbn;
    uint64_t ref_count;
};

/* Main on-disk data structures: block map, hash index, and hash log. */
#define BLOCK_MAP_SIZE (NVIRT_BLOCKS * sizeof(uint64_t))
#define HASH_INDEX_SIZE BLOCK_MAP_SIZE
#define HASH_LOG_SIZE (NPHYS_BLOCKS * sizeof(struct hash_log_entry))

/* Seek to hash log entry i. */
#define SEEK_TO_HASH_LOG(fd, i) \
    do { lseek64((fd), BLOCK_MAP_SIZE + HASH_INDEX_SIZE + \
            (i)*sizeof(struct hash_log_entry), SEEK_SET); \
    } while(0)

/* Seek to data log entry i. */
#define SEEK_TO_DATA_LOG(fd, i) \
    do { lseek64((fd), BLOCK_MAP_SIZE + HASH_INDEX_SIZE + HASH_LOG_SIZE + \
            (i)*BLOCK_SIZE, SEEK_SET); \
    } while(0)

static void usage()
{
    fprintf(stderr, "Usage: ./dedup\n");
}

static void print_debug_info()
{
    fprintf(stderr, "SIZE is %llu\n", SIZE);
    fprintf(stderr, "BLOCK_MAP_SIZE is %llu\n", BLOCK_MAP_SIZE);
    fprintf(stderr, "HASH_INDEX_SIZE is %llu\n", HASH_INDEX_SIZE);
    fprintf(stderr, "HASH_LOG_SIZE is %llu\n", HASH_LOG_SIZE);
}

/* Initialize the underlying block device. */
static int init()
{
    uint64_t i;
    int fd;
    int err;
    void *zeros;

    fd = open(IMAGE, O_RDWR|O_LARGEFILE);
    assert(fd != -1);

    /* We mmap a bunch of zeros into memory. This way we can write it directly
     * into the file to zero out the block map and hash index. */
    zeros = mmap(NULL, BLOCK_MAP_SIZE + HASH_INDEX_SIZE, PROT_READ,
            MAP_PRIVATE|MAP_ANONYMOUS, fd, 0);
    assert(zeros != (void *)-1);
    err = write(fd, zeros, BLOCK_MAP_SIZE + HASH_INDEX_SIZE);
    assert(err == BLOCK_MAP_SIZE + HASH_INDEX_SIZE);
    assert(!munmap(zeros, BLOCK_MAP_SIZE + HASH_INDEX_SIZE));

    /* We now initialize the hash log and data log. These start out empty, so we
     * put everything in the free list. It might be more efficient to stage this
     * in memory and then write it out in larger blocks. But the Linux buffer
     * cache will probably take care of that anyway for now. */
    for (i = 1; i <= NPHYS_BLOCKS; i++) {
        SEEK_TO_HASH_LOG(fd, i - 1);
        err = write(fd, &i, sizeof(uint64_t));
        assert(err == sizeof(uint64_t));
    }
    for (i = 1; i <= NPHYS_BLOCKS; i++) {
        SEEK_TO_DATA_LOG(fd, i - 1);
        err = write(fd, &i, sizeof(uint64_t));
        assert(err == sizeof(uint64_t));
    }

    return 0;
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;
    (void) usage;
    (void) print_debug_info;

    print_debug_info();
    init();

    return 0;
}
