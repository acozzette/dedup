#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <openssl/sha.h>
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

/* Currently using 160-bit (20-byte) SHA-1 hashes as fingerprints. */
#define FINGERPRINT_SIZE 20

/* We advertise twice as many virtual blocks as we have physical blocks. */
#define NPHYS_BLOCKS (SIZE / BLOCK_SIZE)
#define NVIRT_BLOCKS (2 * NPHYS_BLOCKS)

struct hash_index_entry {
    char hash[FINGERPRINT_SIZE];
    uint64_t hash_log_address;
};

struct hash_log_entry {
    uint64_t pbn;
    uint64_t ref_count;
};

/* Main on-disk data structures: block map, hash index, and hash log. */
#define BLOCK_MAP_SIZE (NVIRT_BLOCKS * FINGERPRINT_SIZE)
#define ENTRIES_PER_BUCKET 8
#define NBUCKETS NVIRT_BLOCKS
#define HASH_INDEX_SIZE \
    (ENTRIES_PER_BUCKET * NBUCKETS * sizeof(struct hash_index_entry))
#define HASH_LOG_SIZE (NPHYS_BLOCKS * sizeof(struct hash_log_entry))

/* Seek to block map entry i. */
#define SEEK_TO_BLOCK_MAP(fd, i) \
    do { lseek64((fd), (i)*FINGERPRINT_SIZE, SEEK_SET); } while(0)

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

/* FIXME: BUSE should be modified to include a mechanism for storing state that
 * does not require global variables. */
static int fd;
static void *zeros;

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
    fprintf(stderr, "NPHYS_BLOCKS is %llu\n", NPHYS_BLOCKS);
    fprintf(stderr, "NVIRT_BLOCKS is %llu\n", NVIRT_BLOCKS);
}

static int fingerprint_is_zero(char *fingerprint)
{
    int i;

    for (i = 0; i < FINGERPRINT_SIZE; i++) {
        if (fingerprint[i])
            return 0;
    }

    return 1;
}

static int hash_index_insert(char *hash, uint64_t hash_log_address)
{
    (void) hash;
    (void) hash_log_address;

    return 0;
}

static uint64_t hash_index_lookup(char *hash)
{
    (void) hash;

    return 0;
}

static int hash_index_remove(char *hash)
{
    (void) hash;

    return 0;
}

static uint64_t hash_log_new()
{
    return 0;
}

static int hash_log_free(uint64_t hash_log_address)
{
    (void) hash_log_address;

    return 0;
}

/* Initialize the underlying block device. */
static int init()
{
    uint64_t i;
    int err;

    fd = open(IMAGE, O_RDWR|O_LARGEFILE);
    assert(fd != -1);

    /* We mmap a bunch of zeros into memory. This way we can write it directly
     * into the file to zero out the block map and hash index. */
    zeros = mmap(NULL, BLOCK_MAP_SIZE + HASH_INDEX_SIZE, PROT_READ,
            MAP_PRIVATE|MAP_ANONYMOUS, fd, 0);
    assert(zeros != (void *)-1);
    err = write(fd, zeros, BLOCK_MAP_SIZE + HASH_INDEX_SIZE);
    assert(err == BLOCK_MAP_SIZE + HASH_INDEX_SIZE);

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

static int dedup_write(const void *buf, uint32_t len, uint64_t offset)
{
    (void) buf;
    (void) len;
    (void) offset;
    return 0;
}

static int dedup_read(void *buf, uint32_t len, uint64_t offset)
{
    int err;
    char fingerprint[FINGERPRINT_SIZE];

    uint64_t vbn = offset % BLOCK_SIZE;
    SEEK_TO_BLOCK_MAP(fd, vbn);
    err = read(fd, fingerprint, FINGERPRINT_SIZE);
    assert(err == FINGERPRINT_SIZE);

    if (fingerprint_is_zero(fingerprint)) {
        fprintf(stderr, "This virtual block has not yet been used.\n");
        /* Fill this virtual block with zeros. */
        dedup_write(zeros, BLOCK_SIZE, vbn);
        memset(buf, len, 0);
        return len;
    }

    /* Otherwise, we must look up the physical block corresponding to this
     * virtual block. */

    return 0;
}

static int dedup_disc()
{
    return 0;
}

static int dedup_flush()
{
    return 0;
}

static int dedup_trim(uint64_t from, uint32_t len)
{
    (void) from;
    (void) len;
    return 0;
}

int main(int argc, char *argv[])
{
    (void) usage;
    (void) hash_index_insert;
    (void) hash_index_lookup;
    (void) hash_index_remove;
    (void) hash_log_new;
    (void) hash_log_free;

    print_debug_info();
    init();

    struct buse_operations bop = {
        .read = dedup_read,
        .write = dedup_write,
        .disc = dedup_disc,
        .flush = dedup_flush,
        .trim = dedup_trim
    };

    buse_main(argc, argv, &bop, NULL);

    return 0;
}
