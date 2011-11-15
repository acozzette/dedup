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

#define SEEK_TO_BUCKET(fd, i) \
    do { lseek64((fd), BLOCK_MAP_SIZE + (i)*sizeof(hash_bucket), SEEK_SET); \
    } while(0)

/* Seek to hash log entry i. */
#define SEEK_TO_HASH_LOG(fd, i) \
    do { lseek64((fd), BLOCK_MAP_SIZE + HASH_INDEX_SIZE + \
            (i)*sizeof(struct hash_log_entry), SEEK_SET); \
    } while(0)

/* Seek to offset j in data log entry i. */
#define SEEK_TO_DATA_LOG(fd, i, j) \
    do { lseek64((fd), BLOCK_MAP_SIZE + HASH_INDEX_SIZE + HASH_LOG_SIZE + \
            (i)*BLOCK_SIZE + j, SEEK_SET); \
    } while(0)

struct hash_index_entry {
    char hash[FINGERPRINT_SIZE];
    uint64_t hash_log_address;
};

typedef struct hash_index_entry hash_bucket[ENTRIES_PER_BUCKET];

struct hash_log_entry {
    uint64_t pbn;
    uint64_t ref_count;
};

/* FIXME: BUSE should be modified to include a mechanism for storing state that
 * does not require global variables. */
static int fd;
static void *zeros;
static uint64_t hash_log_free_list;

static void usage()
{
    fprintf(stderr, "Usage: ./dedup /dev/nbd[0-9]\n");
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

static int hash_index_get_bucket(char *hash, hash_bucket *bucket)
{
    /* We don't need to look at the entire hash, just the last few bytes. */
    int32_t *hash_tail = (int32_t *)(hash + FINGERPRINT_SIZE - sizeof(int32_t));
    int bucket_index = *hash_tail % NBUCKETS;
    SEEK_TO_BUCKET(fd, bucket_index);
    int err = read(fd, bucket,
            sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);
    assert(err == sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);

    return 0;
}

static int hash_index_put_bucket(char *hash, hash_bucket *bucket)
{
    /* We don't need to look at the entire hash, just the last few bytes. */
    int32_t *hash_tail = (int32_t *)(hash + FINGERPRINT_SIZE - sizeof(int32_t));
    int bucket_index = *hash_tail % NBUCKETS;
    SEEK_TO_BUCKET(fd, bucket_index);
    int err = write(fd, bucket,
            sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);
    assert(err == sizeof(struct hash_index_entry) * ENTRIES_PER_BUCKET);

    return 0;
}

static int hash_index_insert(char *hash, uint64_t hash_log_address)
{
    hash_bucket bucket;
    hash_index_get_bucket(hash, &bucket);

    for (int i = 0; i < ENTRIES_PER_BUCKET; i++)
        if (bucket[i].hash_log_address == 0) {
            /* We have found an empty slot. */
            memcpy(bucket[i].hash, hash, FINGERPRINT_SIZE);
            bucket[i].hash_log_address = hash_log_address;
            hash_index_put_bucket(hash, &bucket);
            return 0;
        }

    /* We failed to find a slot. In the future it would be nice to have a more
     * sophisticated hash table that resolves collisions better. But for now we
     * just give up. */
    assert(0);
}

static uint64_t hash_index_lookup(char *hash)
{
    hash_bucket bucket;
    hash_index_get_bucket(hash, &bucket);

    for (int i = 0; i < ENTRIES_PER_BUCKET; i++)
        if (!memcmp(bucket[i].hash, hash, FINGERPRINT_SIZE))
            return bucket[i].hash_log_address;

    return -1;
}

static int hash_index_remove(char *hash)
{
    hash_bucket bucket;
    hash_index_get_bucket(hash, &bucket);

    for (int i = 0; i < ENTRIES_PER_BUCKET; i++)
        if (!memcmp(bucket[i].hash, hash, FINGERPRINT_SIZE)) {
            memset(bucket + i, 0, sizeof(struct hash_index_entry));
            hash_index_put_bucket(hash, &bucket);
            return 0;
        }

    return -1;
}

static uint64_t hash_log_new()
{
    uint64_t new_block = hash_log_free_list;
    SEEK_TO_HASH_LOG(fd, new_block);
    int err = read(fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));

    return new_block;
}

static int hash_log_free(uint64_t hash_log_address)
{
    SEEK_TO_HASH_LOG(fd, hash_log_address);
    int err = write(fd, &hash_log_address, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));
    hash_log_free_list = hash_log_address;

    return 0;
}

static uint64_t physical_block_new()
{
    return 0;
}

static int physical_block_free(uint64_t pbn)
{
    (void) pbn;

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
        SEEK_TO_DATA_LOG(fd, i - 1, 0);
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

    uint64_t vbn = offset / BLOCK_SIZE;
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
    uint64_t hash_log_address = hash_index_lookup(fingerprint);
    assert(hash_log_address != (uint64_t)-1);

    SEEK_TO_HASH_LOG(fd, hash_log_address);
    struct hash_log_entry h;
    err = read(fd, &h, sizeof(struct hash_log_entry));
    assert(err == sizeof(struct hash_log_entry));

    SEEK_TO_DATA_LOG(fd, h.pbn, offset % BLOCK_SIZE);
    err = read(fd, buf, len);
    /* FIXME: this won't work properly if the requested data spans more than one
     * block. */

    return len;
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
    (void) hash_index_insert;
    (void) hash_index_lookup;
    (void) hash_index_remove;
    (void) hash_log_new;
    (void) hash_log_free;
    (void) print_debug_info;
    (void) physical_block_new;
    (void) physical_block_free;

    int err;

    init();

    /* By convention the first entry in the hash log is a pointer to the hash
     * log free list. */
    SEEK_TO_HASH_LOG(fd, 0);
    err = read(fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));

    struct buse_operations bop = {
        .read = dedup_read,
        .write = dedup_write,
        .disc = dedup_disc,
        .flush = dedup_flush,
        .trim = dedup_trim
    };

    if (argc != 2) {
        usage();
        return -1;
    }

    buse_main(argc, argv, &bop, NULL);

    return 0;
}
