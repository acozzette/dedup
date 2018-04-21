#define _GNU_SOURCE
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <sys/stat.h>
#include <unistd.h>

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
#include <zlog.h>
#include "BUSE/buse.h"

/* We start with an 1 GB toy image file. */
#define IMAGE "image"
#define SIZE (11ull * 1024ull * 1024ull * 1024ull)

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

/* The size of the fingerprint cache, described in terms of how many bits are
 * used to determine the location of a cache line. Here, we use the first 20
 * bits of the fingerprint, which allows us to store 1M entries, each 32B, for a
 * total cache that uses 32 MB of memory. */
#define CACHE_SIZE 20

zlog_category_t* log_category;
zlog_category_t* cache_category;

#define MIN(x, y) ((x) < (y) ? (x) : (y))

struct hash_index_entry {
    char hash[FINGERPRINT_SIZE];
    uint64_t hash_log_address;
};

typedef struct hash_index_entry hash_bucket[ENTRIES_PER_BUCKET];

struct hash_log_entry {
    char fingerprint[FINGERPRINT_SIZE];
    uint32_t ref_count;
    uint64_t pbn;
};

/* Forward declaration */
static int read_one_block(void *buf, uint32_t len, uint64_t offset);

/* FIXME: BUSE should be modified to include a mechanism for storing state that
 * does not require global variables. */
static int fd;
static void *zeros;
static struct hash_log_entry *cache;
static uint64_t hash_log_free_list;
static uint64_t data_log_free_list;

static void usage()
{
    fprintf(stderr, "Usage: ./dedup [-i | -n] /dev/nbd[0-9]\n");
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
            // bucket[i] is an entry of hash_index which contains a fingerprint and a hash_log_address

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
    int err = write(fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));
    hash_log_free_list = hash_log_address;

    return 0;
}

static uint64_t physical_block_new()
{
    uint64_t new_block = data_log_free_list;
    SEEK_TO_DATA_LOG(fd, new_block, 0);
    int err = read(fd, &data_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));

    return new_block;
}

static int physical_block_free(uint64_t pbn)
{
    SEEK_TO_DATA_LOG(fd, pbn, 0);
    int err = write(fd, &data_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));
    data_log_free_list = pbn;

    return 0;
}

/* Initialize the underlying block device. */
static int init()
{
    uint64_t i;
    uint64_t err;

//    err = write(fd, zeros, BLOCK_MAP_SIZE + HASH_INDEX_SIZE);
    void *new_zeros = malloc(BLOCK_MAP_SIZE+HASH_INDEX_SIZE);
    err = write(fd, new_zeros, BLOCK_MAP_SIZE+HASH_INDEX_SIZE);
    printf("%lu\n", err);
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

/* Given a fingerprint, return the index where it can (potentially) be found in
 * the cache. */
static u_int32_t get_cache_index(char *fingerprint)
{
    /* It doesn't actually matter which bits we choose, as long as we are
     * consistent. So let's treat the first four bytes as an integer and take
     * the lower bits of that. */
    u_int32_t mask = (1 << CACHE_SIZE) - 1;
    u_int32_t result = ((u_int32_t *)fingerprint)[0] & mask;
    assert(result < mask);
    return result;
}

static struct hash_log_entry lookup_fingerprint(char *fingerprint)
{
    int err;
    char log_line[1024 * 1024];

    u_int32_t index = get_cache_index(fingerprint);
    if (!memcmp(fingerprint, cache[index].fingerprint, FINGERPRINT_SIZE)) {
        /* Awesome, this fingerprint is already cached, so we are good to go. */
        sprintf(log_line, "1");
        zlog_info(cache_category, log_line);
        return cache[index];
    }
    sprintf(log_line, "0");
    zlog_info(cache_category, log_line);

    /* Otherwise we have to look on disk. */
    uint64_t hash_log_address = hash_index_lookup(fingerprint);
    assert(hash_log_address != (uint64_t)-1);

    /* Now let's look up everything in the 4K block containing the hash log
     * entry we want. This way we can cache it all for later. */
    // fixme
    hash_log_address -= hash_log_address % BLOCK_SIZE;
    SEEK_TO_HASH_LOG(fd, hash_log_address);
    struct hash_log_entry h;

    for (unsigned i = 0; i < BLOCK_SIZE/sizeof(struct hash_log_entry); i++) {
        err = read(fd, &h, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));

        u_int32_t j = get_cache_index(h.fingerprint);
        memcpy(cache + j, &h, FINGERPRINT_SIZE);
    }

    /* Now we should have looked up the fingerprint we wanted, along with a
     * bunch of others. */

    err = memcmp(fingerprint, cache[index].fingerprint, FINGERPRINT_SIZE);
    if (err != 0) {
        hash_log_address = hash_index_lookup(fingerprint);
        SEEK_TO_HASH_LOG(fd, hash_log_address);
        struct hash_log_entry h_tmp;
        err = read(fd, &h_tmp, sizeof(struct hash_log_entry));
//        fprintf(stderr, "hash log entry: %02x\nfingerprint: %02x\n", h_tmp.fingerprint, fingerprint);
    }

    return cache[index];
}

static int decrement_refcount(char *fingerprint)
{
    struct hash_log_entry hle;
    uint64_t hash_log_address = hash_index_lookup(fingerprint);
    SEEK_TO_HASH_LOG(fd, hash_log_address);
    int err = read(fd, &hle, sizeof(struct hash_log_entry));
    assert(err == sizeof(struct hash_log_entry));

    if (hle.ref_count > 1) {
        hle.ref_count--;
        SEEK_TO_HASH_LOG(fd, hash_log_address);
        err = write(fd, &hle, sizeof(struct hash_log_entry));
    } else {
        /* The ref_count is now zero, so we need to do some garbage collection
         * here. */
        hash_index_remove(fingerprint);
        physical_block_free(hle.pbn);
        hash_log_free(hash_log_address);
    }

    return 0;
}

/* Write an extent that is guaranteed to lie within a single virtual (and
 * physical) block. */
static int write_one_block(const void *buf, uint32_t len, uint64_t offset)
{
    char log_line[1024*1024];
    int err;
    char fingerprint[FINGERPRINT_SIZE];
    uint64_t vbn = offset / BLOCK_SIZE;
    uint64_t hash_log_address;
    struct hash_log_entry new_entry;

    assert((offset % BLOCK_SIZE)+ len <= BLOCK_SIZE);

    SEEK_TO_BLOCK_MAP(fd, vbn);
    err = read(fd, fingerprint, FINGERPRINT_SIZE);
    assert(err == FINGERPRINT_SIZE);

    if (!fingerprint_is_zero(fingerprint)) {
        /* We need to decrement the refcount for the old fingerprint. */
        decrement_refcount(fingerprint);
    }

    if (len != BLOCK_SIZE) {
        /* We need to read in the existing block and apply our changes to it so
         * that we can determine the fingerprint. */
        void *newbuf = malloc(BLOCK_SIZE);
        read_one_block(newbuf, BLOCK_SIZE, 0);
        memcpy((char *)newbuf + (offset % BLOCK_SIZE), buf, len);
        SHA1(newbuf, BLOCK_SIZE, (unsigned char *)fingerprint);
        free(newbuf);
    } else
        SHA1(buf, BLOCK_SIZE, (unsigned char *)fingerprint);

    /* Compute the fingerprint of the new block and update the block map. */
    SEEK_TO_BLOCK_MAP(fd, vbn);
    err = write(fd, fingerprint, FINGERPRINT_SIZE);
    assert(err == FINGERPRINT_SIZE);

    /* See if this fingerprint is already stored. */
    hash_log_address = hash_index_lookup(fingerprint);
    if (hash_log_address == (uint64_t) -1) {
        sprintf(log_line, "[REDUNDANT] | len: %u, offset: %lu", len, offset);
        zlog_info(log_category, log_line);
        /* This block is new. */
        memcpy(&(new_entry.fingerprint), fingerprint, FINGERPRINT_SIZE);
        new_entry.pbn = physical_block_new();
        new_entry.ref_count = 1;
        hash_log_address = hash_log_new();
        hash_index_insert(fingerprint, hash_log_address);
        SEEK_TO_HASH_LOG(fd, hash_log_address);
        err = write(fd, &new_entry, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));
        SEEK_TO_DATA_LOG(fd, new_entry.pbn, offset % BLOCK_SIZE);
        err = write(fd, buf, len);
        assert(err == (int)len);
    } else {
        sprintf(log_line, "[NEW] | len: %u, offset: %lu", len, offset);
        zlog_info(log_category, log_line);
        /* This block has already been stored. We just need to increment the
         * refcount. */
        SEEK_TO_HASH_LOG(fd, hash_log_address);
        err = read(fd, &new_entry, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));
        new_entry.ref_count += 1;
        SEEK_TO_HASH_LOG(fd, hash_log_address);
        err = write(fd, &new_entry, sizeof(struct hash_log_entry));
        assert(err == sizeof(struct hash_log_entry));
    }

    return 0;
}

static int dedup_write(const void *buf, uint32_t len, uint64_t offset)
{
    const char *bufi = buf;
    uint32_t displacement = offset % BLOCK_SIZE;

    /* If we don't begin on a block boundary, handle that case separately. */
    if (displacement != 0) {
        uint32_t write_size = MIN(len, BLOCK_SIZE - displacement);
        write_one_block(bufi, write_size, offset);
        bufi += write_size;
        len -= write_size;
        offset += write_size;
    }
    /* Now handle the full blocks. */
    while (len > BLOCK_SIZE) {
        assert(offset % BLOCK_SIZE == 0);
        write_one_block(bufi, BLOCK_SIZE, offset);
        bufi += BLOCK_SIZE;
        len -= BLOCK_SIZE;
        offset += BLOCK_SIZE;
    }
    /* Finally, handle the case where we don't end on a block boundary. */
    if (len != 0)
        write_one_block(bufi, len, offset);

    return 0;
}

/* Read an extent that is guaranteed to lie within a single virtual (and
 * physical) block. */
static int read_one_block(void *buf, uint32_t len, uint64_t offset)
{
    int err;
    char fingerprint[FINGERPRINT_SIZE];
    uint64_t vbn = offset / BLOCK_SIZE;
    SEEK_TO_BLOCK_MAP(fd, vbn);
    err = read(fd, fingerprint, FINGERPRINT_SIZE);
    assert(err == FINGERPRINT_SIZE);

    if (fingerprint_is_zero(fingerprint)) {
        memset(buf, 0, len);
        return 0;
    }

    /* Otherwise, we must look up the physical block corresponding to this
     * virtual block. */
    struct hash_log_entry h = lookup_fingerprint(fingerprint);

    SEEK_TO_DATA_LOG(fd, h.pbn, offset % BLOCK_SIZE);
    err = read(fd, buf, len);
    assert(err == (int)len);

    return 0;
}

static int dedup_read(void *buf, uint32_t len, uint64_t offset)
{
    char *bufi = buf;
    uint32_t displacement = offset % BLOCK_SIZE;

    /* If we don't begin on a block boundary, handle that case separately. */
    if (displacement != 0) {
        uint32_t read_size = MIN(len, BLOCK_SIZE - displacement);
        read_one_block(bufi, read_size, offset);
        bufi += read_size;
        len -= read_size;
        offset += read_size;
    }
    /* Now handle the full blocks. */
    while (len > BLOCK_SIZE) {
        assert(offset % BLOCK_SIZE == 0);
        read_one_block(bufi, BLOCK_SIZE, offset);
        bufi += BLOCK_SIZE;
        len -= BLOCK_SIZE;
        offset += BLOCK_SIZE;
    }
    /* Finally, handle the case where we don't end on a block boundary. */
    if (len != 0)
        read_one_block(bufi, len, offset);

    return 0;
}

/* Called upon receipt of a disconnect request. We need to make sure everything
 * is written to stable storage before this function returns. */
static int dedup_disc()
{
    int err;

    fprintf(stderr, "Just received a disconnect request.\n");
    SEEK_TO_HASH_LOG(fd, 0);
    err = write(fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));

    SEEK_TO_DATA_LOG(fd, 0, 0);
    err = write(fd, &data_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));

    return 0;
}

static int dedup_flush()
{
    fprintf(stderr, "Just received a flush request.\n");
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
    (void) print_debug_info;
    printf("block map size + hash index size: %llu,\n", BLOCK_MAP_SIZE + HASH_INDEX_SIZE);

    int err;

    if (argc != 3) {
        usage();
        return -1;
    }

    err = zlog_init("../zlog.conf");
    if(err) {
        fprintf(stderr, "zlog init failed\n");
        return -1;
    }
    log_category = zlog_get_category("fixed_chunk");
    cache_category = zlog_get_category("cache");


    fd = open64("/home/cyril/mnt/IMAGE", O_CREAT|O_RDWR|O_LARGEFILE);
    assert(fd != -1);

    /* We mmap a bunch of zeros into memory. This way we can write it directly
     * into the file to zero out the block map and hash index. */
    zeros = mmap(NULL, BLOCK_MAP_SIZE + HASH_INDEX_SIZE, PROT_READ,
            MAP_PRIVATE|MAP_ANONYMOUS, fd, 0);
    assert(zeros != (void *)-1);

    if (!strcmp(argv[1], "-i")) {
        fprintf(stderr, "Performing initialization.\n");
        init();
        return 0;
    }

    /* By convention the first entry in the hash log is a pointer to the hash
     * log free list. Likewise for the data log. */
    SEEK_TO_HASH_LOG(fd, 0);
    err = read(fd, &hash_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));
    SEEK_TO_DATA_LOG(fd, 0, 0);
    err = read(fd, &data_log_free_list, sizeof(uint64_t));
    assert(err == sizeof(uint64_t));

    struct buse_operations bop = {
        .read = dedup_read,
        .write = dedup_write,
        .disc = dedup_disc,
        .flush = dedup_flush,
        .trim = dedup_trim,
        .size = NVIRT_BLOCKS * 4096,
    };

    cache = calloc(1 << CACHE_SIZE, sizeof(struct hash_log_entry));
    buse_main(argv[2], &bop, NULL);
    free(cache);
    zlog_fini();
    return 0;
}
