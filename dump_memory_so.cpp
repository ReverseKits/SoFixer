#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define INITIAL_SEGMENT_CAPACITY 16
#define COPY_BUFFER_SIZE 4096

struct segment {
    uint64_t start_address;
    uint64_t end_address;
    uint64_t file_offset;
    char permissions[5];
    char path[PATH_MAX];
};

struct segment_list {
    struct segment *items;
    size_t count;
    size_t capacity;
};

static void usage(const char *program)
{
    fprintf(
        stderr,
        "Usage:\n"
        "  %s <pid> <so-name-or-path> <output-file>\n\n"
        "Examples:\n"
        "  %s 25961 libdpt.so /data/local/tmp/libdpt_dump.so\n"
        "  %s 25961 /data/data/com.example/lib/libfoo.so ./libfoo_dump.so\n",
        program,
        program,
        program
    );
}

static int parse_pid(const char *text, pid_t *pid)
{
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "Invalid PID: %s\n", text);
        return -1;
    }

    if (value <= 0 || value > INT_MAX) {
        fprintf(stderr, "PID out of range: %s\n", text);
        return -1;
    }

    *pid = (pid_t)value;
    return 0;
}

static const char *path_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static int path_matches(const char *mapped_path, const char *requested)
{
    if (strchr(requested, '/') != NULL) {
        return strcmp(mapped_path, requested) == 0;
    }

    return strcmp(path_basename(mapped_path), requested) == 0;
}

static void trim_deleted_suffix(char *path)
{
    static const char suffix[] = " (deleted)";
    size_t path_length = strlen(path);
    size_t suffix_length = sizeof(suffix) - 1;

    if (path_length >= suffix_length &&
        strcmp(path + path_length - suffix_length, suffix) == 0) {
        path[path_length - suffix_length] = '\0';
    }
}

static int segment_list_append(
    struct segment_list *list,
    const struct segment *segment
)
{
    struct segment *new_items;
    size_t new_capacity;

    if (list->count == list->capacity) {
        if (list->capacity > SIZE_MAX / 2 ||
            (list->capacity != 0 &&
             list->capacity * 2 > SIZE_MAX / sizeof(*new_items))) {
            fprintf(stderr, "Too many mappings\n");
            return -1;
        }

        new_capacity = list->capacity == 0
            ? INITIAL_SEGMENT_CAPACITY
            : list->capacity * 2;

        new_items = static_cast<struct segment *>(
            realloc(
                list->items,
                new_capacity * sizeof(*new_items)
            )
        );

        if (new_items == NULL) {
            fprintf(stderr, "realloc failed: %s\n", strerror(errno));
            return -1;
        }

        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = *segment;
    return 0;
}

static int parse_maps_line(
    const char *line,
    struct segment *segment
)
{
    unsigned long long start;
    unsigned long long end;
    unsigned long long offset;
    unsigned int device_major;
    unsigned int device_minor;
    unsigned long long inode;
    char permissions[5] = {0};
    int consumed = 0;
    const char *path;
    size_t path_length;

    int fields = sscanf(
        line,
        "%llx-%llx %4s %llx %x:%x %llu %n",
        &start,
        &end,
        permissions,
        &offset,
        &device_major,
        &device_minor,
        &inode,
        &consumed
    );

    if (fields != 7 || consumed <= 0 || start >= end ||
        strlen(permissions) != 4 ||
        (permissions[0] != 'r' && permissions[0] != '-') ||
        (permissions[1] != 'w' && permissions[1] != '-') ||
        (permissions[2] != 'x' && permissions[2] != '-') ||
        (permissions[3] != 'p' && permissions[3] != 's')) {
        return 0;
    }

    path = line + consumed;

    while (*path == ' ' || *path == '\t') {
        ++path;
    }

    if (*path == '\0' || *path == '\n') {
        return 0;
    }

    path_length = strcspn(path, "\r\n");

    if (path_length == 0 || path_length >= sizeof(segment->path)) {
        return 0;
    }

    memset(segment, 0, sizeof(*segment));

    segment->start_address = (uint64_t)start;
    segment->end_address = (uint64_t)end;
    segment->file_offset = (uint64_t)offset;

    memcpy(
        segment->permissions,
        permissions,
        sizeof(segment->permissions)
    );

    memcpy(segment->path, path, path_length);
    segment->path[path_length] = '\0';

    trim_deleted_suffix(segment->path);

    return 1;
}

static int read_matching_segments(
    pid_t pid,
    const char *requested_so,
    struct segment_list *segments,
    char *resolved_path,
    size_t resolved_path_size
)
{
    char maps_path[64];
    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;
    FILE *maps = NULL;
    int ambiguous = 0;
    int result = -1;

    snprintf(
        maps_path,
        sizeof(maps_path),
        "/proc/%ld/maps",
        (long)pid
    );

    maps = fopen(maps_path, "re");
    if (maps == NULL) {
        fprintf(
            stderr,
            "Cannot open %s: %s\n",
            maps_path,
            strerror(errno)
        );
        return -1;
    }

    while ((line_length = getline(&line, &line_capacity, maps)) >= 0) {
        struct segment segment;

        (void)line_length;

        if (!parse_maps_line(line, &segment)) {
            continue;
        }

        if (!path_matches(segment.path, requested_so)) {
            continue;
        }

        if (resolved_path[0] == '\0') {
            snprintf(
                resolved_path,
                resolved_path_size,
                "%s",
                segment.path
            );
        } else if (strcmp(resolved_path, segment.path) != 0) {
            fprintf(
                stderr,
                "Ambiguous SO name: mappings with the same basename have "
                "different paths:\n"
                "  selected: %s\n"
                "  other:    %s\n"
                "Pass the full mapped path to select one explicitly.\n",
                resolved_path,
                segment.path
            );
            ambiguous = 1;
            continue;
        }

        if (segment_list_append(segments, &segment) != 0) {
            goto cleanup;
        }
    }

    if (ferror(maps)) {
        fprintf(stderr, "Error reading %s\n", maps_path);
        goto cleanup;
    }

    if (ambiguous) {
        goto cleanup;
    }

    if (segments->count == 0) {
        fprintf(
            stderr,
            "No mappings found for \"%s\" in %s\n",
            requested_so,
            maps_path
        );
        goto cleanup;
    }

    result = 0;

cleanup:
    free(line);
    fclose(maps);
    return result;
}

static int calculate_output_layout(
    const struct segment_list *segments,
    uint64_t *base_address,
    uint64_t *output_size
)
{
    uint64_t lowest_address;
    uint64_t highest_address;

    if (segments->count == 0) {
        fprintf(stderr, "Cannot calculate an empty output layout\n");
        return -1;
    }

    lowest_address = segments->items[0].start_address;
    highest_address = segments->items[0].end_address;

    for (size_t i = 1; i < segments->count; ++i) {
        const struct segment *segment = &segments->items[i];

        if (segment->start_address < lowest_address) {
            lowest_address = segment->start_address;
        }

        if (segment->end_address > highest_address) {
            highest_address = segment->end_address;
        }
    }

    if (highest_address <= lowest_address) {
        fprintf(stderr, "Invalid virtual address layout\n");
        return -1;
    }

    *base_address = lowest_address;
    *output_size = highest_address - lowest_address;
    return 0;
}

static void print_segments(const struct segment_list *segments)
{
    fprintf(stderr, "Matched mappings:\n");

    for (size_t i = 0; i < segments->count; ++i) {
        const struct segment *segment = &segments->items[i];
        uint64_t size =
            segment->end_address - segment->start_address;

        fprintf(
            stderr,
            "  [%zu] %016" PRIx64 "-%016" PRIx64
            " %s file_offset=%08" PRIx64
            " size=%08" PRIx64 "\n",
            i,
            segment->start_address,
            segment->end_address,
            segment->permissions,
            segment->file_offset,
            size
        );
    }
}

static int write_all_at(
    int fd,
    const unsigned char *buffer,
    size_t size,
    uint64_t offset
)
{
    size_t completed = 0;

    while (completed < size) {
        ssize_t written = pwrite(
            fd,
            buffer + completed,
            size - completed,
            (off_t)(offset + completed)
        );

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }

            fprintf(
                stderr,
                "pwrite at %#" PRIx64 " failed: %s\n",
                offset + completed,
                strerror(errno)
            );
            return -1;
        }

        if (written == 0) {
            fprintf(
                stderr,
                "pwrite returned zero at %#" PRIx64 "\n",
                offset + completed
            );
            return -1;
        }

        completed += (size_t)written;
    }

    return 0;
}

static int dump_segment(
    int mem_fd,
    int output_fd,
    const struct segment *segment,
    uint64_t output_offset
)
{
    unsigned char buffer[COPY_BUFFER_SIZE];
    uint64_t segment_size =
        segment->end_address - segment->start_address;
    uint64_t completed = 0;

    while (completed < segment_size) {
        uint64_t remaining = segment_size - completed;
        size_t requested = remaining > sizeof(buffer)
            ? sizeof(buffer)
            : (size_t)remaining;

        ssize_t read_size = pread(
            mem_fd,
            buffer,
            requested,
            (off_t)(segment->start_address + completed)
        );

        if (read_size < 0) {
            if (errno == EINTR) {
                continue;
            }

            fprintf(
                stderr,
                "pread memory address %#" PRIx64 " failed: %s\n",
                segment->start_address + completed,
                strerror(errno)
            );
            return -1;
        }

        if (read_size == 0) {
            fprintf(
                stderr,
                "Unexpected EOF at memory address %#" PRIx64 "\n",
                segment->start_address + completed
            );
            return -1;
        }

        if (write_all_at(
                output_fd,
                buffer,
                (size_t)read_size,
                output_offset + completed
            ) != 0) {
            return -1;
        }

        completed += (uint64_t)read_size;
    }

    return 0;
}

static int dump_all_segments(
    pid_t pid,
    const struct segment_list *segments,
    const char *output_path
)
{
    char mem_path[64];
    char *temporary_path = NULL;
    uint64_t base_address;
    uint64_t output_size;
    int mem_fd = -1;
    int output_fd = -1;
    int result = -1;

    if (calculate_output_layout(
            segments,
            &base_address,
            &output_size
        ) != 0) {
        return -1;
    }

    if (output_size == 0 || output_size > (uint64_t)INT64_MAX) {
        fprintf(
            stderr,
            "Invalid output size: %#" PRIx64 "\n",
            output_size
        );
        return -1;
    }

    snprintf(
        mem_path,
        sizeof(mem_path),
        "/proc/%ld/mem",
        (long)pid
    );

    mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);
    if (mem_fd == -1) {
        fprintf(
            stderr,
            "Cannot open %s: %s\n",
            mem_path,
            strerror(errno)
        );
        goto cleanup;
    }

    if (strlen(output_path) > SIZE_MAX - sizeof(".tmp.XXXXXX")) {
        fprintf(stderr, "Output path is too long\n");
        goto cleanup;
    }

    temporary_path = static_cast<char *>(
        malloc(strlen(output_path) + sizeof(".tmp.XXXXXX"))
    );
    if (temporary_path == NULL) {
        fprintf(stderr, "malloc failed: %s\n", strerror(errno));
        goto cleanup;
    }

    snprintf(
        temporary_path,
        strlen(output_path) + sizeof(".tmp.XXXXXX"),
        "%s.tmp.XXXXXX",
        output_path
    );

    output_fd = mkstemp(temporary_path);

    if (output_fd == -1) {
        fprintf(
            stderr,
            "Cannot create temporary output for %s: %s\n",
            output_path,
            strerror(errno)
        );
        goto cleanup;
    }

    if (fcntl(output_fd, F_SETFD, FD_CLOEXEC) == -1) {
        fprintf(stderr, "fcntl(FD_CLOEXEC) failed: %s\n", strerror(errno));
        goto cleanup;
    }

    if (ftruncate(output_fd, (off_t)output_size) == -1) {
        fprintf(
            stderr,
            "ftruncate(%s, %#" PRIx64 ") failed: %s\n",
            output_path,
            output_size,
            strerror(errno)
        );
        goto cleanup;
    }

    /*
     * The temporary file was just created, so bytes not covered by a mapped
     * segment remain zero.  This preserves gaps in the virtual address layout.
     */

    fprintf(
        stderr,
        "Output layout: base=%016" PRIx64
        " end=%016" PRIx64
        " size=%#" PRIx64 "\n",
        base_address,
        base_address + output_size,
        output_size
    );

    for (size_t i = 0; i < segments->count; ++i) {
        const struct segment *segment = &segments->items[i];
        uint64_t output_offset =
            segment->start_address - base_address;

        fprintf(
            stderr,
            "Dumping %016" PRIx64 "-%016" PRIx64
            " -> output offset %#" PRIx64
            " (mapped file offset %#" PRIx64 ")...\n",
            segment->start_address,
            segment->end_address,
            output_offset,
            segment->file_offset
        );

        if (dump_segment(
                mem_fd,
                output_fd,
                segment,
                output_offset
            ) != 0) {
            goto cleanup;
        }
    }

    if (fsync(output_fd) == -1) {
        fprintf(
            stderr,
            "fsync failed: %s\n",
            strerror(errno)
        );
        goto cleanup;
    }

    if (close(output_fd) == -1) {
        output_fd = -1;
        fprintf(stderr, "close output failed: %s\n", strerror(errno));
        goto cleanup;
    }
    output_fd = -1;

    if (rename(temporary_path, output_path) == -1) {
        fprintf(
            stderr,
            "Cannot rename temporary output to %s: %s\n",
            output_path,
            strerror(errno)
        );
        goto cleanup;
    }

    fprintf(
        stderr,
        "Dump completed: %s, size=%#" PRIx64 " (%" PRIu64 " bytes)\n",
        output_path,
        output_size,
        output_size
    );

    result = 0;

cleanup:
    if (output_fd != -1) {
        close(output_fd);
    }

    if (mem_fd != -1) {
        close(mem_fd);
    }

    if (result != 0 && temporary_path != NULL) {
        unlink(temporary_path);
    }

    free(temporary_path);

    return result;
}

static int output_aliases_library(
    const char *library_path,
    const char *output_path
)
{
    struct stat library_stat;
    struct stat output_stat;

    if (strcmp(library_path, output_path) == 0) {
        return 1;
    }

    if (stat(library_path, &library_stat) == -1 ||
        stat(output_path, &output_stat) == -1) {
        return 0;
    }

    return library_stat.st_dev == output_stat.st_dev &&
        library_stat.st_ino == output_stat.st_ino;
}

int main(int argc, char **argv)
{
    pid_t pid;
    const char *requested_so;
    const char *output_path;
    struct segment_list segments = {NULL, 0, 0};
    char resolved_path[PATH_MAX] = {0};
    int result = EXIT_FAILURE;

    if (argc != 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (parse_pid(argv[1], &pid) != 0) {
        return EXIT_FAILURE;
    }

    requested_so = argv[2];
    output_path = argv[3];

    if (read_matching_segments(
            pid,
            requested_so,
            &segments,
            resolved_path,
            sizeof(resolved_path)
        ) != 0) {
        goto cleanup;
    }

    fprintf(stderr, "Selected library: %s\n", resolved_path);
    print_segments(&segments);

    if (output_aliases_library(resolved_path, output_path)) {
        fprintf(
            stderr,
            "Refusing to overwrite the mapped library: %s\n",
            output_path
        );
        goto cleanup;
    }

    if (dump_all_segments(
            pid,
            &segments,
            output_path
        ) != 0) {
        goto cleanup;
    }

    result = EXIT_SUCCESS;

cleanup:
    free(segments.items);
    return result;
}
