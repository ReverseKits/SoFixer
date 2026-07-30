#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <vector>

static const size_t COPY_BUFFER_SIZE = 16 * 1024;

struct ElfLayout {
  uint64_t min_vaddr;
  uint64_t max_vaddr;
};

struct Mapping {
  uint64_t start;
  uint64_t end;
  uint64_t offset;
  char permissions[5];
  std::string path;
};

static void usage(const char *program) {
  fprintf(stderr,
          "Usage:\n"
          "  %s <pid> <so-name-or-path> <original-so> <output-file>\n\n"
          "Example:\n"
          "  %s 25961 libfoo.so ./libfoo.so ./libfoo_dump.so\n",
          program, program);
}

static uint64_t page_start(uint64_t value, uint64_t page_size) {
  return value & ~(page_size - 1);
}

static uint64_t page_end(uint64_t value, uint64_t page_size) {
  return page_start(value + page_size - 1, page_size);
}

static bool read_exact(int fd, void *buffer, size_t size, uint64_t offset) {
  size_t done = 0;
  while (done < size) {
    ssize_t count = pread(fd, static_cast<char *>(buffer) + done, size - done,
                          static_cast<off_t>(offset + done));
    if (count < 0 && errno == EINTR)
      continue;
    if (count <= 0)
      return false;
    done += static_cast<size_t>(count);
  }
  return true;
}

template <typename Ehdr, typename Phdr>
static bool parse_load_segments(int fd, uint64_t page_size, ElfLayout *layout) {
  Ehdr ehdr;
  if (!read_exact(fd, &ehdr, sizeof(ehdr), 0) || ehdr.e_phnum == 0 ||
      ehdr.e_phentsize != sizeof(Phdr)) {
    return false;
  }

  uint64_t min_vaddr = UINT64_MAX;
  uint64_t max_vaddr = 0;
  bool found_pt_load = false;

  for (size_t i = 0; i < ehdr.e_phnum; ++i) {
    Phdr phdr;
    uint64_t offset = static_cast<uint64_t>(ehdr.e_phoff) + i * sizeof(Phdr);
    if (!read_exact(fd, &phdr, sizeof(phdr), offset))
      return false;
    if (phdr.p_type != PT_LOAD)
      continue;

    found_pt_load = true;
    min_vaddr = std::min<uint64_t>(min_vaddr, phdr.p_vaddr);
    max_vaddr = std::max<uint64_t>(
        max_vaddr, static_cast<uint64_t>(phdr.p_vaddr) + phdr.p_memsz);
  }

  if (!found_pt_load) {
    return false;
  }

  layout->min_vaddr = page_start(min_vaddr, page_size);
  layout->max_vaddr = page_end(max_vaddr, page_size);
  return layout->max_vaddr > layout->min_vaddr;
}

static bool read_elf_layout(const char *path, ElfLayout *layout) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "Cannot open original SO %s: %s\n", path, strerror(errno));
    return false;
  }

  unsigned char ident[EI_NIDENT];
  bool ok = read_exact(fd, ident, sizeof(ident), 0) &&
            memcmp(ident, ELFMAG, SELFMAG) == 0 &&
            ident[EI_DATA] == ELFDATA2LSB;

  long page_size = sysconf(_SC_PAGESIZE);
  if (ok && page_size > 0) {
    if (ident[EI_CLASS] == ELFCLASS32) {
      ok = parse_load_segments<Elf32_Ehdr, Elf32_Phdr>(
          fd, static_cast<uint64_t>(page_size), layout);
    } else if (ident[EI_CLASS] == ELFCLASS64) {
      ok = parse_load_segments<Elf64_Ehdr, Elf64_Phdr>(
          fd, static_cast<uint64_t>(page_size), layout);
    } else {
      ok = false;
    }
  } else {
    ok = false;
  }

  close(fd);
  if (!ok)
    fprintf(stderr, "Invalid or unsupported ELF: %s\n", path);
  return ok;
}

static std::string basename_of(const std::string &path) {
  size_t slash = path.rfind('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

static bool path_matches(const std::string &mapped,
                         const std::string &requested) {
  return requested.find('/') != std::string::npos
             ? mapped == requested
             : basename_of(mapped) == requested;
}

static bool read_maps(pid_t pid, std::vector<Mapping> *mappings) {
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

  FILE *file = fopen(maps_path, "re");
  if (file == NULL) {
    fprintf(stderr, "Cannot open %s: %s\n", maps_path, strerror(errno));
    return false;
  }

  char *line = NULL;
  size_t capacity = 0;
  while (getline(&line, &capacity, file) >= 0) {
    unsigned long long start, end, offset;
    unsigned long long inode;
    unsigned int device_major, device_minor;
    char permissions[5] = {};
    int path_position = 0;

    int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %llu %n", &start, &end,
                        permissions, &offset, &device_major, &device_minor,
                        &inode, &path_position);
    if (fields != 7 || start >= end)
      continue;

    char *path = line + path_position;
    while (*path == ' ' || *path == '\t')
      ++path;
    path[strcspn(path, "\r\n")] = '\0';

    static const char deleted_suffix[] = " (deleted)";
    size_t path_length = strlen(path);
    size_t suffix_length = sizeof(deleted_suffix) - 1;
    if (path_length >= suffix_length &&
        strcmp(path + path_length - suffix_length, deleted_suffix) == 0) {
      path[path_length - suffix_length] = '\0';
    }

    Mapping mapping;
    mapping.start = start;
    mapping.end = end;
    mapping.offset = offset;
    memcpy(mapping.permissions, permissions, sizeof(mapping.permissions));
    mapping.path = path;
    mappings->push_back(mapping);
  }

  bool ok = !ferror(file);
  free(line);
  fclose(file);
  return ok;
}

static bool same_file(const char *first, const char *second) {
  if (strcmp(first, second) == 0)
    return true;

  struct stat first_stat;
  struct stat second_stat;
  return stat(first, &first_stat) == 0 && stat(second, &second_stat) == 0 &&
         first_stat.st_dev == second_stat.st_dev &&
         first_stat.st_ino == second_stat.st_ino;
}

static bool copy_memory(int mem_fd, int output_fd, uint64_t address,
                        uint64_t size, uint64_t output_offset) {
  std::vector<unsigned char> buffer(COPY_BUFFER_SIZE);

  while (size != 0) {
    size_t count = static_cast<size_t>(std::min<uint64_t>(size, buffer.size()));
    if (!read_exact(mem_fd, buffer.data(), count, address) ||
        pwrite(output_fd, buffer.data(), count,
               static_cast<off_t>(output_offset)) !=
            static_cast<ssize_t>(count)) {
      return false;
    }
    address += count;
    output_offset += count;
    size -= count;
  }
  return true;
}

static bool dump_memory(pid_t pid, const std::vector<Mapping> &mappings,
                        uint64_t load_bias, const ElfLayout &layout,
                        const char *output_path) {
  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
  int mem_fd = open(mem_path, O_RDONLY | O_CLOEXEC);
  if (mem_fd < 0) {
    fprintf(stderr, "Cannot open %s: %s\n", mem_path, strerror(errno));
    return false;
  }

  std::string temporary_path = std::string(output_path) + ".tmp.XXXXXX";
  std::vector<char> temporary_name(temporary_path.begin(),
                                   temporary_path.end());
  temporary_name.push_back('\0');

  int output_fd = mkstemp(temporary_name.data());
  bool ok = output_fd >= 0 &&
            ftruncate(output_fd, static_cast<off_t>(layout.max_vaddr)) == 0;

  uint64_t range_start = load_bias + layout.min_vaddr;
  uint64_t range_end = load_bias + layout.max_vaddr;

  for (size_t i = 0; ok && i < mappings.size(); ++i) {
    const Mapping &mapping = mappings[i];
    if (mapping.permissions[0] != 'r' || mapping.end <= range_start ||
        mapping.start >= range_end) {
      continue;
    }

    uint64_t start = std::max(mapping.start, range_start);
    uint64_t end = std::min(mapping.end, range_end);
    fprintf(stderr,
            "  %016" PRIx64 "-%016" PRIx64 " %s %-12s -> %#" PRIx64 "\n", start,
            end, mapping.permissions, mapping.path.c_str(), start - load_bias);

    ok = copy_memory(mem_fd, output_fd, start, end - start, start - load_bias);
  }

  if (ok)
    ok = fsync(output_fd) == 0;
  if (output_fd >= 0 && close(output_fd) != 0)
    ok = false;
  close(mem_fd);

  if (ok) {
    ok = rename(temporary_name.data(), output_path) == 0;
  }
  if (!ok) {
    fprintf(stderr, "Dump failed: %s\n", strerror(errno));
    unlink(temporary_name.data());
  }
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 5) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }

  char *pid_end = NULL;
  long pid_value = strtol(argv[1], &pid_end, 10);
  if (*argv[1] == '\0' || *pid_end != '\0' || pid_value <= 0 ||
      pid_value > INT32_MAX) {
    fprintf(stderr, "Invalid PID: %s\n", argv[1]);
    return EXIT_FAILURE;
  }

  const char *requested_so = argv[2];
  const char *original_so = argv[3];
  const char *output_path = argv[4];

  if (same_file(original_so, output_path)) {
    fprintf(stderr, "Output must not overwrite the original SO\n");
    return EXIT_FAILURE;
  }

  ElfLayout layout = {};
  std::vector<Mapping> mappings;
  if (!read_elf_layout(original_so, &layout) ||
      !read_maps(static_cast<pid_t>(pid_value), &mappings)) {
    return EXIT_FAILURE;
  }

  const Mapping *anchor = NULL;
  for (size_t i = 0; i < mappings.size(); ++i) {
    const Mapping &mapping = mappings[i];
    if (path_matches(mapping.path, requested_so)) {
      anchor = &mapping;
      break;
    }
  }

  if (anchor == NULL) {
    fprintf(stderr, "Cannot find the SO mapping\n");
    return EXIT_FAILURE;
  }
  if (same_file(anchor->path.c_str(), output_path)) {
    fprintf(stderr, "Output must not overwrite the mapped SO\n");
    return EXIT_FAILURE;
  }

  uint64_t load_bias = anchor->start - layout.min_vaddr;
  fprintf(stderr,
          "SO: %s\n"
          "load_bias=%#" PRIx64 ", ELF range=%#" PRIx64 "-%#" PRIx64
          ", dump size=%#" PRIx64 "\n"
          "Dumping mappings:\n",
          anchor->path.c_str(), load_bias, layout.min_vaddr, layout.max_vaddr,
          layout.max_vaddr);

  if (!dump_memory(static_cast<pid_t>(pid_value), mappings, load_bias, layout,
                   output_path)) {
    return EXIT_FAILURE;
  }

  fprintf(stderr, "Dump completed: %s\n", output_path);
  return EXIT_SUCCESS;
}
