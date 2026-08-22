/*
 * Invokes a linker through posix_spawn or posix_spawnp without knowing its implementation. The
 * macOS integration test loads Wild's opt-in interposer into this parent, which is the same
 * process boundary Rustc uses for its final linker child.
 */

#include <spawn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv) {
  if (argc < 2) return 64;

  int use_path_search = 1;
  if (argc >= 3 && strcmp(argv[1], "--posix-spawn") == 0) {
    use_path_search = 0;
    --argc;
    ++argv;
  }

  char **linker_argv = argv + 1;
  if (argc == 3 && strcmp(argv[1], "--argv-file") == 0) {
    int file = open(argv[2], O_RDONLY);
    if (file < 0) return 65;
    struct stat metadata;
    if (fstat(file, &metadata) != 0 || metadata.st_size <= 1) return 66;
    size_t length = (size_t)metadata.st_size;
    char *buffer = malloc(length);
    if (buffer == NULL) return 67;
    size_t offset = 0;
    while (offset < length) {
      ssize_t count = read(file, buffer + offset, length - offset);
      if (count <= 0) return 68;
      offset += (size_t)count;
    }
    (void)close(file);
    if (buffer[length - 1] != '\0') return 69;
    size_t argument_count = 0;
    for (size_t index = 0; index < length; ++index) argument_count += buffer[index] == '\0';
    linker_argv = calloc(argument_count + 1, sizeof(*linker_argv));
    if (linker_argv == NULL) return 70;
    size_t argument = 0;
    linker_argv[argument++] = buffer;
    for (size_t index = 0; index + 1 < length; ++index) {
      if (buffer[index] == '\0') linker_argv[argument++] = buffer + index + 1;
    }
    if (argument != argument_count || linker_argv[0][0] == '\0') return 71;
  }

  posix_spawn_file_actions_t file_actions;
  if (posix_spawn_file_actions_init(&file_actions) != 0) return 72;
  posix_spawnattr_t attributes;
  if (posix_spawnattr_init(&attributes) != 0) {
    (void)posix_spawn_file_actions_destroy(&file_actions);
    return 73;
  }
  int report_timing = getenv("WILD_MACHO_CACHE_INLINE_PROBE_TIMING") != NULL;
  struct timespec started;
  if (report_timing && clock_gettime(CLOCK_MONOTONIC, &started) != 0) return 74;
  pid_t child;
  int result = use_path_search
                   ? posix_spawnp(&child, linker_argv[0], &file_actions, &attributes, linker_argv, environ)
                   : posix_spawn(&child, linker_argv[0], &file_actions, &attributes, linker_argv, environ);
  (void)posix_spawnattr_destroy(&attributes);
  (void)posix_spawn_file_actions_destroy(&file_actions);
  if (result != 0) return result;

  int status = 0;
  if (waitpid(child, &status, 0) != child) return 75;
  if (!WIFEXITED(status)) return 76;
  if (report_timing) {
    struct timespec finished;
    if (clock_gettime(CLOCK_MONOTONIC, &finished) != 0) return 77;
    uint64_t elapsed_ns = (uint64_t)(finished.tv_sec - started.tv_sec) * UINT64_C(1000000000) +
                          (uint64_t)(finished.tv_nsec - started.tv_nsec);
    printf("elapsed_ns=%llu\n", (unsigned long long)elapsed_ns);
  }
  return WEXITSTATUS(status);
}
