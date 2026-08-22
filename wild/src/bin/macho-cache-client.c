/*
 * Minimal macOS client for Wild's opt-in Mach-O stable-layout cache service.
 *
 * Cargo launches a linker executable for every final link. Starting the full Rust linker merely
 * to submit an already-verified cache hit costs tens of milliseconds, so this native client sends
 * the exact argv to the same-user service and exits after its response. The Rust service parses,
 * validates, patches, signs, and publishes every hit. A miss always execs the configured Wild
 * binary with the original argv, preserving the ordinary linker as the correctness fallback.
 */

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define CACHE_ENV "WILD_MACHO_INCREMENTAL_CACHE_SERVICE"
#define SERVICE_DIRECTORY_ENV "WILD_MACHO_INCREMENTAL_CACHE_SERVICE_DIR"
#define SERVER_ENV "WILD_MACHO_INCREMENTAL_CACHE_SERVICE_SERVER"
#define TIMING_ENV "WILD_MACHO_INCREMENTAL_CACHE_SERVICE_TIMING"
#define SERVICE_ARGUMENT "--wild-macho-cache-service"
#define REQUEST_MAGIC "WILD-MACHO-CACHE-SERVICE-3"
#define STARTUP_RETRIES 100
#define MAX_FRAME_BYTES (16 * 1024 * 1024)

static const unsigned char request_magic[] = REQUEST_MAGIC;

static uint64_t monotonic_ns(void) {
  struct timespec time;
  if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return 0;
  return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

static int write_all(int fd, const void *buffer, size_t length) {
  const unsigned char *cursor = buffer;
  while (length > 0) {
    ssize_t written = write(fd, cursor, length);
    if (written < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    cursor += (size_t)written;
    length -= (size_t)written;
  }
  return 0;
}

static int read_all(int fd, void *buffer, size_t length) {
  unsigned char *cursor = buffer;
  while (length > 0) {
    ssize_t read_count = read(fd, cursor, length);
    if (read_count == 0) return -1;
    if (read_count < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    cursor += (size_t)read_count;
    length -= (size_t)read_count;
  }
  return 0;
}

static int write_u32(int fd, uint32_t value) {
  unsigned char bytes[4] = {
      (unsigned char)value,
      (unsigned char)(value >> 8),
      (unsigned char)(value >> 16),
      (unsigned char)(value >> 24),
  };
  return write_all(fd, bytes, sizeof(bytes));
}

static int write_string(int fd, const char *value) {
  size_t length = strlen(value);
  if (length > UINT32_MAX || length > MAX_FRAME_BYTES) return -1;
  return write_u32(fd, (uint32_t)length) || write_all(fd, value, length);
}

static const char *cache_directory(int argc, char *const argv[]) {
  for (int index = 1; index + 1 < argc; ++index) {
    if (strcmp(argv[index], "-incremental_cache") == 0) return argv[index + 1];
  }
  return NULL;
}

static int make_socket_path(const char *cache_directory, char *buffer, size_t buffer_size) {
  const char *service_directory = getenv(SERVICE_DIRECTORY_ENV);
  if (service_directory == NULL || service_directory[0] == '\0') service_directory = cache_directory;
  if (mkdir(service_directory, 0700) != 0 && errno != EEXIST) return -1;

  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(cache_directory, (CC_LONG)strlen(cache_directory), digest);
  int written = snprintf(
      buffer,
      buffer_size,
      "%s/macho-%02x%02x%02x%02x%02x%02x%02x%02x.sock",
      service_directory,
      digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]);
  return written < 0 || (size_t)written >= buffer_size ? -1 : 0;
}

static int connect_socket(const char *socket_path) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int no_sigpipe = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) != 0) {
    close(fd);
    return -1;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  if (strlen(socket_path) >= sizeof(address.sun_path)) {
    close(fd);
    return -1;
  }
  strcpy(address.sun_path, socket_path);
  if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

// The service can outlive this short-lived linker client. Give it no Cargo/Rustc standard-stream
// pipes, otherwise their readers may wait for the service's idle lifetime after the link exits.
static void start_service(const char *server, const char *cache_directory) {
  posix_spawn_file_actions_t file_actions;
  if (posix_spawn_file_actions_init(&file_actions) != 0) return;
  int configured =
      posix_spawn_file_actions_addopen(&file_actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
      posix_spawn_file_actions_addopen(&file_actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
      posix_spawn_file_actions_addopen(&file_actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0;
  char *const service_argv[] = {(char *)server, SERVICE_ARGUMENT, (char *)cache_directory, NULL};
  pid_t child;
  if (configured) (void)posix_spawn(&child, server, &file_actions, NULL, service_argv, environ);
  (void)posix_spawn_file_actions_destroy(&file_actions);
}

static int connect_or_start(const char *socket_path, const char *server, const char *cache_directory) {
  int fd = connect_socket(socket_path);
  if (fd >= 0) return fd;
  unlink(socket_path);
  start_service(server, cache_directory);
  for (int attempt = 0; attempt < STARTUP_RETRIES; ++attempt) {
    fd = connect_socket(socket_path);
    if (fd >= 0) return fd;
    usleep(10000);
  }
  return -1;
}

static uint64_t read_low_u128(const unsigned char *value) {
  uint64_t low = 0;
  for (size_t index = 0; index < sizeof(low); ++index) {
    low |= (uint64_t)value[index] << (index * CHAR_BIT);
  }
  return low;
}

static int submit_request(
    int fd, int argc, char *const argv[], uint64_t *server_ns, uint64_t *parse_ns, uint64_t *apply_ns) {
  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == NULL) return -1;
  if (write_all(fd, request_magic, sizeof(request_magic)) != 0 || write_string(fd, cwd) != 0 ||
      write_u32(fd, (uint32_t)argc) != 0) {
    return -1;
  }
  for (int index = 0; index < argc; ++index) {
    if (write_string(fd, argv[index]) != 0) return -1;
  }
  unsigned char response[49];
  if (read_all(fd, response, sizeof(response)) != 0) return -1;
  *server_ns = read_low_u128(response + 1);
  *parse_ns = read_low_u128(response + 17);
  *apply_ns = read_low_u128(response + 33);
  return response[0] == 1 ? 1 : 0;
}

#ifndef WILD_MACHO_CACHE_CLIENT_NO_MAIN
static void exec_fallback(const char *server, char **argv) {
  signal(SIGPIPE, SIG_DFL);
  execve(server, argv, environ);
  fprintf(stderr, "wild cache client: failed to exec %s: %s\n", server, strerror(errno));
  _exit(127);
}
#endif

/*
 * Applies an exact argv through the cache service without replacing this process on a miss.
 *
 * This is shared with the opt-in Rustc inline client, which must preserve its parent process and
 * delegate ordinary links back to Rustc's original spawn call. The service still owns all
 * parsing, validation, patching, signing, and output publication; a false result is the same
 * conservative cache miss as the standalone client's exec fallback.
 */
static int macho_cache_try_apply(int argc, char *const argv[]) {
  uint64_t request_started = monotonic_ns();
  const char *server = getenv(SERVER_ENV);
  const char *cache = cache_directory(argc, argv);
  if (server == NULL || server[0] == '\0' || cache == NULL || getenv(CACHE_ENV) == NULL) return 0;

  char socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  if (make_socket_path(cache, socket_path, sizeof(socket_path)) != 0) return 0;
  int fd = connect_or_start(socket_path, server, cache);
  if (fd < 0) return 0;
  uint64_t server_ns = 0;
  uint64_t parse_ns = 0;
  uint64_t apply_ns = 0;
  int result = submit_request(fd, argc, argv, &server_ns, &parse_ns, &apply_ns);
  close(fd);
  if (result == 1) {
    const char *output = "<unknown output>";
    for (int index = 1; index + 1 < argc; ++index) {
      if (strcmp(argv[index], "-o") == 0) {
        output = argv[index + 1];
        break;
      }
    }
    fprintf(stderr, "wild: Mach-O stable-layout cache hit: %s\n", output);
    if (getenv(TIMING_ENV) != NULL && request_started != 0) {
      fprintf(
          stderr,
          "wild: Mach-O cache service timing: client_ns=%llu server_ns=%llu parse_ns=%llu apply_ns=%llu\n",
          (unsigned long long)(monotonic_ns() - request_started),
          (unsigned long long)server_ns,
          (unsigned long long)parse_ns,
          (unsigned long long)apply_ns);
    }
    return 1;
  }
  return 0;
}

#ifndef WILD_MACHO_CACHE_CLIENT_NO_MAIN
int main(int argc, char **argv) {
  // A stale or incompatible service may close while we are still sending its request. Treat that
  // as an ordinary cache miss and exec Wild rather than letting the shim terminate on SIGPIPE.
  signal(SIGPIPE, SIG_IGN);
  if (macho_cache_try_apply(argc, argv)) return 0;
  const char *server = getenv(SERVER_ENV);
  if (server != NULL && server[0] != '\0') exec_fallback(server, argv);
  fprintf(stderr, "wild cache client requires %s\n", SERVER_ENV);
  return 127;
}
#endif
