/*
 * Opt-in macOS Rustc-side cache client.
 *
 * Rustc uses posix_spawn for ordinary linker commands on macOS. The production path invokes
 * Wild's bounded cache protocol in this already-running parent, then replaces only a successful
 * cache hit with a minimal child so Rustc retains its normal wait/exit-status contract. The full
 * linker argv already exists in Rustc when this interposer runs, so a hit avoids paying
 * for a second process to receive that argv. Rustc still receives a real, successful minimal
 * child and therefore keeps its ordinary wait/exit-status contract. A cache miss delegates to a
 * path-equivalent posix_spawn call with the original argv.
 */

#include <errno.h>
#include <mach-o/dyld.h>
#include <limits.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WILD_MACHO_CACHE_CLIENT_NO_MAIN
#include "macho-cache-client.c"

#define INLINE_ENV "WILD_MACHO_INCREMENTAL_CACHE_INLINE"
#define INLINE_DIAGNOSTICS_ENV "WILD_MACHO_INCREMENTAL_CACHE_INLINE_DIAGNOSTICS"

typedef int (*posix_spawn_function)(
    pid_t *restrict,
    const char *restrict,
    const posix_spawn_file_actions_t *restrict,
    const posix_spawnattr_t *restrict,
    char *const[restrict],
    char *const[restrict]);

#define DYLD_INTERPOSE(replacement, replaced) \
  __attribute__((used)) static const struct { \
    const void *replacement; \
    const void *replaced; \
  } interpose_##replacement##_##replaced \
      __attribute__((section("__DATA,__interpose"))) = { \
          (const void *)(unsigned long)&replacement, \
          (const void *)(unsigned long)&replaced, \
      }

static int has_incremental_cache_argument(char *const argv[]) {
  if (argv == NULL) return 0;
  for (size_t index = 1; argv[index] != NULL; ++index) {
    if (strcmp(argv[index], "-incremental_cache") == 0) return 1;
  }
  return 0;
}

static int argument_count(char *const argv[]) {
  if (argv == NULL) return 0;
  int count = 0;
  while (argv[count] != NULL) {
    if (count == INT_MAX) return -1;
    ++count;
  }
  return count;
}

static const char *environment_value(char *const envp[], const char *name) {
  if (envp == NULL) return NULL;
  size_t name_len = strlen(name);
  for (size_t index = 0; envp[index] != NULL; ++index) {
    if (strncmp(envp[index], name, name_len) == 0 && envp[index][name_len] == '=') {
      return envp[index] + name_len + 1;
    }
  }
  return NULL;
}

/*
 * This library interposes the public posix_spawn symbol. Obtain its address from the concrete
 * libsystem_kernel Mach-O image, which bypasses dyld's interposed dlsym result, so fallback links
 * and the successful `/usr/bin/true` replacement do not recurse through this interposer.
 */
static posix_spawn_function original_spawn_symbol(const char *name) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  for (uint32_t index = 0; index < _dyld_image_count(); ++index) {
    const char *image_name = _dyld_get_image_name(index);
    if (image_name == NULL || strcmp(image_name, "/usr/lib/system/libsystem_kernel.dylib") != 0) {
      continue;
    }
    NSSymbol symbol = NSLookupSymbolInImage(
        _dyld_get_image_header(index),
        name,
        NSLOOKUPSYMBOLINIMAGE_OPTION_BIND | NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR);
    if (symbol != NULL) return (posix_spawn_function)NSAddressOfSymbol(symbol);
    break;
  }
#pragma clang diagnostic pop
  return NULL;
}

static int spawn_original(
    pid_t *restrict pid,
    const char *restrict path,
    const posix_spawn_file_actions_t *restrict file_actions,
    const posix_spawnattr_t *restrict attrp,
  char *const argv[restrict],
  char *const envp[restrict]) {
  static posix_spawn_function implementation;
  if (implementation == NULL) implementation = original_spawn_symbol("_posix_spawn");
  if (implementation == NULL) return ENOSYS;
  return implementation(pid, path, file_actions, attrp, argv, envp);
}

// Preserve the PATH-search subset Rustc needs without recursively calling the interposed symbol.
static int spawn_originalp(
    pid_t *restrict pid,
    const char *restrict file,
    const posix_spawn_file_actions_t *restrict file_actions,
    const posix_spawnattr_t *restrict attrp,
    char *const argv[restrict],
    char *const envp[restrict]) {
  if (file == NULL || file[0] == '\0') return ENOENT;
  if (strchr(file, '/') != NULL) return spawn_original(pid, file, file_actions, attrp, argv, envp);
  const char *path = environment_value(envp, "PATH");
  if (path == NULL) return ENOENT;
  size_t file_len = strlen(file);
  int saved_error = ENOENT;
  for (const char *entry = path;;) {
    const char *separator = strchr(entry, ':');
    size_t entry_len = separator == NULL ? strlen(entry) : (size_t)(separator - entry);
    char candidate[PATH_MAX];
    if (entry_len == 0) {
      if (file_len >= sizeof(candidate)) return ENAMETOOLONG;
      memcpy(candidate, file, file_len + 1);
    } else {
      if (entry_len > sizeof(candidate) - file_len - 2) return ENAMETOOLONG;
      memcpy(candidate, entry, entry_len);
      candidate[entry_len] = '/';
      memcpy(candidate + entry_len + 1, file, file_len + 1);
    }
    int result = spawn_original(pid, candidate, file_actions, attrp, argv, envp);
    if (result == 0) return 0;
    if (result == EACCES) saved_error = EACCES;
    else if (result != ENOENT && result != ENOTDIR) return result;
    if (separator == NULL) return saved_error;
    entry = separator + 1;
  }
}

static int spawn_cache_hit(
    pid_t *restrict pid,
    const posix_spawn_file_actions_t *restrict file_actions,
    const posix_spawnattr_t *restrict attrp,
    char *const envp[restrict]) {
  static char true_path[] = "/usr/bin/true";
  char *const true_argv[] = {true_path, NULL};
  if (getenv(INLINE_DIAGNOSTICS_ENV) != NULL) {
    static const char marker[] = "wild inline cache: replacing linker child\n";
    (void)write(STDERR_FILENO, marker, sizeof(marker) - 1);
  }
  uint64_t started = monotonic_ns();
  int result = spawn_original(pid, true_path, file_actions, attrp, true_argv, envp);
  if (getenv(TIMING_ENV) != NULL && started != 0) {
    fprintf(
        stderr,
        "wild inline cache: replacement spawn_ns=%llu\n",
        (unsigned long long)(monotonic_ns() - started));
  }
  return result;
}

static int inline_cache_hit(int argc, char *const argv[]) {
  if (argc == 0 || !has_incremental_cache_argument(argv)) return 0;
  if (getenv(INLINE_DIAGNOSTICS_ENV) != NULL) {
    static const char inspecting[] = "wild inline cache: inspecting linker child\n";
    (void)write(STDERR_FILENO, inspecting, sizeof(inspecting) - 1);
  }
  if (getenv(INLINE_ENV) == NULL) {
    if (getenv(INLINE_DIAGNOSTICS_ENV) != NULL) {
      static const char disabled[] = "wild inline cache: disabled in linker parent\n";
      (void)write(STDERR_FILENO, disabled, sizeof(disabled) - 1);
    }
    return 0;
  }
  if (macho_cache_try_apply(argc, argv)) return 1;
  if (getenv(INLINE_DIAGNOSTICS_ENV) != NULL) {
    static const char miss[] = "wild inline cache: cache miss; spawning linker\n";
    (void)write(STDERR_FILENO, miss, sizeof(miss) - 1);
  }
  return 0;
}

static int wild_inline_posix_spawn(
    pid_t *restrict pid,
    const char *restrict path,
    const posix_spawn_file_actions_t *restrict file_actions,
    const posix_spawnattr_t *restrict attrp,
    char *const argv[restrict],
    char *const envp[restrict]) {
  int argc = argument_count(argv);
  if (inline_cache_hit(argc, argv)) return spawn_cache_hit(pid, file_actions, attrp, envp);
  return spawn_original(pid, path, file_actions, attrp, argv, envp);
}

static int wild_inline_posix_spawnp(
    pid_t *restrict pid,
    const char *restrict file,
    const posix_spawn_file_actions_t *restrict file_actions,
    const posix_spawnattr_t *restrict attrp,
    char *const argv[restrict],
    char *const envp[restrict]) {
  int argc = argument_count(argv);
  if (inline_cache_hit(argc, argv)) return spawn_cache_hit(pid, file_actions, attrp, envp);
  return spawn_originalp(pid, file, file_actions, attrp, argv, envp);
}

DYLD_INTERPOSE(wild_inline_posix_spawn, posix_spawn);
DYLD_INTERPOSE(wild_inline_posix_spawnp, posix_spawnp);
