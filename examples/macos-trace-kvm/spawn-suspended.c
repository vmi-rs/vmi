// Guest-side helper for the macos-trace-kvm example.
//
// Starts a command suspended right after exec, before dyld runs, prints its
// pid, and resumes it when Enter is pressed. Attach the tracer to the pid in
// between to trace a short-lived command from its first call.
//
// Build in the guest: cc -o spawn-suspended spawn-suspended.c
// Usage:              ./spawn-suspended ls -als

#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s COMMAND [ARG...]\n", argv[0]);
        return 2;
    }

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);

    pid_t pid;
    int err = posix_spawnp(&pid, argv[1], NULL, &attr, argv + 1, environ);
    posix_spawnattr_destroy(&attr);
    if (err != 0) {
        fprintf(stderr, "posix_spawnp: %s\n", argv[1]);
        return 127;
    }

    // Wait on the terminal so the command keeps its stdin.
    FILE *tty = fopen("/dev/tty", "r");
    fprintf(stderr, "pid %d suspended; attach the tracer, then press Enter\n", pid);
    fgetc(tty != NULL ? tty : stdin);
    if (tty != NULL)
        fclose(tty);

    kill(pid, SIGCONT);

    int status;
    if (waitpid(pid, &status, 0) < 0)
        return 1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
