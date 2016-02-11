#define _GNU_SOURCE
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#define PROGRAM_OFFSET 0x00400000

/* 
 * search locations of DT_SYMTAB and DT_STRTAB and save them into global
 * variables, also save the nchains from hash table.
 */

unsigned long symtab;
unsigned long strtab;
/*int nchains;*/

static int interrupted = 0;

/* attach to pid */
void ptrace_attach(int pid)
{
	if ((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0) {
		perror("ptrace_attach");
		exit(-1);
	}
	waitpid(pid, NULL, WUNTRACED);
}

/* detach process */
void ptrace_detach(int pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		perror("ptrace_detach");
		exit(-1);
	}
}

/* read data from location addr */
void read_data(int pid, unsigned long addr, void *vptr, int len)
{
    int i, count;
	long word;
	unsigned long *ptr = (unsigned long *) vptr;
	count = i = 0;
	while (count < len) {
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + count, NULL);
		count += sizeof(long);
		ptr[i++] = word;
	}
}

/* read string from pid's memory */
char *read_str(int pid, unsigned long addr)
{
    // find size
    unsigned int str_size = 1;
    while (1) {
        unsigned long l = ptrace(PTRACE_PEEKTEXT, pid, addr + str_size * sizeof(char), NULL);
        int found_end = 0;

        for (int i = 0; i < 4; i++) {
            if ((char)l == '\0') {
                found_end = 1;
                break;
            }

            l >>= 8;
            str_size += 1;
        }

        if (found_end)
            break;
    }

    if (str_size > 1000) {
        char *c = calloc(13, 1);
        memcpy(c, "LARGE STRING", 12);
        c[12] = '\0';
        return "LARGE STRING";
    }

	char *ret = calloc(str_size, 1);
	read_data(pid, addr, ret, str_size);
	return ret;
}

/* write data to location addr */
void write_data(int pid, unsigned long addr, void *vptr, int len)
{
	int i, count;
	long word;
	i = count = 0;
	while (count < len) {
		memcpy(&word, vptr + count, sizeof(word));
		word = ptrace(PTRACE_POKETEXT, pid, addr + count, word);
		count += sizeof(long);
	}
}

/* locate link-map in pid's memory */
void allocate_display_space(int pid, long free_addr)
{
	Elf64_Ehdr *ehdr = malloc(sizeof(Elf64_Ehdr));
	Elf64_Phdr *phdr = malloc(sizeof(Elf64_Phdr));
	Elf64_Dyn *dyn = malloc(sizeof(Elf64_Dyn));
    Elf64_Addr phdr_addr, dyn_addr;

	/* 
	 * first we check from elf header, mapped at PROGRAM_OFFSET, the offset
	 * to the program header table from where we try to locate
	 * PT_DYNAMIC section.
	 */

	read_data(pid, PROGRAM_OFFSET, ehdr, sizeof(Elf64_Ehdr));

    if (ehdr->e_ident[EI_MAG0] != '\x7f' ||
        ehdr->e_ident[EI_MAG1] != 'E' ||
        ehdr->e_ident[EI_MAG2] != 'L' ||
        ehdr->e_ident[EI_MAG3] != 'F') {
        printf("Error finding ELF header\n");
        return;
    }

	phdr_addr = PROGRAM_OFFSET + ehdr->e_phoff;

    int found_dynamic_section = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        read_data(pid, phdr_addr + i * sizeof(Elf64_Phdr), phdr,
                  sizeof(Elf64_Phdr));

        if (phdr->p_type == PT_DYNAMIC) {
            found_dynamic_section = 1;
            break;
        }
    }

    if (!found_dynamic_section) {
        printf("Dynamic section not found\n");
        return;
    }

    Elf64_Addr strtab_addr = 0, symtab_addr = 0;
    Elf64_Xword strtab_size = 0;

    for (Elf64_Addr dyn_addr = phdr->p_vaddr;
         dyn_addr < phdr->p_vaddr + phdr->p_memsz;
         dyn_addr += sizeof(Elf64_Dyn)) {
        read_data(pid, dyn_addr, dyn, sizeof(Elf64_Dyn));

        if (dyn->d_tag == DT_NULL) {
            break;
        }

        if (dyn->d_tag == DT_STRTAB) {
            strtab_addr = dyn->d_un.d_ptr;
        }

        if (dyn->d_tag == DT_SYMTAB) {
            symtab_addr = dyn->d_un.d_ptr;
        }

        if (dyn->d_tag == DT_STRSZ) {
            strtab_size = dyn->d_un.d_val;
        }
    }

    if (symtab_addr == 0) {
        printf("Failed to find dynamic symbol table\n");
        return;
    }

    char *string_table = calloc(strtab_size, 1);
    read_data(pid, strtab_addr, string_table, strtab_size);

    int num_syms = 0;
    for (int i = 0; i < strtab_size; i++) {
        if (string_table[i] == '\0') {
            num_syms++;
        }
    }

    for (int i = 0; i < num_syms; i++) {
        Elf64_Sym sym;
        read_data(pid, symtab_addr + i * sizeof(Elf64_Sym), &sym, sizeof(Elf64_Sym));
        
        if (!strcmp(string_table + sym.st_name, "__environ")) {
            unsigned long environ;
            read_data(pid, sym.st_value, &environ, sizeof(environ));

            for (int i = 0;; i++) {
                unsigned long env_ptr;
                read_data(pid, environ + i * sizeof(env_ptr), &env_ptr, sizeof(env_ptr));
                
                if (env_ptr == 0) {
                    break;
                }

                char *c = read_str(pid, env_ptr);

                if (!strncmp(c, "DISPLAY=", 8)) {
                    write_data(pid, free_addr, c, strlen(c));
                    write_data(pid, environ + i * sizeof(env_ptr), &free_addr, sizeof(free_addr));
                    printf("DISPLAY location successfully changed\n");
                    break;
                }

                free(c);
            }
        }
    }
}

void update_display(pid_t pid, long display_addr, char *val, int len) {
    // write it after the DISPLAY= part
    write_data(pid, display_addr + 8, val, len);
    printf("Updated DISPLAY\n");
}

long find_free_space(pid_t pid) {
    FILE *fp;
    char filename[30];
    char line[85];
    long addr;
    char str[20];

    sprintf(filename, "/proc/%d/maps", pid);
    fp = fopen(filename, "r");
    if(fp == NULL)
        exit(1);
    while(fgets(line, 85, fp) != NULL) {
        sscanf(line, "%lx-%*s %*s %*s %s", &addr, str, str, str, str);
        if(strcmp(str, "00:00") == 0)
            break;
    }
    fclose(fp);
    return addr;
}

const char *tmp_dir = "/tmp/display-injector";

void parent(pid_t pid) {
    mkdir(tmp_dir, S_IRWXU);

    unsigned int s = socket(AF_UNIX, SOCK_STREAM, 0);

    if (s == -1) {
        printf("Error creating socket\n");
        return;
    }

    struct sockaddr_un local;
    local.sun_family = AF_UNIX;
    sprintf(local.sun_path, "%s/%s.%d", tmp_dir, "zsh", pid);
    unlink(local.sun_path);
    int len = strlen(local.sun_path) + sizeof(local.sun_family);

    if (bind(s, (struct sockaddr *)&local, len) == -1) {
        printf("Error binding to %s\n", local.sun_path);
        return;
    }

    listen(s, 5);

    sleep(1); // give process time to start; calling ptrace_attach too soon seems to crash things
	ptrace_attach(pid);
    long free_addr = find_free_space(pid);
    allocate_display_space(pid, free_addr);
    ptrace_detach(pid);

    while (!interrupted) {
        struct sockaddr remote;
        int s_remote = accept(s, &remote, &len);

        char buf[100];
        len = recv(s_remote, &buf, 100, 0);
        close(s_remote);

        if (len <= 0) {
            continue;
        }

        ptrace_attach(pid);
        update_display(pid, free_addr, buf, len);
        ptrace_detach(pid);
    }

    close(s);
    unlink(local.sun_path);
}

void child(char *argv[], char *envp[]) {
    execve(argv[0], argv, envp);
}

static void signal_handler(int sig) {
    if (sig == SIGCHLD) {
        int stat;
        pid_t pid = waitpid(-1, &stat, WNOHANG);

        if (WIFEXITED(stat)) {
            interrupted = 1;
        }
    } else {
        interrupted = 1;
    }
}

int main(int argc, char *argv[], char *envp[]) {
    if (argc < 2) {
        printf("Usage: %s <executable> [args...]\n", argv[0]);
        return 1;
    }

    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGKILL, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    pid_t pid = fork();

    if (pid < 0) {
        printf("Error forking\n");
        exit(1);
    }

    if (pid) {
        parent(pid);
    } else {
        child(argv + 1, envp);
    }
}

