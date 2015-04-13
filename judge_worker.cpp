#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/types.h> 
#include <sys/user.h> 
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <assert.h>
#include "okcalls.h"

#define STD_MB 1048576
#define STD_F_LIM (STD_MB<<5)
#define _SIZE 512
//#define nil ((void*)0)
#define nil NULL
#ifdef __i386
#define REG_SYSCALL orig_eax
#define REG_RET eax
#define REG_ARG0 ebx
#define REG_ARG1 ecx
#else
#define REG_SYSCALL orig_rax
#define REG_RET rax
#define REG_ARG0 rdi
#define REG_ARG1 rsi

#endif

#include "langinfo.h"

#define SBOJ_WT 0
#define SBOJ_AC 1
#define SBOJ_PE 2
#define SBOJ_WA 3
#define SBOJ_TLE 4
#define SBOJ_MLE 5
#define SBOJ_OLE 6
#define SBOJ_RE 7
#define SBOJ_CE 8

#define DEBUG

#ifdef DEBUG
#define Debuging 1
#else
#define Debuging 0
#endif

static char judge_pre[_SIZE] = "/home/judger";
static char judge_dir[_SIZE];
static char data_dir[_SIZE];
static int msgid;

struct submission {
	int p_id, submission_id;
	int mem_lmt, time_lmt, spj, lang;
	char path[_SIZE];
};
struct submission sbm;

//hust_oj
void print_runtimeerror(char * err) {
	FILE *ferr = fopen("error.out", "a+");
	fprintf(ferr, "Runtime Error:%s\n", err);
	fclose(ferr);
}
int get_proc_status(int pid, const char * mark) {
	FILE * pf;
	char fn[_SIZE], buf[_SIZE];
	int ret = 0;
	sprintf(fn, "/proc/%d/status", pid);
	pf = fopen(fn, "r");
	int m = strlen(mark);
	while (pf && fgets(buf, _SIZE - 1, pf)) {

		buf[strlen(buf) - 1] = 0;
		if (strncmp(buf, mark, m) == 0) {
			sscanf(buf + m + 1, "%d", &ret);
		}
	}
	if (pf)
		fclose(pf);
	return ret;
}
int after_equal(char * c) {
	int i = 0;
	for (; c[i] != '\0' && c[i] != '='; i++)
		;
	return ++i;
}
void trim(char * c) {
	char buf[_SIZE];
	char * start, *end;
	strcpy(buf, c);
	start = buf;
	while (isspace(*start))
		start++;
	end = start;
	while (!isspace(*end))
		end++;
	*end = '\0';
	strcpy(c, start);
}

long get_file_size(const char * filename) {
	struct stat f_stat;

	if (stat(filename, &f_stat) == -1) {
		return 0;
	}

	return (long) f_stat.st_size;
}

int execute_cmd(const char * fmt, ...) {
	char cmd[_SIZE];

	int ret = 0;
	va_list ap;

	va_start(ap, fmt);
	vsprintf(cmd, fmt, ap);
	ret = system(cmd);
	va_end(ap);
	return ret;
}

int IsInputFile(const char fname[]) {
	int l = strlen(fname);
	if (l <= 3 || strcmp(fname + l - 3, ".in") != 0)
		return 0;
	else
		return l - 3;
}
//end_hust_oj

int read_conf(char * row, const char * key, char * val) {
	if (strncmp(row, key, strlen(key)) == 0) {
		strcpy(val, row + after_equal(row));
		trim(val);
		return 1;
	}
	return 0;
}

void read_int(char * row, const char * key, int * val) {
	char buf[_SIZE];
	if (read_conf(row, key, buf))
		sscanf(buf, "%d", val);

}

void clean_dir(char * dir) {
	execute_cmd("/bin/rm -rf %s/*", dir);
}

struct submission get_msg_from_mq() {
	struct submission ret;
	if (msgrcv(msgid, (void *) &ret, BUFSIZ, 0, 0) == -1) {
		perror("msgrcv");
		exit(EXIT_FAILURE);
	}
	return ret;
}

void get_submission_info(int argc, char** argv) {
	sbm = get_msg_from_mq();
}

void get_source(char *judge_dir) {
	int pid = fork();
	puts("cp start");
	if (pid == 0) {
		while(setgid(9090)!=0) sleep(1);
		while(setuid(9090)!=0) sleep(1);
		while(setresuid(9090, 9090, 9090)!=0) sleep(1);
		execute_cmd("/bin/cp %s %sMain.%s", sbm.path, judge_dir, lang_ext[sbm.lang]);
		puts("cp finish");
		exit(0);
	} else {
		int status = 0;
		waitpid(pid, &status, 0);
	}
}


int compile(int lang) {
	int pid = fork();
	if (pid == 0) {
		struct rlimit LIM;
		LIM.rlim_max = 30;
		LIM.rlim_cur = 30;
		setrlimit(RLIMIT_CPU, &LIM);
		alarm(30);
		LIM.rlim_max = 100 * STD_MB;
		LIM.rlim_cur = 100 * STD_MB;
		setrlimit(RLIMIT_FSIZE, &LIM);
		LIM.rlim_max = STD_MB << 10;
		LIM.rlim_cur = STD_MB << 10;
		setrlimit(RLIMIT_AS, &LIM);
		if (lang == 2) {
			freopen("ce.log", "w", stdout);
		} else {
			freopen("ce.log", "w", stderr);
		}
		execute_cmd("chown judger *");

		while(setgid(9090)!=0) sleep(1);
		while(setuid(9090)!=0) sleep(1);
		while(setresuid(9090, 9090, 9090)!=0) sleep(1);
		execvp(compiler[lang][0], (char * const *) compiler[lang]);
		exit(0);
	} else {
		int status = 0;
		waitpid(pid, &status, 0);
		return get_file_size("ce.log");
	}
}

void copy_data(char * file, int name_len, char * data_path, int &outputlmt) {
	char filename[_SIZE];
	strncpy(filename, file, name_len);
	filename[name_len] = 0;
	execute_cmd("/bin/cp %s/%s.in %s/data.in", data_path, filename, judge_dir);
	execute_cmd("/bin/cp %s/%s.std %s/data.std", data_path, filename, judge_dir);
	char opfile[_SIZE];
	sprintf(opfile, "%s/data.std", judge_dir);
	outputlmt = get_file_size(opfile) * 2 + 1024;
}


int calls[_SIZE] = { 0 };
void init_syscalls_limits(int lang) {
	int i;
	memset(calls, 0, sizeof(calls));
	if (lang <= 1) { //C & C++
		for (i = 0; i==0||LANG_CV[i]; i++) {
			calls[LANG_CV[i]] = OJ_MAX_LIMIT;
		}
	} else if (lang == 2) { // Pascal
		for (i = 0; i==0||LANG_PV[i]; i++)
			calls[LANG_PV[i]] = OJ_MAX_LIMIT;
	}
}

void run_solution(int lang, int mem_lmt, int time_lmt, int &usedtime) {
	nice(19);
	chdir(judge_dir);
	puts("Start run Main");
	freopen("data.in", "r", stdin);
	freopen("output.out", "w", stdout);
	freopen("error.out", "a+", stderr);

	ptrace(PTRACE_TRACEME, 0, nil, nil);

	chroot(judge_dir);


	while (setgid(9090) != 0) sleep(1);
	while (setuid(9090) != 0) sleep(1);
	while (setresuid(9090, 9090, 9090) != 0) sleep(1);

	struct rlimit LIM;
	//set time limit
	LIM.rlim_max = LIM.rlim_cur = (time_lmt - usedtime / 1000) + 1;
	setrlimit(RLIMIT_CPU, &LIM);

	alarm(0);
	alarm(time_lmt * 2);

	//set file size limit
	LIM.rlim_max = STD_F_LIM + STD_MB;
	LIM.rlim_cur = STD_F_LIM;
	setrlimit(RLIMIT_FSIZE, &LIM);

	//set proc limit
	switch(lang) {
		default:
			LIM.rlim_max = LIM.rlim_cur = 1;
	}
	setrlimit(RLIMIT_NPROC, &LIM);

	//set stack limit
	LIM.rlim_max = LIM.rlim_cur = STD_MB << 6;
	setrlimit(RLIMIT_STACK, &LIM);

	//set memory limit
	LIM.rlim_cur = STD_MB * mem_lmt / 2 * 3;
	LIM.rlim_max = STD_MB * mem_lmt * 2;
	setrlimit(RLIMIT_AS, &LIM);

	switch(lang) {
		case 0:
		case 1:
		case 2:
			execl("./Main", "./Main", (char*) nil);
			puts("fuck?");
			break;
	}

	exit(0);
}

void watch_solution(int &flag, pid_t pid, int lang, int mem_lmt, int time_lmt, int &usedtime, int &usedmem, int spj, char *userout, int output_lmt) {
	int tmpmem;

	int status, sig, exitcode;
	struct user_regs_struct reg;
	struct rusage ruse;

	puts("Father: start watch");

	while (1) {
		wait4(pid, &status, 0, &ruse);
		//		puts("Father: sleep");
		//		sleep(2);

		tmpmem = get_proc_status(pid, "VmPeak:") << 10;

		if (tmpmem > usedmem) usedmem = tmpmem;
		if (usedmem > mem_lmt * STD_MB) {
			flag = SBOJ_MLE;
			ptrace(PTRACE_KILL, pid, nil, nil);
			break;
		}

		if (WIFEXITED(status)) break;

		if (get_file_size("error.out")) {
			flag = SBOJ_RE;
			ptrace(PTRACE_KILL, pid, nil, nil);
			break;
		}

		if (!spj && get_file_size(userout) > output_lmt) {
			flag = SBOJ_OLE;
			ptrace(PTRACE_KILL, pid, nil, nil);
			break;
		}

		exitcode = WEXITSTATUS(status);
		if (exitcode != 5 && exitcode != 0) {
			switch(exitcode) {
				case SIGCHLD:
				case SIGALRM:
					alarm(0);
				case SIGKILL:
				case SIGXCPU:
					flag = SBOJ_TLE;
					break;
				case SIGXFSZ:
					flag = SBOJ_OLE;
					break;
				default:
					flag = SBOJ_RE;
			}
			print_runtimeerror(strsignal(exitcode));
			ptrace(PTRACE_KILL, pid, nil, nil);
			break;
		}

		if (WIFSIGNALED(status)) {
			/*  WIFSIGNALED: if the process is terminated by signal
			 *
			 *  psignal(int sig, char *s)，like perror(char *s)，print out s, with error msg from system of sig  
			 * sig = 5 means Trace/breakpoint trap
			 * sig = 11 means Segmentation fault
			 * sig = 25 means File size limit exceeded
			 */
			sig = WTERMSIG(status);

			switch (sig) {
				case SIGCHLD:
				case SIGALRM:
					alarm(0);
				case SIGKILL:
				case SIGXCPU:
					flag = SBOJ_TLE;
					break;
				case SIGXFSZ:
					flag = SBOJ_OLE;
					break;

				default:
					flag = SBOJ_RE;
			}
			print_runtimeerror(strsignal(sig));
			break;
		}

		//system calls
		ptrace(PTRACE_GETREGS, pid, nil, &reg);
		if (!calls[reg.REG_SYSCALL]) {
			flag = SBOJ_RE;
			char error[_SIZE];
			sprintf(error, "[ERROR] A not allowed system call %d is called!", (int)reg.REG_SYSCALL);
			print_runtimeerror(error);
			ptrace(PTRACE_KILL, pid, nil, nil);
		}

		ptrace(PTRACE_SYSCALL, pid, nil, nil);
	}

	usedtime += (ruse.ru_utime.tv_sec * 1000 + ruse.ru_utime.tv_usec / 1000);
	usedtime += (ruse.ru_stime.tv_sec * 1000 + ruse.ru_stime.tv_usec / 1000);
}

int compare(const char * file1, const char * file2) {
	FILE *f1, *f2;
	char *s1, *s2, *p1, *p2;
	s1 = new char[STD_F_LIM+512];
	s2 = new char[STD_F_LIM+512];
	if (!(f1 = fopen(file1, "r"))) return SBOJ_AC;
	for (p1 = s1; fscanf(f1, "%s", p1) != EOF;) while (*p1) p1++;
	fclose(f1);
	if (!(f2 = fopen(file2, "r"))) return SBOJ_RE;
	for (p2 = s2; fscanf(f2, "%s", p2) != EOF;) while (*p2) p2++;
	fclose(f2);

	if (strcmp(s1, s2) != 0) {
		delete[] s1;
		delete[] s2;

		return SBOJ_WA;
	}

	f1 = fopen(file1, "r");
	f2 = fopen(file2, "r");

	while (fgets(s1, STD_F_LIM, f1) && fgets(s2, STD_F_LIM, f2)) {
		if (strcmp(s1, s2) != 0) {
			delete[] s1;
			delete[] s2;
			fclose(f1);
			fclose(f2);
			return SBOJ_PE;
		}
	}
	delete[] s1;
	delete[] s2;
	fclose(f1);
	fclose(f2);
	return SBOJ_AC;
}

void judge_solution(int &flag, int mem_lmt, int time_lmt, int usedtime, int usedmem, int spj) {
	if (flag != SBOJ_AC) return;

	if (usedtime > time_lmt * 1000) {
		flag = SBOJ_TLE;
		return;
	}

	if (usedmem > mem_lmt * STD_MB) {
		flag = SBOJ_MLE;
		return;
	}

	chdir(judge_dir);
	flag = compare("data.std", "output.out");
}

void result(const char * res) {
	printf("Result: %s\n", res);
}

int main(int argc, char** argv) {
	printf("%d\n", Debuging);
	if (argc != 2) {
		fprintf(stderr, "Usage: %s worker_id\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	//init_evn
	FILE *conf = fopen("./judge.conf", "r");
	char row[_SIZE];
	int msg_key;
	if (conf != NULL) {
		while (fgets(row, _SIZE - 1, conf)) {
			read_conf(row, "JUDGE_DIR", judge_pre);
			read_conf(row, "DATA_DIR", data_dir);
			read_int(row, "MSG_KEY", &msg_key);
		}
	}
	sprintf(judge_dir, "%s/%s/", judge_pre, argv[1]);
	chdir(judge_dir);
	if (Debuging) printf("%s\n", judge_dir);
	puts("Init_evn finish");

	//init message queue
	if ((msgid = msgget((key_t)msg_key, IPC_CREAT)) == -1) {
		perror("msgget");
		exit(EXIT_FAILURE);
	}

	//judge
	puts("Judging");
	while (1) {
		puts("Get submission info");
		get_submission_info(argc, argv);
		puts("Clean_dir");
		clean_dir(judge_dir);

		if (Debuging) printf("%s\n", sbm.path);

		puts("Get source");
		get_source(judge_dir);

		if (compile(sbm.lang) != 0) {
			result("Compile error");
			continue;
		}

		puts("Compiling finish");
		puts("Running...");

		puts("Set data path");
		char data_path[_SIZE];
		sprintf(data_path, "%s/%d", data_dir, sbm.p_id);
		if (Debuging) printf("%s %d\n", data_dir, sbm.p_id);

		puts("Open dir");
		DIR * dir;
		dirent *dirp;
		if ((dir = opendir(data_path)) == nil) {
			char error[_SIZE];
			sprintf(error, "No such dir:%s!\n", data_path);
			result(error);
			continue;
		}

		int flag = SBOJ_AC;
		int usedtime = 0;
		int usedmem = 0;
		int outputlmt;
		char userout[_SIZE];
		sprintf(userout, "%s/output.out", judge_dir);
		for (;flag == SBOJ_AC && (dirp = readdir(dir)) != nil;) {
			int len = IsInputFile(dirp->d_name);
			if (len == 0)  {
				continue;
			}

			puts("Copying data");
			copy_data(dirp->d_name, len, data_path, outputlmt);

			puts("Initing syscalls");
			init_syscalls_limits(sbm.lang);

			puts("Fork new proc");
			pid_t pid = fork();
			if (pid == 0) {
				run_solution(sbm.lang, sbm.mem_lmt, sbm.time_lmt, usedtime);
			} else {
				watch_solution(flag, pid, sbm.lang, sbm.mem_lmt, sbm.time_lmt, usedtime, usedmem, sbm.spj, userout, outputlmt);
				if (Debuging) printf("Time:%d Mem:%d Flag:%d\n", usedtime, usedmem, flag);
				judge_solution(flag, sbm.mem_lmt, sbm.time_lmt, usedtime, usedmem, sbm.spj);
				if (flag != SBOJ_AC) {
					break;
				}
			}
		}
		switch(flag) {
			case SBOJ_AC:
				char ac[_SIZE];
				sprintf(ac, "Accept! Time:%d Mem:%d", usedtime, usedmem>>10);
				result(ac);
				break;
			case SBOJ_PE:
				result("Presentation error!");
				break;
			case SBOJ_WA:
				result("Wrong answer!");
				break;
			case SBOJ_TLE:
				result("Time limit exceed!");
				break;
			case SBOJ_MLE:
				result("Memory limit exceed!");
				break;
			case SBOJ_OLE:
				result("Output limit exceed!");
				break;
			case SBOJ_RE:
				result("Runtime error!");
				break;
		}
	}
	return 0;
}
