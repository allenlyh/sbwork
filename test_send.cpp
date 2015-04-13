#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#define MAX_TEXT 512
#define _SIZE 512
struct msg_st                    //消息队列的结构体
{
	int p_id, submission_id;
	int mem_lmt, time_lmt, spj, lang;
	char path[_SIZE] = "/home/allen/test.cpp";
};
int main(int argc,char **argv)
{
	struct msg_st some_data;
	int msgid;

	if((msgid = msgget((key_t)23333,0666|IPC_CREAT)) == -1 )
	{
		perror("msgget");
		exit(EXIT_FAILURE);
	}

	while (1) {
		printf("Enter the mssage to send:");
		scanf("%d %d %d %d", &some_data.mem_lmt, &some_data.time_lmt, &some_data.lang, &some_data.p_id);
		if (some_data.mem_lmt == -1) break;

		if((msgsnd(msgid,(void *) &some_data,MAX_TEXT,0)) == -1)			
		{
			perror("msgsnd");
			exit(EXIT_FAILURE);
		}			
	}
	if(msgctl(msgid,IPC_RMID,0) == -1)
	{
		printf("msgctl(IPC_RMID) failed \n");
		exit(EXIT_FAILURE);
	}	
	return 0;
}

