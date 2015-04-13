#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#define MAX_TEXT 512
struct msg_st                    //消息队列的结构体
{
	int my_msg_type;
	int mem_lmt, time_lmt;
	char lang[10];
	int spj;
};
int main(int argc,char **argv)
{
	struct msg_st some_data;
	int msgid;

	if((msgid = msgget((key_t)12345,0666|IPC_CREAT)) == -1 )
	{
		perror("msgget");
		exit(EXIT_FAILURE);
	}

	while (1) {
		printf("Enter the mssage to send:");
		scanf("%d %d %s %d", &some_data.mem_lmt, &some_data.time_lmt, some_data.lang, &some_data.spj);

		if((msgsnd(msgid,(void *) &some_data,MAX_TEXT,0)) == -1)			
		{
			perror("msgsnd");
			exit(EXIT_FAILURE);
		}			
	}
	return 0;
}

