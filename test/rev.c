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
	int msgid1;
	struct msg_st some_data;

	if((msgid1= msgget((key_t)12345,0666|IPC_CREAT)) == -1)
	{
		perror("msgget");
		exit(EXIT_FAILURE);
	}		
	/*
	while (1) {
		if(msgrcv(msgid1,(void *) & some_data,BUFSIZ,0 , 0) == -1)  
		{  
			perror("msgrcv");  
			exit(EXIT_FAILURE);  
		}  
		printf("%d %d %s %d\n", some_data.mem_lmt, some_data.time_lmt, some_data.lang, some_data.spj);
	}
	*/
	printf("%u\n", BUFSIZ);
	if(msgctl(msgid1,IPC_RMID,0) == -1)
	{
		printf("msgctl(IPC_RMID) failed \n");
		exit(EXIT_FAILURE);
	}	
	return 0;
}

