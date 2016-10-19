#include <stdio.h>
#include <stdlib.h>
void badfunc(int *);
int main(int argc, char *argv[])
{
	if(argc<2)
		return 0;
	int in=atoi(argv[1]);
	if(in<=0)
		return 0;
	int *f=malloc(sizeof(int));
	*f=4;
	badfunc(f);
	if(in==3)
		printf("%d\n",*f);
}

void badfunc(int *arn)
{
	free(arn);
}

