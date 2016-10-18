#include <stdio.h>
#include <stdlib.h>

void badfunc(void *n);
int main(int argc, char *argv[])
{
	if(argc<2)
	{
		printf("not proper usage\n");
		return 1;
	}

	int *t=malloc(sizeof(int));
	*t=5;
	int p=atoi(argv[1]);
	if(p<5)
	{
		badfunc(t);
	}
	if(p==2)
		printf("%d",*t);

}

void badfunc(void *n)
{
	free(n);
}
