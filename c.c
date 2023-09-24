#include <stdio.h>
#include <stdlib.h>
#include<time.h>
int main()
{
    printf("%d\n",time(0));
    int guess;
    int randm=rand()%10000;
    scanf("%d",&guess);
    if(guess==randm)
    {
        system("/bin/sh");
    }
    else
    {
        printf("rand:%d",randm);
    }

}
