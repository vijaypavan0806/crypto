#include<stdio.h>
int main()
{
    FILE *a;
    char x[40];
    int p=0;
    a=open("arun.txt", "r+");
    while(fgets(a, "%s", x)!=EOF)
    {
        p++;
    }
    printf("%d", p);
}
