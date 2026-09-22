#include <stdio.h>
#include <stdlib.h>
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    srand((unsigned)strtoul(argv[1],0,0));
    for(unsigned i=0;i<4;++i)printf("%d\n",rand());
    return 0;
}
