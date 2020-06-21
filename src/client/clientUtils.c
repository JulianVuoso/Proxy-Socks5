#include "client/clientUtils.h"


//chekear que todos los comandos esten al final
void validateArgv(int argc,char * const*argv){
    for (int i = 1,optEnd = 0, optArg = 0; i < argc; i++)
    {
           if(!optArg){
               if(argv[i][0]=='-'){
                   if(optEnd){
                       printf("Formato erroneo, los comandos deben ir al final\n");
                       exit(-1);
                   }
                   optArg = 1;
               }else{
                   optEnd = 1;
               }
           }else{
               optArg = 0;
           }
    }
}