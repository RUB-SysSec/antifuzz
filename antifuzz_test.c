#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include "antifuzz.h"
#if !(FOR_CGC)
#include <sys/stat.h>
#endif

void crash() {
  printf("crashing\n");
  char *a = NULL;
  *a = 1;
}

int check(char* fileContent, int filesize) {
  /* crash if file content is "crsh" */
  if(filesize >= 4) {
  #if DIFFICULTY_LEVEL == 1
    #if USE_HASH_CMP == 1
      if(antifuzz_char_equal(fileContent[0], antifuzzC))
    #else
      if(fileContent[0] == 'c')
    #endif
      {
        return 1;
      } else {
        return 0;
      }
  #endif
  #if DIFFICULTY_LEVEL == 4
    #if USE_HASH_CMP == 1
      if(antifuzz_char_equal(fileContent[0], antifuzzC))
    #else
      if(fileContent[0] == 'c')
    #endif
      {
        printf("first character is correct\n");
      #if USE_HASH_CMP == 1
        if(antifuzz_char_equal(fileContent[1], antifuzzR))
      #else
        if(fileContent[1] == 'r')
      #endif
        {
          printf("second character is correct\n");
        #if USE_HASH_CMP == 1
          if(antifuzz_char_equal(fileContent[2], antifuzzS))
        #else
          if(fileContent[2] == 's')
        #endif
          {
            printf("third character is correct\n");
          #if USE_HASH_CMP == 1
            if(antifuzz_char_equal(fileContent[3], antifuzzH))
          #else
            if(fileContent[3] == 'h')
          #endif
            {
              printf("fourth character is correct\n");
              return 1;
            } else {
              return 0;
            }
          } else {
            return 0;
          }
        } else {
          return 0;
        }
      } else {
        return 0;
      }
    #endif
  } else {
    return 0;
  }
}

#if FOR_CGC
int __attribute__((fastcall)) main(int unused_argc, char *unused_argv[]) {
  char* fileContent = NULL;
  int filesize = 4;
  antifuzz_init_cgc(&fileContent, filesize, FLAG_ALL);
#else
int main(int argc, char* argv[]) {

  //printf("%s starting...\n", argv[0]);
  if(argc < 2) {
    printf("Usage: %s <file> \n", argv[0]);
    exit(-1);
  }

  // init antifuzz with all evasions and set argv[1] as an input file
  antifuzz_init(argv[1], FLAG_ALL);

  /*struct stat st;
  stat(argv[1], &st);
  unsigned int filesize = st.st_size;*/
  FILE *f = fopen(argv[1], "r");
  if(!f) {
    printf("can't open file\n");
    return -1;
  }
  fseek(f, 0L, SEEK_END);
  unsigned int filesize = ftell(f);
  fseek(f, 0L, SEEK_SET);
  unsigned char *fileContent = (unsigned char*)malloc(filesize);
  filesize = antifuzz_fread(fileContent, 1, filesize, f);
#endif

  if(check(fileContent, filesize)) {
    crash();
  } else {
    antifuzz_onerror();
  }

#if !FOR_CGC
  fclose(f);
#endif
  printf("antifuzz_test done\n");
  return 0;
}