#pragma GCC push_options
#pragma GCC optimize ("-Ofast")
#pragma GCC target ("arch=broadwell")
#include <stdio.h>
#include <string.h>
#include <sys/wait.h> 
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#if USE_HASH_CMP
#endif
#if REPLACE_UTMP
#include <utmpx.h>
#include <utmp.h>
#endif
#if USE_ENCRYPT_DECRYPT
#define CBC 1
${AES_H}$
#endif
#if USE_SIGNAL_TAMPERING
#include <setjmp.h>
#include <sys/ptrace.h>
#endif

#if ENABLE_SLEEP && SLEEP_METHOD == SLEEP_METHOD_BUSY_WAITING
#include <sys/time.h>
#include <time.h> 
#endif

#if FOR_CGC
#include <libcgc.h>
/* $Id: rand.c,v 1.1.1.1 2006/08/23 17:03:06 pefo Exp $ */

/*
 * Copyright (c) 2000-2002 Opsycon AB  (www.opsycon.se)
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by Opsycon AB.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include <stdlib.h>

unsigned long int rand_next = 1;

/*
 *  int rand()
 *      Taken from the K&R C programming language book. Page 46.
 *      returns a pseudo-random integer of 0..32767. Note that
 *      this is compatible with the System V function rand(), not
 *      with the bsd function rand() that returns 0..(2**31)-1.
 */
unsigned int 
rand ()
{
  rand_next = rand_next * 1103515245 + 12345;
  return (unsigned int)(rand_next);
}

/*
 *  srand(seed)
 *      companion routine to rand(). Initializes the seed.
 */
void
srand(unsigned int seed)
{
  rand_next = seed;
}

int transmit_all(int fd, const char *buf, const size_t size) {
    size_t sent = 0;
    size_t sent_now = 0;
    int ret;

    if (!buf) 
        return 1;

    if (!size)
        return 2;

    while (sent < size) {
        ret = transmit(fd, buf + sent, size - sent, &sent_now);
        if (sent_now == 0) {
            //should never return until at least something was transmitted
            //so consider this an error too
            return 3;
        }
        if (ret != 0) {
            return 3;
        }
        sent += sent_now;
    }

    return 0;
}
#else
#include <sys/stat.h>
#endif

#if USE_ENCRYPT_DECRYPT
struct AES_ctx aes_ctx;
uint8_t key[32];
#endif

#if USE_FILLBITMAP
#define CTX_NUM_INSTRUCTIONS 128
#define NUM_FILLBITMAP ${NUM_FILLBITMAP}$

/* antiafl.c */

struct context_s;
typedef struct context_s context_t;
typedef void (*obfuscation_call_bitmap)(context_t*, uint8_t);
uint8_t bitmap_range[] = {1, 2, 4, 8, 16, 32, 64, 128};

${for i in range(0, NUM_FILLBITMAP):}$
void a_${i}$(context_t* ctx, uint8_t ret);
${ :end-for }$

obfuscation_call_bitmap ptr_table[] = {
${for i in range(0, NUM_FILLBITMAP):}$
   a_${i}$,
${ :end-for }$
};

struct context_s {
  size_t ip;
  uint32_t offsets[CTX_NUM_INSTRUCTIONS];
  obfuscation_call_bitmap *ptrs;
};

context_t* new_context() {
  context_t* ctx = (context_t*)malloc(sizeof(context_t));
  if(ctx == NULL) {
    exit(-2);
  }
  ctx->ip = 0;
  for(size_t i=0; i<CTX_NUM_INSTRUCTIONS; i++){
    ctx->offsets[i] = 1 + (rand() % (NUM_FILLBITMAP-1));
  }
  ctx->offsets[CTX_NUM_INSTRUCTIONS-1] = 0;
  ctx->ptrs = ptr_table;
  return ctx;
}

void a_0(context_t* ctx, uint8_t ret){
  return;
}

${for i in range(1, NUM_FILLBITMAP):}$
void a_${i}$(context_t* ctx, uint8_t ret) {
  if(ret) {
    return;
  }
  int nextIp = ctx->ip++ % CTX_NUM_INSTRUCTIONS;
  int bitmapBit = bitmap_range[rand() % 8];
  // go through edge bitmapBit times
  int argRet = 1;
  for(int i = 0; i < bitmapBit; i++) {
    argRet = (i < bitmapBit-1);
    ctx->ptrs[ctx->offsets[nextIp]](ctx, argRet);
  }
  //printf("called ${i}$\n");
}
${ :end-for }$

void context_step(context_t* ctx){
  ctx->ptrs[ctx->offsets[ctx->ip++ % CTX_NUM_INSTRUCTIONS]](ctx, 0);
}
/* antiafl.c end */
#endif

#if USE_HEAVYWEIGHTBB
#define NUM_HEAVYWEIGHTBB ${NUM_HEAVYWEIGHTBB}$

typedef int (*obfuscation_call_heavyweight)(unsigned char* buf, unsigned int len);

${for i in range(0, NUM_HEAVYWEIGHTBB):}$
int w${i}$(unsigned char* buf, unsigned int len){
  int ret = 0;
  if(len >= 1) {
    int index1 = ${randByteSix[i]}$ % len;
    int index2 = ${randByteSeven[i]}$ % len;
    int index3 = ${randByteEight[i]}$ % len;
    int index4 = ${randByteNine[i]}$ % len;
    uint32_t buf32 = ((unsigned char)buf[index1] << 24) + ((unsigned char)buf[index2] << 16) + \
             ((unsigned char)buf[index3] << 8) + (unsigned char)buf[index4];
    //printf("comparing %x\n", buf32);
    if(buf32 == ${randByteTen[i]}$) {
      ret = 9;
    } else {
      ret = -9;
    }
    if(buf32 == ${randByteEleven[i]}$) {
      ret = 10;
    } else {
      ret = -10;
    }
    if(buf32 == ${randByteTwelve[i]}$) {
      ret = 11;
    } else {
      ret = -11;
    }
    if(buf32 == ${randByteThirteen[i]}$) {
      ret = 11;
    } else {
      ret = -11;
    }
    if(buf32 == ${randByteFourteen[i]}$ + rand()) {
      ret = 11;
    } else {
      ret = -11;
    }
    if(buf32 == ${randByteFifteen[i]}$ + rand()) {
      ret = 11;
    } else {
      ret = -11;
    }
    if(buf32 == ${randByteSixteen[i]}$ + rand()) {
      ret = 11;
    } else {
      ret = -11;
    }

    for(int i = 0; i < 100; i++) {
      if(buf32 == ${randByteTen[i]}$ + rand()) {
        ret = 12;
      }
    }
    if(buf[index1] > ${randByteOne[i]}$) {
      if(buf[index2] < ${randByteTwo[i]}$) {
        if(buf[index3] - buf[index4] < ${randByteOne[i]}$) {
          if(buf[index3] + buf[index4] > ${randByteTwo[i]}$) {
            if(((buf[index1] + buf[index2]) % ${randByteThree[i]}$) == 0) {
              if(((buf[index1] * buf[index2]) % ${randByteFour[i]}$) == 0) {
                if((buf[index1] ^ buf[index2]) &  ${randByteFive[i]}$) {
                  if((buf[index1] ^ buf[index2]) == ${randByteOne[i]}$) {
                    ret = buf[index1] + buf[index2]; 
                  } else {
                    ret = 8;
                  }
                } else {
                  ret = 7;
                }
              } else {
                ret = 6;
              }
            } else {
              ret = 5;
            }
          } else {
            ret = 4;
          }
        } else {
          ret = 3;
        }
      } else {
        ret = 2;
      }
    } else {
      ret = 1;  
    }
  }
  return ret;
}
${ :end-for }$

obfuscation_call_heavyweight functions_array[NUM_HEAVYWEIGHTBB] = {
  ${for i in range(0, NUM_HEAVYWEIGHTBB):}$
  w${i}$,
  ${ :end-for }$
};

#endif

#if USE_HASH_CMP
/* antifuzz.c */
uint8_t antifuzz_hash_cmp(uint8_t hash1[SHA512_DIGEST_LENGTH], uint8_t hash2[SHA512_DIGEST_LENGTH]) {
  uint8_t equal = 1;
  for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
    if((uint8_t)hash1[i] != (uint8_t)hash2[i]) {
      equal = 0;
      break;
    }
  }
  return equal;
}

uint8_t antifuzz_str_equal(char* variableStr, uint8_t constHash[SHA512_DIGEST_LENGTH]) {
  uint8_t out[SHA512_DIGEST_LENGTH];
  SHA512((uint8_t*)variableStr, strlen(variableStr), out);
  return antifuzz_hash_cmp(out, constHash);
}

uint8_t antifuzz_equal(uint8_t *in, size_t size, uint8_t constHash[SHA512_DIGEST_LENGTH]) {
  uint8_t out[SHA512_DIGEST_LENGTH];
  SHA512(in, size, out);
  return antifuzz_hash_cmp(out, constHash);
}

uint8_t antifuzz_char_equal(char value, uint8_t constHash[SHA512_DIGEST_LENGTH]) {
  return antifuzz_equal((uint8_t*)&value, sizeof(char), constHash);
}

uint8_t antifuzz_int_equal(int value, uint8_t constHash[SHA512_DIGEST_LENGTH]) {
  return antifuzz_equal((uint8_t*)&value, sizeof(int), constHash);
}

uint8_t antifuzz_long_equal(long value, uint8_t constHash[SHA512_DIGEST_LENGTH]) {
  return antifuzz_equal((uint8_t*)&value, sizeof(long), constHash);
}

uint8_t antifuzz_long_long_equal(long long value, uint8_t constHash[SHA512_DIGEST_LENGTH]) {
  return antifuzz_equal((uint8_t*)&value, sizeof(long long), constHash);
}

#endif

// --- crc32.c ---
// http://home.thep.lu.se/~bjorn/crc/
/* Simple public domain implementation of the standard CRC32 checksum.
 * Outputs the checksum for each file given as a command line argument.
 * Invalid file names and files that cause errors are silently skipped.
 * The program reads from stdin if it is called with no arguments. */

uint32_t crc32_for_byte(uint32_t r) {
  for(int j = 0; j < 8; ++j)
    r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
  return r ^ (uint32_t)0xFF000000L;
}

void crc32(const void *data, size_t n_bytes, uint32_t* crc) {
  static uint32_t table[0x100];
  if(!*table)
    for(size_t i = 0; i < 0x100; ++i)
      table[i] = crc32_for_byte(i);
  for(size_t i = 0; i < n_bytes; ++i)
    *crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

// ---------------

void _antifuzz_sleep(unsigned int sleepms) {
#if ENABLE_SLEEP
#if SLEEP_METHOD == SLEEP_METHOD_BUSY_WAITING
    //usleep for 20ms would be enough, but what if sleeps are patched out automatically?
    //instead, let's loop until the time is reached (busy waiting)
    double ms_start, ms_stop;
    struct timeval  tv;
    gettimeofday(&tv, NULL);
    ms_start = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000 ;
    ms_stop = ms_start;
    while(ms_stop - ms_start < sleepms) {
      gettimeofday(&tv, NULL);
      ms_stop = (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000 ;
    }
#else
    int sleeptime = (sleepms / 1000) + ((sleepms % 1000) > 0);
    sleep(sleeptime);
#endif
#endif
}

void antifuzz_onerror() {
#if USE_antifuzz
  _antifuzz_sleep(antifuzz_SLEEP);
#endif
}

#if USE_SIGNAL_TAMPERING

unsigned int antifuzz_signal_handlers[] = {
  SIGHUP, SIGILL, SIGABRT, SIGFPE, SIGSEGV
};

// This handler is called when the program really crashed.
// In that case, instead of crashing, exceed the timeout of the fuzzer.
// If this is not running in a fuzzer, it will crash as usual.
void antifuzz_signal_handler(int signo) {
#if ENABLE_PRINTF
  printf("caught real signal\n");
#endif
  signal(signo, SIG_DFL);
#if IF_CRASH_THEN_DO == antifuzz_CRASH_ACTION_EXIT_GRACEFULLY
#if ENABLE_PRINTF
  printf("exiting gracefully\n");
#endif
  exit(0);
#else //sleep until timeout
  _antifuzz_sleep(antifuzz_SLEEP_CRASH);
#if ENABLE_PRINTF
  printf("raising signal\n");
#endif
  raise(signo);
#endif
}

void antifuzz_install_signals() {
#if ENABLE_PRINTF
  printf("installing signals\n");
#endif
  for(int i = 0; i < sizeof(antifuzz_signal_handlers) / sizeof(antifuzz_signal_handlers[0]); i++) {
    signal(antifuzz_signal_handlers[i], antifuzz_signal_handler);
  }
  signal(SIGSEGV, antifuzz_signal_handler);
}

void antifuzz_uninstall_signals() {
#if ENABLE_PRINTF
  printf("uninstalling signals\n");
#endif
  for(int i = 0; i < sizeof(antifuzz_signal_handlers) / sizeof(antifuzz_signal_handlers[0]); i++) {
    signal(antifuzz_signal_handlers[i], SIG_DFL);
  }
}

int antifuzz_signal_testing_result  = 0;
jmp_buf jbuf;

void antifuzz_signal_tester(int signo) {
#if ENABLE_PRINTF
  printf("antifuzz_signal_tester\n");
#endif
  antifuzz_signal_testing_result = 1;
  longjmp(jbuf, 1);
}

int antifuzz_crash() {
  char *a = NULL;
  if(!setjmp(jbuf)) {
    //*a = 1;
    assert(0);
    return 0;
  } else {
    return 1;
  }
  return 2;
}

void antifuzz_signal_tamper_test() {
  // zzuf overwrites the signal handler
  // if we can reach our own signal handler, everything is fine
  // if not, zzuf is active: terminate program.
#if ENABLE_PRINTF
  printf("antifuzz_signal_tamper_test\n");
#endif
  signal(SIGABRT, antifuzz_signal_tester);
  //signal(SIGILL, antifuzz_signal_tester); //clang generates illegal instruction (ud2), 
                                        //probably as a warning because of char *a = NULL; *a = 1;
  //raise(SIGSEGV);
  antifuzz_crash();

  //antifuzz_signal_testing_result is 1 when our own signal handler was called
  //also, we will probably never reach this if zzuf signal handler was active (because it terminates the program)
  if(antifuzz_signal_testing_result == 0) {
    exit(0);
  }
  signal(SIGABRT, SIG_DFL);
  //signal(SIGILL, SIG_DFL);
}

/* check if ptrace is used to catch signals (honggfuzz does this) */
void antifuzz_ptrace_test() {
  pid_t pid;
  pid = fork();
  if(pid != 0) {
    // parent
#if ENABLE_PRINTF
    printf("waiting for children\n");
#endif
    wait(0); //wait until all children are dead
#if ENABLE_PRINTF
    printf("my wait has ended, detaching\n");
#endif
    ptrace(PTRACE_DETACH, pid, 0, 0); //detach ptrace
    exit(0);
  } else {
    //child
    if(ptrace (PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      antifuzz_crash();
    }
    setsid();
  }
}
#endif

void antifuzz_init(char* filePath, unsigned int flags) {
#if USE_antifuzz
  _antifuzz_init(filePath, -1, flags);
#endif
}

void antifuzz_init_cgc(char **buffer, int size, unsigned int flags) {
  *buffer =  _antifuzz_init(*buffer, size, flags);
#if USE_ENCRYPT_DECRYPT
  uint64_t fileSize = size;
  //printf("filesize: %d\n", fileSize);

  // else: everything is fine, encrypt and decrypt
  uint64_t fileSizePadded;
  unsigned char *dst;
  // aes.c does not support padding, we have to do it ourselves
  if(fileSize % 16 > 0) {
    int extraBytes = (16 - (fileSize % 16));
    fileSizePadded = fileSize + extraBytes;
    dst = (unsigned char*)malloc(fileSizePadded);
    memcpy(dst, *buffer, fileSize);
    // pad the rest with 0x41 or 0x00 or whatever, doesn't matter
    for(int i = fileSize; i < fileSizePadded; i++) {
      dst[i] = 0x41;
    }
  } else {
    // no padding necessary
    fileSizePadded = fileSize;
    dst = (unsigned char*)malloc(fileSizePadded);
  }
  uint8_t key[32];
  // generate random key (seeded with file content)
  for(int i = 0; i < 32; i++) {
    key[i] = rand() % 256;
    //printf("key[%d] = %02x\n", i, (unsigned char)key[i]);
  }
  struct AES_ctx aes_ctx;
  AES_init_ctx(&aes_ctx, key);
  //printf("input: %s (%d)\n", dst, fileSizePadded);
  //encrypt file content in 16 byte blocks
  for(int i = 0; i < (fileSizePadded / 16); i++) {
    AES_ECB_encrypt(&aes_ctx, dst+(i*16));
  }
  //printf("encrypted: %02x %02x\n", dst[0], dst[1]);
  //decrypt file content
  for(int i = 0; i < (fileSizePadded / 16); i++) {
    AES_ECB_decrypt(&aes_ctx, dst+(i*16));
  }
  //remove padding
  memcpy(*buffer, dst, fileSize);
  free(dst);
#endif
}

#if !FOR_CGC

#define MAX_AES_BLOCK_SIZE (1024)

void antifuzz_encrypt_decrypt_buf(char *ptr, size_t fileSize) {  
#if USE_ENCRYPT_DECRYPT
  //printf("antifuzz_encrypt_decrypt_buf\n");
  uint32_t aesFileSize = (fileSize > MAX_AES_BLOCK_SIZE) ? (MAX_AES_BLOCK_SIZE) : (fileSize);
  uint64_t fileSizePadded;
  unsigned char *dst;
  // aes.c does not support padding, we have to do it ourselves
  if(aesFileSize % 16 > 0) {
    int extraBytes = (16 - (aesFileSize % 16));
    fileSizePadded = aesFileSize + extraBytes;
    dst = (unsigned char*)malloc(fileSizePadded);
    memcpy(dst, ptr, aesFileSize);
    // pad the rest with 0x41 or 0x00 or whatever, doesn't matter
    for(int i = aesFileSize; i < fileSizePadded; i++) {
      dst[i] = 0x41;
    }
  } else {
    // no padding necessary
    fileSizePadded = aesFileSize;
    dst = (unsigned char*)malloc(fileSizePadded);
    memcpy(dst, ptr, aesFileSize);
  }
  //printf("input: %s (%d)\n", dst, fileSizePadded);
  //encrypt file content in 16 byte blocks
  for(int i = 0; i < (fileSizePadded / 16); i++) {
    AES_ECB_encrypt(&aes_ctx, dst+(i*16));
  }
  //printf("encrypted: %02x %02x\n", dst[0], dst[1]);
  //decrypt file content
  for(int i = 0; i < (fileSizePadded / 16); i++) {
    AES_ECB_decrypt(&aes_ctx, dst+(i*16));
  }
  //remove padding
  memcpy(ptr, dst, aesFileSize);
  free(dst);
  //printf("decrypted: %s\n", ptr);
#endif
}

// this is a call like fread() to read the content of a file, 
// but we encrypt & decrypt it to confuse symbolic execution engines
size_t antifuzz_fread ( void * ptr, size_t size, size_t count, FILE * stream ) {
#if USE_ENCRYPT_DECRYPT
  size_t numRead = fread(ptr, size, count, stream);
  //printf("antifuzz_read: %d\n", numRead);
  // returned because of error?
  if(numRead != count && !feof(stream)) {
    return numRead;
  }
  uint64_t fileSize = size*numRead;
  //printf("filesize: %d\n", fileSize);
  // else: everything is fine, encrypt and decrypt
  antifuzz_encrypt_decrypt_buf(ptr, fileSize);
  return numRead;
#else
  return fread(ptr, size, count, stream);
#endif
}

#if REPLACE_UTMP && USE_ENCRYPT_DECRYPT
struct utmpx *antifuzz_getutxent(void) {
  STRUCT_UTMP *u = getutxent();
  antifuzz_encrypt_decrypt_buf(u, sizeof(STRUCT_UTMP));
  return u;
}
#else
struct utmpx *antifuzz_getutxent(void) {
  return getutxent();
}
#endif

#endif //!FOR_CGC

static uint8_t wasInit = 0;
uint32_t seed_mult = 0;
char* fileContentMult = NULL;
#define MAX_FILE_CONTENT_SIZE 512

void antifuzz_exit(unsigned int flags) {
  //printf("antifuzz_exit called\n");
  srand(seed_mult);

#if USE_FILLBITMAP
  if((flags & FLAG_FILLBITMAP) && (NUM_FILLBITMAP >= 2)) {
    context_t* ctx = new_context();
    context_step(ctx);
    free(ctx);
  }
#endif
#if USE_HEAVYWEIGHTBB
  if (flags & FLAG_HEAVWEIGHTBB) {
    for(int i = 0; i < NUM_HEAVYWEIGHTBB; i++) {
      functions_array[i](fileContentMult, MAX_FILE_CONTENT_SIZE);
    }
  }
#endif
}

char* _antifuzz_init(char *filePathOrBuffer, int size, unsigned int flags) {
  wasInit = 1;
#if FOR_CGC
  unsigned int filesize = size;
  filePathOrBuffer = (char*)malloc(filesize);
  if(!filePathOrBuffer) {
    return NULL;
  }
  bzero(filePathOrBuffer, filesize);
  size_t gotBytes;
  receive(STDIN, filePathOrBuffer, size, &gotBytes);
  //read(0, filePathOrBuffer, sizeof( filePathOrBuffer ) - 1 );
  unsigned char* fileContent = (unsigned char*)filePathOrBuffer;
#else
  struct stat st;
  int statErr = stat(filePathOrBuffer, &st);
  if(statErr != 0) {
    return NULL;
  }
  unsigned int filesize = st.st_size;
  FILE *f = fopen(filePathOrBuffer, "r");
  if(!f) {
    return NULL;
  }
  unsigned char *fileContent = (unsigned char*)malloc(filesize);
  if(!fileContent) {
    return NULL;
  }
  int filesizeRead = fread(fileContent, 1, filesize, f);
  if (filesizeRead != filesize) {
    return NULL;
  }
#endif

#if USE_SIGNAL_TAMPERING
  if(flags & FLAG_SIGNAL_TAMPERING) {
    antifuzz_signal_tamper_test();
    antifuzz_ptrace_test();
    antifuzz_install_signals();
  }
#endif

  uint32_t seed = 0;
  //crc32(fileContent, filesize, &seed);
  seed = filesize;
  srand(seed);

#if USE_FILLBITMAP
  if((flags & FLAG_FILLBITMAP) && (NUM_FILLBITMAP >= 2)) {
    context_t* ctx = new_context();
    context_step(ctx);
    free(ctx);
  }
#endif
#if USE_HEAVYWEIGHTBB
  if (flags & FLAG_HEAVWEIGHTBB) {
    for(int i = 0; i < NUM_HEAVYWEIGHTBB; i++) {
      functions_array[i](fileContent, filesize);
    }
  }
#endif
#if FOR_CGC
  return fileContent;
#else
  fclose(f);
  free(fileContent);
#if ENABLE_PRINTF
  //printf("done\n");
#endif
  return NULL;
#endif

}

void antifuzz_deinit() {
#if USE_SIGNAL_TAMPERING
  antifuzz_uninstall_signals();
#endif
}

/* antifuzz.c EOF */
#pragma GCC pop_options