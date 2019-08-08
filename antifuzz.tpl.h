#ifndef antifuzz_H
#define antifuzz_H
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#define FLAG_FILLBITMAP 1
#define FLAG_HEAVWEIGHTBB 2
#define FLAG_SIGNAL_TAMPERING 4
#define FLAG_ANTI_DEBUGGING 8
#define FLAG_AFL FLAG_FILLBITMAP
#define FLAG_TFUZZ FLAG_FILLBITMAP
#define FLAG_DRILLER FLAG_FILLBITMAP
#define FLAG_VUZZER FLAG_HEAVWEIGHTBB
#define FLAG_KLEE FLAG_HEAVWEIGHTBB
#define FLAG_ZZUF FLAG_SIGNAL_TAMPERING
#define FLAG_ALL FLAG_FILLBITMAP | FLAG_HEAVWEIGHTBB | FLAG_SIGNAL_TAMPERING | FLAG_ANTI_DEBUGGING

#define USE_antifuzz ${USE_antifuzz}$
#define USE_FILLBITMAP ${USE_FILLBITMAP}$
#define USE_HEAVYWEIGHTBB ${USE_HEAVYWEIGHTBB}$
#define DETECT_AFL ${DETECT_AFL}$
#define DETECT_QEMU ${DETECT_QEMU}$
#define DETECT_PIN ${DETECT_PIN}$
#define FOR_CGC ${FOR_CGC}$
#define ENABLE_SLEEP ${ENABLE_SLEEP}$
#define DIFFICULTY_LEVEL ${DIFFICULTY_LEVEL}$
#define antifuzz_SLEEP ${SLEEP_MS}$
#define antifuzz_SLEEP_CRASH ${SLEEP_CRASH_MS}$
#define USE_SIGNAL_TAMPERING (${USE_SIGNAL_TAMPERING}$ && !FOR_CGC)
#define USE_HASH_CMP ${USE_HASH_CMP}$
#define USE_ANTI_DEBUGGING (${USE_ANTI_DEBUGGING}$ && !FOR_CGC)
#define USE_ENCRYPT_DECRYPT ${ENABLE_ENCRYPT_DECRYPT}$
#define ZZUF_OUTPUT_QUEUE_FILE ${ZZUF_OUTPUT_QUEUE_FILE}$
#define REPLACE_UTMP ${REPLACE_UTMP}$

#define INCLUDE_UNISTD ${INCLUDE_UNISTD}$

#define antifuzz_CRASH_ACTION_SLEEP_UNTIL_TIMEOUT 0
#define antifuzz_CRASH_ACTION_EXIT_GRACEFULLY 1 
#define IF_CRASH_THEN_DO ${CRASH_ACTION}$

#define SLEEP_METHOD_BUSY_WAITING 0
#define SLEEP_METHOD_TRADITIONAL 1
#define SLEEP_METHOD ${SLEEP_METHOD}$

#define ENABLE_PRINTF ${ENABLE_PRINTF}$

#if USE_HASH_CMP
${SHA512_H}$
uint8_t antifuzz_hash_cmp(uint8_t hash1[SHA512_DIGEST_LENGTH], uint8_t hash2[SHA512_DIGEST_LENGTH]);
uint8_t antifuzz_str_equal(char* variableStr, uint8_t constHash[SHA512_DIGEST_LENGTH]);
uint8_t antifuzz_equal(uint8_t *in, size_t size, uint8_t constHash[SHA512_DIGEST_LENGTH]);
uint8_t antifuzz_char_equal(char value, uint8_t constHash[SHA512_DIGEST_LENGTH]);
uint8_t antifuzz_int_equal(int value, uint8_t constHash[SHA512_DIGEST_LENGTH]);
uint8_t antifuzz_long_equal(long value, uint8_t constHash[SHA512_DIGEST_LENGTH]);
uint8_t antifuzz_long_long_equal(long long value, uint8_t constHash[SHA512_DIGEST_LENGTH]);
#endif
void antifuzz_onerror();
void antifuzz_init(char* filePath, unsigned int flags);
char *antifuzz_init_multiple(char *filePathOrBuffer, unsigned int flags);
void antifuzz_exit(unsigned int flags);
char* _antifuzz_init(char *filePathOrBuffer, int size, unsigned int flags);
#if FOR_CGC
void antifuzz_init_cgc(char **buffer, int size, unsigned int flags);
#else
size_t antifuzz_fread(void * ptr, size_t size, size_t count, FILE * stream);
/*int antifuzz_fclose(FILE *stream);
FILE *antifuzz_fopen(const char *filename, const char *mode);
void antifuzz_generate_queue_file_by_filename(char* inputfilename);*/
#endif
void antifuzz_encrypt_decrypt_buf(char *ptr, size_t fileSize) ;

/* antifuzz_constants.tpl.h */
#if USE_HASH_CMP
${antifuzz_CONSTANTS_TPL_H}$
#endif

/* antifuzz.tpl.c file */
${antifuzz_TPL_C}$

#endif