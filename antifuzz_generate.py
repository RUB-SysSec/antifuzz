#!/usr/bin/python

import sys, re, os
from templite import Templite
import hashlib
import argparse, random

# https://stackoverflow.com/questions/16022556/has-python-3-to-bytes-been-back-ported-to-python-2-7
def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

def getType(line):
  if "char" in line and '"' in line:
    return "string"
  elif "char" in line:
    return "char"
  elif "int" in line:
    return "int"
  elif "long long" in line:
    return "long long"
  elif "long" in line:
    return "long"
  else:
    return None

def getName(line):
  s = line.split(' ')
  s = filter(lambda x: x != '', s)
  nameIndex = s.index('=')-1
  if s[nameIndex].startswith("*"):
    s[nameIndex] = s[nameIndex][1:]
  if s[nameIndex].endswith("[]"):
    s[nameIndex] = s[nameIndex][:-2]
  return s[nameIndex]

def getValue(line):
  #s = line.split(' ')
  #s = filter(lambda x: x != '', s)
  #valueIndex = s.index('=')+1
  #if s[valueIndex].endswith(";"):
  #  s[valueIndex] = s[valueIndex][:-1]
  #return s[valueIndex]
  equalPos = line.index('=')
  semicolonPos = line.rindex(';')
  return line[equalPos+1:semicolonPos]

def hexStrToByteArray(h):
  ret = "{"
  for i in range(0, len(h), 2):
    if i != 0:
      ret += ", "
    ret += "0x%s" % h[i:i+2]
  ret += "}"
  return ret


fillbitmapFunctions = 0
heavyweightbbs = 0
detectafl = False
detectqemu = False
detectpin = False
forcgc = False
difficulty = 4
sleepcrashms = 750
sleepms = sleepcrashms
enablesignal = False
#disablecmp = False
hashcmp = False
nodebugger = False
anticoverage = False
crashaction = 0
sleepmethod = 0
enableencryptdecrypt = False
enablesleep = False
enableantifuzz = True
outputqueuefile = False
includeunistd = True
enablePrintf = True

parser = argparse.ArgumentParser(description="", prog="antifuzz_generate", usage="%(prog)s <options>")
parser.add_argument('--fill-bitmap', '-f', dest='fillbitmap', metavar='--fill-bitmap', help='Number of functions (for Anti-AFL and Anti-TFuzz). Use 0 to disable support.', nargs=1)
parser.add_argument('--heavyweight-bb', '-b', dest='heavyweightbb', metavar='--heavyweight-bb', help='Number of basic blocks for great weights (Anti-Vuzzer, Anti-Klee). Use 0 to disable support.', nargs=1)
parser.add_argument('--enable-anti-coverage', dest="enableanticoverage", action='store_true', help='Set --fill-bitmap to 1000 and --heavyweight-bb to 1000')
parser.add_argument('--anti-coverage', '-c', dest='anticoverageval', metavar='--anti-coverage', help='Set --fill-bitmap and --heavyweight-bb to this value', nargs=1)
parser.add_argument('--signal', dest='enablesignal', action='store_true', help='Enable tampering with signals to generate false crash reports (Anti-zzuf) and prevent real crashes from being known (Anti-AFL).')
parser.add_argument('--detect-all', dest="detectall", action='store_true', help='Try to detect all fuzzers and exit if one of them is found')
parser.add_argument('--detect-afl', dest="detectafl", action='store_true', help='Try to detect AFL and exit if found')
parser.add_argument('--detect-qemu', dest="detectqemu", action='store_true', help='Try to detect QEMU (used by some fuzzers, e.g. AFL) and exit it found')
parser.add_argument('--detect-pin', dest='detectpin', action='store_true', help='Try to detect Intel-PIN (used by some fuzzers, e.g. Vuzzer)')
parser.add_argument('--enable-sleep', dest="enablesleep", action='store_true', help='Enable sleep function')
parser.add_argument('--cgc', dest="forcgc", action='store_true', help='Cyber Grand Challenge mode: disable sleep and get input from stdin (and other adjustments)')
parser.add_argument('--difficulty', '-d', dest='difficulty', metavar='--difficulty', help='Set difficulty level, i.e. how many bytes need to be correct to crash', nargs=1)
parser.add_argument('--sleep', dest='sleepms', help='How many milliseconds to sleep in case of error', nargs=1)
parser.add_argument('--sleep-after-crash', dest='sleepcrashms', help='How many milliseconds to sleep in case of crash', nargs=1)
parser.add_argument('--disable-printf', dest="disableprintf", action='store_true', help='Disable printfs')
#parser.add_argument('--disable-cmp', dest="disablecmp", action='store_true', help='Disable EQUAL functions (remove SHA512/hashing support)')
parser.add_argument('--hash-cmp', dest="hashcmp", action='store_true', help='Activate hash comparison functions (also use hash compare in antifuzz_test.c)')
parser.add_argument('--no-debugger', dest="nodebugger", action='store_true', help='Prevent debugging by detaching child process from parent by forking')
parser.add_argument('--crash-action', dest="crashaction", metavar='--crash-action', help='"timeout" if it should be replaced with a timeout (default), "exit" if crash should be replaced with graceful exit', nargs=1)
parser.add_argument('--sleep-method', dest='sleepmethod', metavar='--sleep-method', help='"busy" for busy wait (default) and "sleep" for more traditional sleep()', nargs=1)
parser.add_argument('--enable-encrypt-decrypt', dest="enableencryptdecrypt", action='store_true', help="Enable encrypting and decrypting file content before usage to overload symbolic execution engines.")
parser.add_argument('--output-queue-file', dest="outputqueuefile", action="store_true", help="For zzuf: output file that was read to queue/ directory")
parser.add_argument('--disable-unistd', dest="disableunistd", action="store_true", help="Disable including unistd (lava-m/coreutils needs this)")
parser.add_argument('--disable-all', dest="disableall", action="store_true", help="Disable antifuzz functions")
args = parser.parse_args()

if args.enableanticoverage:
  anticoverage = True
  fillbitmapFunctions = 10000
  heavyweightbbs = 10000
if args.fillbitmap:
  fillbitmapFunctions = int(args.fillbitmap[0])
if args.heavyweightbb:
  heavyweightbbs = int(args.heavyweightbb[0])
if args.anticoverageval:
  fillbitmapFunctions = int(args.anticoverageval[0])
  heavyweightbbs = int(args.anticoverageval[0])
  anticoverage = True
if args.enablesignal:
  enablesignal = True
if args.detectafl:
  detectafl = True
if args.detectqemu:
  detectqemu = True
if args.detectpin:
  detectpin = True
if args.enablesleep:
  enablesleep = True
if args.forcgc:
  forcgc = True
  #enablesleep = False
if args.detectall:
  detectafl = True
  detectqemu = True
  detectpin = True
if args.difficulty:
  difficulty = int(args.difficulty[0])
if args.sleepms:
  sleepms = int(args.sleepms[0])
if args.sleepcrashms:
  sleepcrashms = int(args.sleepcrashms[0])
#if args.disablecmp:
#  disablecmp = True
if args.disableprintf:
  enablePrintf = False
if args.hashcmp:
  hashcmp = True
if args.nodebugger:
  nodebugger = True
if args.crashaction:
  crashaction = 0 
  if args.crashaction[0] == "timeout":
    crashaction = 0
    print("Enabling sleep because crash-action set to timeout.")
    enablesleep = True
  elif args.crashaction[0] == "exit":
    crashaction = 1
  else:
    print "invalid argument %s" % args.crashaction[0]
    sys.exit(-1)
if args.sleepmethod:
  sleepmethod = 0 if args.sleepmethod[0] == "busy" else 1
if args.enableencryptdecrypt:
  enableencryptdecrypt = True
if args.outputqueuefile:
  outputqueuefile = True
if args.disableunistd:
  includeunistd = False
if args.disableall:
  enableantifuzz = False




fileContent = open("antifuzz_constants.tpl.h", "r").readlines()

startParsing = False
newLines = []
for line in fileContent:
  line = line.strip()
  if "@START" in line:
    startParsing = True
  if startParsing and "=" in line:
    t = getType(line)
    n = getName(line)
    value = getValue(line)
    #print "Type: %s, name: %s, value: %s" % (t, n, value)
    oldValue = value

    exec("value = %s" % value)
    if t == "string":
      m = hashlib.sha512()
      m.update(value)
      calculatedHash = m.digest()
    elif t == "char":
      m = hashlib.sha512()
      m.update(value)
      calculatedHash = m.digest()
    elif t == "int":
      m = hashlib.sha512()
      m.update(to_bytes(value, 4, endianess='little'))
      calculatedHash = m.digest()
    elif t == "long":
      m = hashlib.sha512()
      m.update(to_bytes(value, 4, endianess='little'))
      calculatedHash = m.digest()
    elif t == "long long":
      m = hashlib.sha512()
      m.update(to_bytes(value, 8, endianess='little'))
      calculatedHash = m.digest()
    line = "static uint8_t %s[SHA512_DIGEST_LENGTH] = %s;" % (n, hexStrToByteArray(calculatedHash.encode("hex")))
  newLines.append(line)

antifuzz_constants_tpl_h = '\n'.join(newLines)
antifuzz_tpl_c = open("antifuzz.tpl.c", "r").read()
sha512_h = open("sha512.h", "r").read() + "\n" + open("sha512.c", "r").read()
aes_h = open("aes.h", "r").read() + "\n" + open("aes.c", "r").read()

# pre-render step (include all necessary files first)
fileContent = str(open("antifuzz.tpl.h", "r").read())
fileContent = fileContent.replace("${ANTIFUZZ_CONSTANTS_TPL_H}$", antifuzz_constants_tpl_h)
fileContent = fileContent.replace("${ANTIFUZZ_TPL_C}$", antifuzz_tpl_c)
fileContent = fileContent.replace("${SHA512_H}$", sha512_h)
fileContent = fileContent.replace("${AES_H}$", aes_h)

# and now render all options
fileOutput = open("antifuzz.h", "w+")
t = Templite(fileContent)
renderOptions = {}
renderOptions['USE_ANTIFUZZ']                 = int(enableantifuzz)
renderOptions['NUM_FILLBITMAP']             = fillbitmapFunctions
renderOptions['USE_FILLBITMAP']             = int(fillbitmapFunctions > 0)
renderOptions['NUM_HEAVYWEIGHTBB']          = heavyweightbbs
renderOptions['USE_HEAVYWEIGHTBB']          = int(heavyweightbbs > 0)
renderOptions['USE_SIGNAL_TAMPERING']       = int(enablesignal)
renderOptions['DETECT_AFL']                 = int(detectafl)
renderOptions['DETECT_QEMU']                = int(detectqemu)
renderOptions['DETECT_PIN']                 = int(detectpin)
renderOptions['ENABLE_SLEEP']               = int(enablesleep)
renderOptions['FOR_CGC']                    = int(forcgc)
renderOptions['DIFFICULTY_LEVEL']           = int(difficulty)
renderOptions['SLEEP_MS']                   = int(sleepms)
renderOptions['SLEEP_CRASH_MS']             = int(sleepcrashms)
#renderOptions['CMP_ENABLED']               = int(not disablecmp)
renderOptions['USE_HASH_CMP']               = int(hashcmp)
renderOptions['USE_ANTI_DEBUGGING']         = int(nodebugger)
renderOptions['CRASH_ACTION']               = int(crashaction)
renderOptions['SLEEP_METHOD']               = int(sleepmethod)
renderOptions['ENABLE_ENCRYPT_DECRYPT']     = int(enableencryptdecrypt)
renderOptions['ZZUF_OUTPUT_QUEUE_FILE']     = int(outputqueuefile)
renderOptions['INCLUDE_UNISTD']             = int(includeunistd)
renderOptions['ENABLE_PRINTF']              = int(enablePrintf)
renderOptions['REPLACE_UTMP']               = 0
renderOptions['randByteOne']                = [random.randrange(256)    for x in range(heavyweightbbs)]
renderOptions['randByteTwo']                = [random.randrange(256)    for x in range(heavyweightbbs)]
renderOptions['randByteThree']              = [random.randrange(2, 10)  for x in range(heavyweightbbs)] # remove 0 because we use this value for modulo
renderOptions['randByteFour']               = [random.randrange(2, 10)  for x in range(heavyweightbbs)] # dito
renderOptions['randByteFive']               = [2**random.randrange(7)   for x in range(heavyweightbbs)]
renderOptions['randByteSix']                = [x                        for x in range(heavyweightbbs)]
renderOptions['randByteSeven']              = [x+1                      for x in range(heavyweightbbs)]
renderOptions['randByteEight']              = [x+2                      for x in range(heavyweightbbs)]
renderOptions['randByteNine']               = [x+3                      for x in range(heavyweightbbs)]
renderOptions['randByteTen']                = [random.randrange(0x10000000, 0xffffffff) for x in range(heavyweightbbs)]
renderOptions['randByteEleven']             = [random.randrange(0x10000000, 0xffffffff) for x in range(heavyweightbbs)]
renderOptions['randByteTwelve']             = [random.randrange(0x10000000, 0xffffffff) for x in range(heavyweightbbs)]
renderOptions['randByteThirteen']           = [random.randrange(0x10000000, 0xffffffff) for x in range(heavyweightbbs)]
renderOptions['randByteFourteen']           = [random.randrange(0x10000000, 0xffffffff) for x in range(heavyweightbbs)]
renderOptions['randByteFifteen']            = [random.randrange(0x10000000, 0xffffffff) for x in range(heavyweightbbs)]
renderOptions['randByteSixteen']            = [random.randrange(0x10000000, 0xffffffff) for x in range(heavyweightbbs)]

fileContent = t.render(**renderOptions)
#print fileContent
fileOutput.write(fileContent)