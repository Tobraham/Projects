# CHANGE THIS VALUE TO INCREASE OR DECREASE THE SCRIPT'S
# ALLOWABLE PASSWORD LENGTH FOR BRUTE FORCING
# ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇
maxPassLength = 6   # Set to 6 for this project but could be much larger in real-world usage

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                                           #
#   Et Tu, Brute ?                                                                          #
#   by Toby Sheets                                                                          #
#   CU Boulder                                                                              #
#   TCP - Digital Forensics                                                                 #
#                                                                                           #
#   Crack an MD5-hashed password. Defaults to a brute force method unless                   #
#   you supply a wordlist, then it will default to a dictionary attack.                     #
#   There are a few mangler rules set up by adding the -m='' flag.                          #
#       Example: -m='c' iterates through the dictionary and capitalizes                     #
#       the first letter of the dictionary word.                                            #
#                                                                                           #
#   usage: >>>py ettubrute [-h] [-d D] pw                                                   #
#                                                                                           #
#     positional arguments:                                                                 #
#       pw = an md5 hash string -OR- /path/to/md5hash_file                                  #
#                                                                                           #
#     optional arguments:                                                                   #
#       -h, --help           show this help message and exit                                #
#       -d D, -dictionary D  [Optional] /path/to/wordlist_file for dictionary-based crack   #
#       -m M, -mangler M     [Optional] enables wordlist mangling rules.                    #
#                                                                                           #
#      Available mangling flags:                                                            #
#      Examples using 'password' from the wordlist:                                         #
#                                                                                           #
#       c - Capitalize 1st and/or last letter: Password, passworD                           #
#       C - Captilize each letter and all caps: Password, pAssword, ... PASSWORD            #
#       l - Lowercase entire word: password                                                 #
#       n - Prepend or append 1- and 2-digit numbers: 5password, password23                 #
#       p - Pluralize word by appending 's': passwords                                      #
#       d - Repeat any word <= 5 characters: passpass, dogdog, 123123                       #
#       D - Capitalize any word <= 5 characters and repeat it. i.e. PassPass, DogDog        #
#       r - Reverse the word. i.e. drowssap                                                 #
#       R - Capitalize, then reverse the word: drowssaP                                     #
#       s - split longer passwords into two words: pass, word                               #
#       t - Treat word like a verb and change tenses: passworded, passwords, passwording    #
#       T - capitalize, truncate and prepend/append 4 nums and '!': Pass1454!               #
#       y - Prepend/append 2- and 4-digit years from 1970-2010: 70password, password2019    #
#                                                                                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                                                                       #
#   Usage Examples:                                                                                                     #
#   1 - Brute force MD5 hash sent directly from command line:                                                           #
#        ettubrute 3c086f596b4aee58e1d71b3626fefc87                                                                     #
#                                                                                                                       #
#  2 - Dictionary crack an MD5 hash sent directly via command line:                                                     #
#        ettubrute 3c086f596b4aee58e1d71b3626fefc87 -d 'C:\Users\General\Documents\my_wordlist_file.txt'                #
#                                                                                                                       #
#   3 - Brute force MD5 hash from a text file directly from command line:                                               #
#        ettubrute 'C:\Users\General\Documents\my_hash_file.txt'                                                        #
#                                                                                                                       #
#   4 - Dictionary crack an MD5 hash contained in a text file                                                           #
#        ettubrute 'my_hash_file.txt' -d 'dictionary.txt'                                                               #
#                                                                                                                       #
#   5 - Dictionary crack with some mangling rules applied (capital permuitations and reversing the dictionary word)     #
#        ettubrute 'my_hash_file.txt' -d 'dictionary.txt' -m='Cr'                                                       #
#                                                                                                                       #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #




from math import floor          # For calculating program execution time
from os   import name           # For determing OS name to play beep notification
from os   import path           # For accessing user files
from os   import system         # For determing OS to play beep notification
import argparse                 # For taking command line args[]
import hashlib                  # For calculating md5 hashes of passwords
import itertools                # For looping through password values
import string                   # For accessing string ascii values, digits and punctuation
import sys                      # For exiting the app on completion.
import time                     # For calculating program execution time
import random                   # For randomizing our test library
import winsound                 # For notifing user when pass has been cracked

testPW              = ''
startTime           = 0
endTime             = 0
testedCombinations  = 0
manglerRules        = {
    'cap_ends'      : False,
    'capall'    : False,
    'duplicate' : False,
    'cap_dupe'  : False,
    'cap_rev'   : False,
    'lowerall'  : False,
    'numbers'   : False,
    'plural'    : False,
    'reverse'   : False,
    'split'     : False,
    'tense'     : False,
    'trunc_app' : False,
    'years'     : False
    }
mangledPWs          = set()
testedPWSet         = set()


class bcolors:
    # Simple class for formatting terminal output.
    # This code snippet was borrowed from the internet.
    NORMAL      = '\033[0m'
    BOLD        = '\033[1m'
    FAILED      = '\033[91m'
    SUCCESS     = '\033[92m'
    YELLOW      = '\033[93m'
    BLUE        = '\033[94m'

def main(crackParams):
    # Extract user input from command line args
    global startTime, endTime, testedCombinations, testPW
    if crackParams.d == None:
        # This is a brute force crack.
        startTime   = int(time.time())
        crackedPass = crack_BruteForce(crackParams)
        endTime     = int(time.time())
    else:
        # User supplied a dictionary, so this is a dictionary crack.
        startTime   = int(time.time())
        crackedPass = crack_Dictionary(crackParams)
        endTime     = int(time.time())
    if crackedPass == False:
        printFailedResults(testedCombinations)
    else:
        printResults(startTime, endTime, testedCombinations, crackedPass)

def getPassFromCommandLineArgs(pw):
    # Tests user input. If pw length = 32, then this should be an MD5 hash. Otherwise
    # I expect it to be a file path. If it's a hash, I'll verify that all the characters
    # are consistent with an MD5 hash (i.e. no unusual characters). If it's not a hash, I'll
    # test to see if it's a valid file path. If it's a file, I'll grab the hash from the file contents.
    if len(pw) == 32:
        if validateMD5(pw):
            return pw
    elif path.isfile(pw):
        pw = getPassFromHashFile(crackParams.pw)
        return pw
    else:
        # The file path was exactly 32 characters so it was impossible to tell if this was an MD5
        # hash or a file path. Essentially... I'm confused. Maybe if you rename your hash file the path
        # won't be 32 characters and I can go from there.
        print(f'''Well, this is embarassing - I am unsure if {crackParams.pw} is an md5 hash or a path to a file. \n
        My coding skills are no match. Would you mind trying a different hash or changing your filename slightly?''')
        sys.exit()

def validateMD5(pw):
    # Simple test to ensure your 32-digit entry matches a standard MD5 format before I crack it.
    validates = False
    illegalCharacters = False
    # Validate each character
    for i in pw.lower():
        if (i in md5library) == False:
            illegalCharacters = True
            clearTerminal()
            print(f"There seems to be an illegal character ({i}) in your MD5 hash. Please try again.")
            sys.exit()
            break
    if illegalCharacters == False:
        validates = True
    if  validates == True:
        return True
    return False

def getPassFromHashFile(hashFilePath):
    # Reads the MD5 hashed password from user-supplied text file
    # Returns pssword upon success, exits app on failure
    clearTerminal()
    pwRead = False
    while pwRead == False:
        try:
            f = open(hashFilePath)
            pw = (f.read())
            f.close()
            pwRead = True
        except OSError:
            clearTerminal()
            print (f"Could not open/read file at {hashFilePath}. Please try again.")
            sys.exit()

    # Validate the MD5 contained within the file
    if validateMD5(pw) == True:
        return pw
    else:
        print(f"unable to validate the hash contained in {hashFilePath}. Please try again.")
        sys.exit()

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Brute functions
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def crack_BruteForce(crackParams):
    # Iterates through generated character combinations up to maxPassLength
    # (defined on line 42 above) and tests them against user's hashed password.
    global libraryList, pw, testedCombinations, testPW
    pw = getPassFromCommandLineArgs(crackParams.pw)

    # charCounts will track the characters to be tested in each character
    # position of the temporary password. Since I can have up to maxPassLength characters,
    # I build a maxPassLength-item list and initialize the first to 0 and the rest to -1.
    # These values correspond to a character in our master library comparison
    # string (abcdABCD1234><:... etc).
    # Based on maxPassLength = 6, charCounts would initialize to:
    #   charCounts[0] = 0
    #   charCounts[1] = -1
    #   charCounts[2] = -1
    #   charCounts[3] = -1
    #   charCounts[4] = -1
    #   charCounts[5] = -1
    for i in range(maxPassLength):
        if i == 0:
            charCounts.append(0)
        else:
            charCounts.append(-1)

    # Create our master library string of all ascii alphanumeric characters and punctuation.
    # I'll iterate thru this list to build our brute force test combinations.
    libraryList = buildLibraryString()

    # I found that by shuffling the master comparison string I can sometimes increase
    # the speed at which a match is found. For example if my library string is always
    # (abc...ABC...123...~!@) and the user's password ends in a punctuation character,
    # then I are guaranteed that execution will have to loop until I reach the
    # punctuation portion of the master string. However, if I shuffle the master string
    # (e.g., ~2c1@a3AB~!bC), there's a chance that I could hit that last character of the
    # password sooner and shave off potentially millions of iterations. Of course,
    # sometimes it increases the execution time, but that's the chance you have to take.  :)
    # I have a 50/50 chance of speeding up the crack vs slowing it down. Those seem to be
    # fair odds. To test this, run the same crack a few times and observe the differences.
    # A 3-character pass can take up to 94^3 iterations to brute force without shuffling the
    # character list. Via shuffling, cracking it can be brought down to as low as
    # (94^2)+1 iterations.

    random.shuffle(libraryList)

    # Just in case this loop somehow gets away from me, I'm setting a max iteration time
    # of the length of our character library to the power of [maxPassLength] digits
    # in our hashed password.
    maxIterations = len(libraryList)**maxPassLength

    # Loop until I have found a matching password
    while testedCombinations <= maxIterations: # Set a cap on execution time in case I bugged some logic
        testedCombinations += 1 # increment our crack attempts count every time

        # Build a character combination to hash and compare
        testPW = buildTestPW()

        # Hash and compare the generated combination
        if hashAndCompareWord(testPW):
            return testPW
        else:
            # Update the character counters and try again on the next loop iteration.
            charCounts[0] = incrementCount(0)

        # Dispay iteration count while cracking pw so user knows we're still working
        if testedCombinations % 1000000 == 0:
            clearTerminal()
            leftToTry = maxIterations - testedCombinations
            print(f"Combinations left: {leftToTry:,d}")
    return False

def buildTestPW():
    # Concatenates a test password based on the count values in each character space
    testPW = ''
    for j in charCounts:
        if j >= 0:
            testPW += libraryList[j]
    return testPW

def buildLibraryString():
    # Concatenates a string of all available ascii characters to use for
    # sequential testing against the user's password.

    global libraryList, libraryString
    for x in string.ascii_lowercase:
        libraryList.append(x)
    for x in string.ascii_uppercase:
        libraryList.append(x)
    for x in string.digits:
        libraryList.append(x)
    for x in string.punctuation:
        libraryList.append(x)

    # Build a formatted display version of the library list as a string
    libraryString = ''
    for i in libraryList:
        libraryString = libraryString + i

    # Return the library list
    return libraryList

def buildMD5Library():
    # Quick routine to build an ASCII list of characters for brute force testing
    md5library = []
    for x in string.ascii_lowercase:
        md5library.append(x)
    for x in string.digits:
        md5library.append(x)
    return md5library

def buildMD5tring():
    # Builds a display version of acceptable MD5 hash characters
    # Used for notifying user of acceptable characters when submitting an MD5 hash
    # via thecommand line.
    md5String = ''
    for i in md5library:
        md5String += i
    return md5String

def incrementCount(digit):
    # This function keeps track of what characters I've tested. I start with a
    # list of maxPassLength characters (the max allowable password length) and each value
    # starts at -1, except for the first character, which starts at 0. As each
    # new password is tested, this function is called to increment the value of
    # the character tested. Once the character count reaches the end of all possible
    # characters, it is set back to 0 and the next character is # incremented from
    # -1 to 0 and I'll start the process over again. This is a nested function, so
    # if the current character count exceeds the max, it calls itself to increment
    # the next character in the sequence.

    newValue = 0
    max = len(libraryList)
    currentValue = charCounts[digit]

    # Check to see if I're on the last character in the test library string. If so,
    # then I've exhausted all possible combinations and still have no solution. At
    # that point I need to exit and go sulk in the corner for about 20 minutes. Otherwise
    # I need to set the counter back to 0 for this digit and increment the next
    # digit by 1 and keep working.
    if (currentValue + 1 == 0):
        newValue = currentValue + 1
    elif (currentValue + 1) % max != 0:
        newValue = currentValue + 1
    else:
        if (digit == maxPassLength-1):
            print("I've tried everything with no luck. <Sad panda>")
            userPause('Press any key to exit.')
            sys.exit()
        nextCharacter = digit + 1
        charCounts[nextCharacter] = incrementCount(nextCharacter)
    return newValue

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Dictionary functions
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def crack_Dictionary(crackParams):
    # Returns the cracked password if successful, otherwise returns False
    global pw, testedCombinations, testedPWSet, testPW, manglerRules
    pw = getPassFromCommandLineArgs(crackParams.pw)
    clearTerminal()
    if crackParams.m != None:
        unpackMangleRules(crackParams.m)

    # Display the mangler rules I're about to implement in this crack
    for key, value in manglerRules.items():
        if value == True:
            print(f"{key} -> {value}")
    userPause()
    # Open wordlist file and iterate through all entries. I always test the raw word from the wordlist
    # without any mangling first. If I don't have match, then I pass that word into the mangler
    # function and test and mangled values for a match.
    with open(crackParams.d, "r", encoding='utf8') as wordList:
        for testPW in wordList.readlines():
            testPW = testPW.strip()
            # Generate mangled version of the word for testing based on rules
            # and convert to a set so I don't waste our time testing duplicate
            # words generated from the various rules.
            mangledPWSet = set(getMangledPermutations(testPW))
            for mangledWord in mangledPWSet:
                #print(mangledWord)                      #           <------------------------------------------ Remove this before submitting
                testedCombinations += 1
                # If mangled word matches, stop iteration and print results.
                if hashAndCompareWord(mangledWord):
                    wordList.close()
                    return mangledWord

            # Dispay iteration count while cracking pw so user knows I'm still working
            if testedCombinations % 5000000 == 0:
                clearTerminal()
                print(f"Combinations tested: {testedCombinations:,d}")
        # I've exhausted our wordlist and still haven't found a matching hash
        wordList.close()
        return False
    return False

def unpackMangleRules(mRules):
    # Sets various mangling modes to True based on user input from command line
    # Returns a Python dictionary of rules with each rules set to True or False
    global manglerRules
    for i in mRules:
        if i == ':':
            # ':' sets ALL mangling rules to False, i.e. original word only. This is default
            for key in manglerRules:
                manglerRules[key] = False
        if i == 'A':
            # 'A' sets ALL mangling rules to True
            for key in manglerRules:
                manglerRules[key] = True
            return manglerRules
        else:
            # Set each rule to true if user's flag matches
            if i == 'c':
                manglerRules['cap_ends']    = True
            if i == 'C':
                manglerRules['capall']      = True
            if i == 'l':
                manglerRules['lowerall']    = True
            if i == 'n':
                manglerRules['numbers']     = True
            if i == 'p':
                manglerRules['plural']      = True
            if i == 'd':
                manglerRules['duplicate']   = True
            if i == 'D':
                manglerRules['cap_dupe']    = True
            if i == 'r':
                manglerRules['reverse']     = True
            if i == 'R':
                manglerRules['cap_rev']     = True
            if i == 's':
                manglerRules['split']       = True
            if i == 't':
                manglerRules['tense']       = True
            if i == 'T':
                manglerRules['trunc_app']   = True
            if i == 'y':
                manglerRules['years']   = True
    return manglerRules

def getMangledPermutations(testpw):
    # Iterate through the all the included mangling functions and build a set of mangled versions
    # of the test word to hash and compare. Each mangling routine returns a list of
    # permutations based on the particular rule. I compile all those permutations into one
    # set of mangled versions, including the raw word, and return them to the main dictionary
    # cracking function to hash and compare. I use a Python set so that any duplicates created
    # by multiple rules are ignored to be more efficient.

    global pw, mangledPWs, manglerRules
    mangledPWs = set()
    mangledPWs.add(testpw)
    for key in manglerRules.keys():
        # Iterate thru all rules and execute the ones flagged as True
        if manglerRules[key] == True:
            if  key  == 'cap_ends':
                permutations = mangle_capEnds(testPW)
                for i in range(len(permutations)):
                    mangledPWs.add(permutations[i])
            elif key == 'capall':
                permutations = mangle_capAll(testPW)
                for i in range(len(permutations)):
                    mangledPWs.add(permutations[i])
            elif key == 'duplicate':
                if len(testPW) < 6:
                    permutations = mangle_duplicate(testPW)
                    for i in range(len(permutations)):
                        mangledPWs.add(permutations[i])
            elif key == 'cap_dupe':
                if len(testPW) < 6:
                    mangledPWs.add(mangle_cap_dupe(testPW))
            elif key == 'cap_rev':
                permutations = mangle_cap_rev(testPW)
                for i in range(len(permutations)):
                    mangledPWs.add(permutations[i])
            elif key == 'lowerall':
                mangledPWs.add(mangle_lowerAll(testPW))
            elif key == 'numbers':
                permutations = mangle_numbers(testPW)
                for i in range(len(permutations)):
                    mangledPWs.add(permutations[i])
            elif key == 'plural':
                mangledPWs.add(mangle_puralize(testPW))
            elif key == 'reverse':
                mangledPWs.add(mangle_reverse(testPW))
            elif key == 'split':
                if len(testPW) > 5:
                    permutations = mangle_split(testPW)
                    for i in range(len(permutations)):
                        mangledPWs.add(permutations[i])
            elif key == 'tense':
                if testPW.isalpha() and len(testPW) > 3:
                    permutations = mangle_tense(testPW)
                    for i in range(len(permutations)):
                        mangledPWs.add(permutations[i])
            elif key == 'trunc_app':
                if len(testPW) > 4:
                    permutations = mangle_trunc_append(testPW)
                    for i in range(len(permutations)):
                        mangledPWs.add(permutations[i])
            elif key == 'years':
                permutations = mangle_years(testPW)
                for i in range(len(permutations)):
                    mangledPWs.add(permutations[i])
    return mangledPWs

def mangle_capEnds(testPW):
    # Convert testPW into a mutable list so I can upper case only the first and last letters, then convert it back to a string
    # and add it to our list of permutations.
    permutations = []

    # Upper first character
    mangledPass = list(testPW)
    mangledPass[0] = mangledPass[0].upper()
    permutations.append(''.join(mangledPass))

    # Upper last character
    mangledPass = list(testPW)
    mangledPass[len(testPW)-1] = mangledPass[len(testPW)-1].upper()
    permutations.append(''.join(mangledPass))
    return permutations

def mangle_capAll(testPW):
    # Convert testPW into a mutable list so I can upper case each letter individually, then convert it back to a string
    # and add it to our list of permutations.
    # # Password, pAssword, paSsword, PasSword, passWord, ...
    global mangledPWs
    permutations = []
    testPW = list(testPW)

    # Upper each character individually
    for i in range(len(testPW)):
        testPW[i] = testPW[i].upper()
        mangledPass = ''.join(testPW)
        permutations.append(mangledPass)
        testPW[i] = testPW[i].lower()

    # Add a full ALLCAPS version
    testPW = ''.join(testPW)
    permutations.append(testPW.upper())
    return permutations

def mangle_cap_dupe(testPW):
    # Convert testPW into a mutable list so I can upper case only the first letter, then convert it back to a string.
    # Then I repeat that final capped word. This function is only called on words <= 5 characters in length.
    testPW = list(testPW)
    testPW[0] = testPW[0].upper()
    cappedPass = ''.join(testPW)
    return cappedPass + cappedPass

def mangle_cap_rev(testPW):
    # Convert testPW into a mutable list so I can upper case only the first letter, then convert it back to a string.
    # Then I reverse that final capped word.
    permutations = []
    testPW = list(testPW)

    # Upper first letter
    testPW[0] = testPW[0].upper()
    cappedPass = ''.join(testPW)
    # Reverse it
    permutations.append(cappedPass [::-1])

    #Upper last letter
    testPW[len(testPW) - 1] = testPW[len(testPW) - 1].upper()
    cappedPass = ''.join(testPW)
    # Reverse it
    permutations.append(cappedPass [::-1])
    return permutations

def mangle_duplicate(testPW):
    # Returns a repeated word, such as 'passwordpassword', and a reverse repeat, like 'passworddrowssap'
    permutations = []
    # passwordpassword
    permutations.append(testPW + testPW)
    # passworddrowssap
    permutations.append(testPW + testPW[::-1])
    return permutations

def mangle_lowerAll(testPW):
    # Returns word in all lowercase
    return testPW.lower()

def mangle_numbers(testPW):
    # Adds 1- and 2-digit number combinations to front and end of each test word
    # 0password, password1, 23password, password45, et
    permutations = []
    # Build an ascii string of numbers
    nums = string.digits
    # Iterate thru all single numbers and prepend/append them
    for num in nums:
        permutations.append(testPW + num)
        permutations.append(num + testPW)
    # Iterate thru nums and build 2-digit combinations and append/prepend them
    for i in range(len(nums)):
        for j in range(len(nums)):
            permutations.append(testPW + nums[i] + nums[j])
            permutations.append(nums[i] + nums[j] + testPW)
    return permutations

def mangle_puralize(testPW):
    # Add 's' to word to make it plural
    return testPW + 's'

def mangle_reverse(testPW):
    # Return the word reversed.
    return testPW [::-1]

def mangle_split(testPW):
    # Splits word in two and returns both halves as permutations
    permutations = []
    # Calculate split point
    splitPoint = int(len(testPW) / 2)
    # Return first half
    permutations.append(testPW[0:splitPoint])
    # Return second half
    permutations.append(testPW[splitPoint:len(testPW)])
    return permutations

def mangle_tense(testPW):
    # Treat the word like a verb and modify the various tenses: walks, walked, walking
    permutations = []
    # Add an 'es' to words that end in certain character combinations
    if testPW[len(testPW)-1] == 'o' or testPW[len(testPW)-1] == 'x' or testPW[len(testPW)-1] == 'z' or (testPW[len(testPW)-2] + testPW[len(testPW)-1]) == 'sh' or (testPW[len(testPW)-2] + testPW[len(testPW)-1]) == 'ch' or (testPW[len(testPW)-2] + testPW[len(testPW)-1]) == 'ss' or (testPW[len(testPW)-3] + testPW[len(testPW)-2] + testPW[len(testPW)-1]) == 'tch':
        permutations.append(testPW + 'es')
    # Pluralize words ending in 'y' with 'ies'
    elif testPW[len(testPW)-1] == 'y':
        mangledPW = list(testPW)
        del mangledPW[-1]
        mangledPW = ''.join(mangledPW)
        permutations.append(mangledPW + 'ies')
    elif testPW[len(testPW)-1] != 's':
        permutations.append(testPW + 's')

    # Words ending in 'e' need to have the 'e' removed before adding 'ed' and 'ing'
    #   e.g. 'pace' would need to be 'pacing' and 'paced', not 'paceing' and 'paceed'
    if testPW[len(testPW)-1] == 'e':
        mangledPW = list(testPW)
        del mangledPW[-1]
        mangledPW = ''.join(mangledPW)
        permutations.append(mangledPW + 'ed')
        permutations.append(mangledPW + 'ing')
    elif testPW[len(testPW)-1] == 'y':
        permutations.append(mangledPW + 'ing')
        mangledPW = list(testPW)
        del mangledPW[-1]
        mangledPW = ''.join(mangledPW)
        permutations.append(mangledPW + 'ied')

    else:
        permutations.append(testPW + 'ed')
        permutations.append(testPW + 'ing')
    return permutations

def mangle_trunc_append(testPW):
    # Truncate word to 4 characters, capitalize it, append 2- and 4-digit
    # combinations followed by an !
    permutations = []
    fourCharPass = testPW[0].upper() + testPW[1] + testPW[2] + testPW[3]
    nums = string.digits
    for i in range(len(nums)):
        for j in range(len(nums)):
            # Prepend/append 2-digits
            permutations.append(fourCharPass + nums[i] + nums[j])
            permutations.append(fourCharPass + nums[i] + nums[j] + '!')
            for k in range(len(nums)):
                for l in range(len(nums)):
                    # Prepend/append 4-digits
                    permutations.append(fourCharPass + nums[i] + nums[j] + nums[k] + nums[l])
                    permutations.append(fourCharPass + nums[i] + nums[j] + nums[k] + nums[l] + '!')
    return permutations

def mangle_years(testPW):
    # Create a temporary list of both two- and four-digit years from 1970 through 2021 [1970-2021, 70-21]
    # and then prepend/append them to the word from the wordlist and return all possible permutations.

    # Build all year values
    years = []
    for y in range(1970, 2021):
        years.append(str(y))
    for y in range(70,100):
        years.append(str(y))
    for y in range(0,21):
        if y < 10:
            y = '0' + str(y)
            years.append(y)
        else:
            years.append(str(y))
    permutations = []
    # Prepend / append 2- and 4-digit years
    for y in years:
        permutations.append(y + testPW)
        permutations.append(testPW + y)

    return permutations

def clearTerminal():
    # Quick little function to clear the terminal window to keep the output clean.
    # Borrowed this function from the internet.
    # for windows
    if name == 'nt':
        _ = system('cls')
    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

def hashAndCompareWord(testPW):
    # MD5 hashes the input sent and compares it to the original hashed password
    # Returns True or False where True means the hashed dictionary word matches the
    # hash I'm attemtpting to crack

    global pw
    m = hashlib.md5()
    m.update(testPW.encode('utf_8'))
    hashedPass = m.hexdigest()
    # Return True if original pw matches the hashed test pass, else return False
    return (pw == hashedPass)

def calculateExecutionTime(startTime, endTime, testedCombinations):
    # Calculates program execution time and formats it for display

    # Password tests per second
    if(endTime - startTime <= 0):
        speedRatio = testedCombinations
    else:
        speedRatio = testedCombinations / (endTime - startTime)
    print(f"This exercise tested {bcolors.YELLOW}{testedCombinations:,d} {bcolors.NORMAL}combinations at a rate of {bcolors.YELLOW}{floor(speedRatio):,d} {bcolors.NORMAL}passwords per second.{bcolors.NORMAL}")

    # Total execution time
    duration = endTime - startTime
    if duration <= 0:
        days = 0
        hours = 0
        mins = 0
        secs = 0
    else:
        days = floor(duration / 86400)
        hours = floor((duration % 86400) / 3600)
        mins = floor(((duration % 86400) % 3600) / 60)
        secs = ((duration % 86400) % 3600) % 60
    print(
        f"Total time: {bcolors.YELLOW}{days} days {hours} hours {mins} mins {secs} secs\n\n{bcolors.NORMAL}")

def printResults(startTime, endTime, testedCombinations, testPW):
    # Formats and displays final results upon a successful crack attempt
    clearTerminal()
    print(f'{bcolors.BOLD}{bcolors.SUCCESS}\nF O U N D  I T !\n- - - - - - - - ')
    print(f"{bcolors.BOLD}{bcolors.SUCCESS}      {testPW}\n\n{bcolors.NORMAL}")
    beepSucces()
    calculateExecutionTime(startTime, endTime, testedCombinations)

def printFailedResults(testedCombinations):
    # Formats and displays final results upon a failed crack attempt
    print(f"{bcolors.FAILED}Failed.\n{bcolors.NORMAL}After {bcolors.YELLOW}{testedCombinations:,d}{bcolors.NORMAL} attempts, I was still unable to find a match. \n <Sad Panda>\n\n")
    beepFail()
    sys.exit()

    if len(libraryList) > 0:
        finalLibraryString = ''
        for i in libraryList:
            finalLibraryString = finalLibraryString + i
        print(
            f"The test/ library sequence used for this round was: \n{bcolors.YELLOW}{finalLibraryString}\n\n{bcolors.NORMAL}")
    calculateExecutionTime(startTime, endTime, testedCombinations)

def userPause(message='Hit enter to continue...'):
    # Simple functions acts as a breakpoint on screen.
    input(message)

def beepSucces():
    # Plays an ascending alert tone sequence upon successfully cracking a password
    for i in range(1, 5):
        winsound.Beep(666 * i, 50)

def beepFail():
    # Plays a descending alert tone sequence upon unsuccessfull crack attempt
    winsound.Beep(750, 40)
    winsound.Beep(500, 40)
    winsound.Beep(300, 40)
    winsound.Beep(100, 40)

if __name__ == "__main__":
    # Initializes some variables, parses user commnad line input, and executes
    # main() function

    # initialize some variables
    charCounts          = []
    libraryList         = []
    md5library          = buildMD5Library()
    md5String           = buildMD5tring()

    # Read user commnd line vars
    parser      = argparse.ArgumentParser(prog='ettubrute', description='''
        Crack an MD5-hashed password.
        Defaults to a brute force method unless you supply a wordlist,
        then it will default to a dictionary attack.
        There are a few mangler rules set up by adding the -m=\'\' flag.\n
        Ex.: -m=\'c\' iterates through the dictionary and capitalizes the first letter.''')
    parser.add_argument('pw',                   type=str, help='md5 hash string -OR- /path/to/md5hash_file')
    parser.add_argument('-d', '-dictionary',    type=str, help='[Optional] /path/to/wordlist_file for dictionary-based crack',  default=None)
    parser.add_argument('-m', '-mangler',       type=str, help='[Optional] enables wordlist mangling rules.',  default=':')
    crackParams = parser.parse_args()

    # Clean up the terminal windows
    clearTerminal()

    # Execute the main program
    main(crackParams)

    # Keep the window from closing instantly
    userPause('Thanks for playing!\n\nHit enter to exit...')

    # Fini.