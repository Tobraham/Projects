# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
#                                                                                           #
#   Et Tu, Brute ?                                                                          #
#   by Toby Sheets                                                                          #
#   CU Boulder                                                                              #
#   TCP - Digital Forensics                                                                 #
#                                                                                           #
#   Crack an MD5-hashed password. Defaults to a brute force method unless                   #   
#   you supply a wordlist, then it will default to a dictionary attack.                     #
#                                                                                           #
#   usage: >>>py ettubrute [-h] [-d D] pw                                                   #
#                                                                                           #
#     positional arguments:                                                                 #
#       pw = an md5 hash string -OR- /path/to/md5hash_file                                  #
#                                                                                           #
#     optional arguments:                                                                   #
#       -h, --help           show this help message and exit                                #
#       -d D, -dictionary D  [Optional] /path/to/wordlist_file for dictionary-based crack   #
#                                                                                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                                                                                           #
#   Usage Examples:                                                                                                                         #
#   1 - Brute force MD5 hash sent directly from command line:                                                                               #
#        ettubrute 3c086f596b4aee58e1d71b3626fefc87                                                                                         #                               
#                                                                                                                                           #
#  2 - Dictionary crack an MD5 hash sent directly via command line:                                                                         #
#        ettubrute 3c086f596b4aee58e1d71b3626fefc87 -d 'C:\Users\General\Documents\my_wordlist_file.txt'                                    #                                                                                     
#                                                                                                                                           #
#   3 - Brute force MD5 hash from a text file directly from command line:                                                                   #
#        ettubrute 'C:\Users\General\Documents\my_hash_file.txt'                                                                            #                                             
#                                                                                                                                           #
#   4 - Dictionary crack an MD5 hash contained in a text file                                                                               #
#        ettubrute 'C:\Users\General\Documents\my_hash_file.txt' -d 'H:\Documents\CU\Digital Forensics\Projects\PW Cracking\dictionary.txt' #   
#                                                                                                                                           #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# CHANGE THIS VALUE TO INCREASE OR DECREASE THE SCRIPT'S ALLOWABLE PASSWORD LENGTH
# ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇
maxPassLength = 6


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
        # This is a brute force  crack.
        crackedPass = crack_BruteForce(crackParams)
        endTime     = int(time.time())
        if crackedPass == False:
            printFailedResults(testedCombinations)
        else:     
            printResults(startTime, endTime, testedCombinations, testPW)
    else:
        # User supplied a dictionary, so this is a dictionary crack.
        startTime   = int(time.time())
        crackedPass = crack_Dictionary(crackParams)
        endTime     = int(time.time())
        if crackedPass == False:
            printFailedResults(testedCombinations)
        else:     
            printResults(startTime, endTime, testedCombinations, testPW)

def getPassFromCommandLineArgs(pw):
    # Tests user input. If pw length = 32, then this should be an MD5 hash. Otherwise
    # we expect it to be a file path. If it's a hash, we'll verify that all the characters 
    # are consistent with an MD5 hash (i.e. no unusual characters). If it's not a hash, we'll
    # test to see if it's a valid file path. If it's a file, we'll grab the hash from the file contents.
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
    # Simple test to ensure your 32-digit entry matches a standard MD5 format before we crack it.
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

def crack_BruteForce(crackParams):
    global libraryList, pw, startTime, testedCombinations, testPW
    pw                  = getPassFromCommandLineArgs(crackParams.pw)

    # charCounts will track the characters to be tested in each character
    # position of the temporary password. Since we can have up to maxPassLength characters,
    # we build a maxPassLength-item list and initialize the first to 0 and the rest to -1.
    # These values correspond to a character in our master library comparison
    # string (abcdABCD1234><:... etc).
    for i in range(maxPassLength):
        if i == 0:
            charCounts.append(0)
        else:
            charCounts.append(-1)

    # Create our master library string (abcdABCD1234><:... etc).
    libraryList = buildLibraryString()
    

    # I found that by shuffling the master comparison string I can sometimes increase
    # the speed at which a match is found. For example if my library string is always
    # (abc...ABC...123...~!@) and the user's password ends in a punctuation character,
    # then we are guaranteed that execution will have to loop until we reach the
    # punctuation portion of the master string. However, if I shuffle the master string
    # (e.g., ~2c1@a3AB~!bC), there's a chance that we could hit that last character of the
    # password sooner and shave off potentially millions of iterations. Of course,
    # sometimes it increases the execution time, but that's the chance you have to take.  :)
    # I have a 50/50 chance of speeding up the crack vs slowing it down. Those seem to be
    # fair odds. To test this, run the same crack a few times and observe the differences.
    # A 3-character pass can take up to 94^3 iterations to brute force without shuffling the 
    # character list. Via shuffling, cracking it can be brought down to as low as 
    # (94^2)+1 iterations.

    random.shuffle(libraryList)
    
    # Just in case, I'm setting a max iteration time of the length of our character 
    # library to the power of [maxPassLength] digits in our password.
    maxIterations = len(libraryList)**maxPassLength

    clearTerminal()

    startTime   = int(time.time())

    # Loop until we have found a matching password
    while testedCombinations <= maxIterations: # Set a cap on execution time in case we bugged some logic
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

def crack_Dictionary(crackParams):
    # Returns the cracked password if successful, otherwise returns False
    global pw, testedCombinations, testPW
    pw = getPassFromCommandLineArgs(crackParams.pw)
    clearTerminal()

    # Open wordlist file and iterate through all entries
    with open(crackParams.d, "r") as wordList:
        for testPW in wordList.readlines():
            testedCombinations += 1
            
            if hashAndCompareWord(testPW):
                wordList.close()
                return testPW
        
        # We've exhausted our wordlist and still haven't found a matching hash
        wordList.close()
        return False
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

def clearTerminal():
    # Quick little function to clear the terminal window to keep the output clean.
    # Borrowed this function from the internet.
    # for windows
    if name == 'nt':
        _ = system('cls')
    # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

def incrementCount(digit):
    # This function keeps track of what characters we've tested. We start with a
    # list of maxPassLength characters (the max allowable password length) and each value
    # starts at -1, # except for the first character, which starts at 0. As each
    # new password is tested, this function is called to increment the value of
    # the character tested. Once the character count reaches the end of all possible
    # characters, it is set back to 0 and the next character is # incremented from
    # -1 to 0 and we'll start the process over again. This is a nested function, so
    # if the current character count exceeds the max, it calls itself to increment
    # the next character in the sequence.

    newValue = 0
    max = len(libraryList)
    currentValue = charCounts[digit]

    # Check to see if we're on the last character in the test library string. If so,
    # then we've exhausted all possible combinations and still have no solution. At
    # that point we need to exit and go sulk in the corner for about 20 minutes. Otherwise
    # we need to set the counter back to 0 for this digit and increment the next
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

def hashAndCompareWord(testPW):
    # MD5 hashes the input sent and compares it to the original hashed password
    # Returns True or False where True means the hashed dictionary word matches the 
    # hash we're attemtpting to crack

    global pw
    m = hashlib.md5()
    m.update(testPW.strip().encode('utf_8'))
    hashedPass = m.hexdigest()
    
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
    print(f"{bcolors.FAILED}Failed.\n{bcolors.NORMAL}After {bcolors.YELLOW}{testedCombinations}{bcolors.NORMAL} attempts, I was still unable to find a match. \n <Sad Panda>")
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
        then it will default to a dictionary attack.''')
    parser.add_argument('pw',                   type=str, help='md5 hash string -OR- /path/to/md5hash_file')
    parser.add_argument('-d', '-dictionary',    type=str, help='[Optional] /path/to/wordlist_file for dictionary-based crack',  default=None)
    parser.add_argument('-m', '-mangler',       type=str, help='[Optional] enables internal wordlist mangling rules',           default=None)
    crackParams = parser.parse_args()

    # Clean up the terminal windows
    clearTerminal()

    # Execute the main program
    main(crackParams)

    # Keep the window from closing instantly
    userPause('Thanks for playing!\n\nHit enter to exit...')

    # Fini.

    """ def getPass(pw):
    # Collect and validate user password input. Ensures password length is
    # between 1 and maxPassLength characters in length and that all characters fall within
    # the allowed characters as defined in the 'library' string.

    clearTerminal()
    passlength = len(pw)
    print(f"Pass length is {passlength} {pw}")
    validates = None

    # Loop until password is the correct length
    while ((passlength != 32) or validates == False):
        if passlength != 32:
            print(f"Hashed pass must be 32 alphanumeric characters in length. Try again.")
        if validates == False:
            print(f"An md5 hash can only contain these characters: {md5String}")
        pw = input("What is the hashed password?\n")
        passlength = len(pw)

        # Validate all characters in the password to ensure they are allowed.
        if passlength > 0:
            illegalCharacters = False
            for i in pw.lower():
                if (i in md5library) == False:
                    illegalCharacters = True
                    clearTerminal()
                    print(f"There seems to be an illegal character ({i}). Please try again.")
                    print(md5library)

                    break
            if illegalCharacters == False:
                validates = True
        else:
            clearTerminal()
    return pw.lower() """