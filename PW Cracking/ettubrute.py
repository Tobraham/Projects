# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                                             #
#   Et Tu, Brute ?                                                            #
#   by Toby Sheets                                                            #
#   CU Boulder                                                                #
#   TCP - Digital Forensics                                                   #
#                                                                             #
# Takes an MD% hashed password of up to maxPassLength characters and          #
# brute forces the value from a string library of ascii characters.           #
#                                                                             #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


# CHANGE THIS VALUE TO INCREASE 
# OR DECREASE THE SCRIPT'S 
# ALLOWABLE PASSWORD LENGTH
# ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇
maxPassLength = 6


#import getpass                      # For accepting hidden user input
import hashlib                      # For calculating md5 hashes of passwords
import itertools                    # For looping through password values
import random                       # For randomizing our test library
import string                       # For accessing string ascii values, digits and punctuation
import sys                          # For exiting the app on completion.
import time                         # For calculating program execution time
from   math import floor            # "     "           "       "       "
from   os   import system, name     # For determing which OS user is using to execute certain commands
import winsound                     # For notifing user when pass has been cracked


charCounts  = []
library     = []

class bcolors:
    # Simple class for formatting terminal output. This code is borrowed from the internet.
    BLUE        = '\033[94m'
    PASS_RESULT = '\033[92m'
    YELLOW      = '\033[93m'
    NORMAL      = '\033[0m'
    BOLD        = '\033[1m'

def main():
    # Initialize some variables
    global library
    passFound = False
    testedCombos = 0
    startTime = int(time.time())

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
    library = buildLibrary()

    # Request user's hashed password
    pw      = getPass()

    # I found that by shuffling the master comparison string I can sometimes increase 
    # the speed at which a match is found. For example if my library string is always 
    # (abc...ABC...123...~!@) and the user's password ends in a punctuation character, 
    # then we are guaranteed that execution will have to loop until we reach the 
    # punctuation portion of the master string. However, if I shuffle the master string 
    # (~2c1@a3AB~!bC), there's a chance that we could hit that last character of the 
    # password sooner and shave off potentially millions of iterations. Of course, 
    # sometimes it increases the execution time, but that's the chance you have to take.  :)
    random.shuffle(library)

    # Loop until we have found a matching password
    processingCount = 0
    while passFound == False:
        testPW  = buildTestPW()
        m = hashlib.md5()
        m.update(testPW.encode('utf_8'))
        hashedPass = m.hexdigest()
        # If the test pass matches the user's pass, we'll print the 
        # results and exit the application
        if hashedPass == pw:
            passFound = True
            printResults(startTime, testedCombos, testPW)
        else:
            # Update the character counters and try again on the next loop iteration.
            charCounts[0] = incrementCount(0)
            testedCombos += 1
            
            # Dispay spinners while cracking pw so user knows we're still alive
            if testedCombos%25000 == 0:
                processingCount += 1
                if processingCount == 4:
                    processingCount = 0
                clear()
                if processingCount == 0:
                    print("└ └ └ └ └ └ └")
                elif processingCount  == 1:
                    print("┘ ┘ ┘ ┘ ┘ ┘ ┘")
                elif processingCount == 2:
                    print("┐ ┐ ┐ ┐ ┐ ┐ ┐")
                else:
                    print("┌ ┌ ┌ ┌ ┌ ┌ ┌")    
                

def buildTestPW():
    # Concatenates a test password based on the count values in each character space
    testPW = ''
    for j in charCounts:
        if j >= 0:
            testPW += library[j]
    return  testPW

def calculateExecutionTime(startTime, endTime, testedCombos):
    # Display password tests per second
    if(endTime - startTime <= 0):
        speedRatio = testedCombos
    else:
        speedRatio = testedCombos / (endTime - startTime)
    print(f"This experiment tested {bcolors.YELLOW}{testedCombos:,d} {bcolors.NORMAL}combinations at a rate of {bcolors.YELLOW}{floor(speedRatio):,d} {bcolors.NORMAL}passwords per second.{bcolors.NORMAL}")

    # Display total execution time
    duration = endTime - startTime
    if duration <= 0:
        days   = 0
        hours  = 0
        mins   = 0
        secs   = 0
    else:
        days   = floor(duration / 86400)
        hours  = floor((duration % 86400) / 3600)
        mins   = floor(((duration % 86400) % 3600) / 60)
        secs   = ((duration % 86400) % 3600) % 60
    print(f"Total time: {bcolors.YELLOW}{days} days {hours} hours {mins} mins {secs} secs\n\n{bcolors.NORMAL}")

def getPass():
    # Collect and validate user password input. Ensures password length is 
    # between 1 and maxPassLength characters in length and that all characters fall within 
    # the allowed characters as defined in the 'library' string.

    clear()
    passlength = 0
    validates = False
    pw = ''
    md5library = []

    for x in string.ascii_lowercase:
        md5library.append(x)
    for x in string.digits:
        md5library.append(x)
    md5String = ''
    for i in md5library:
        md5String += i
    
    # Loop until password is the correct length
    while ((passlength != 32) or validates == False):
        if passlength != 32:
            print(f"Hashed pass must be 32 alphanumeric characters in length")
        if validates == False:
            print (f"Pass can only contain these characters: {md5String}")
        pw = input("What is the hashed password?\n")
        passlength = len(pw)

        # Validate all characters in the password to ensure they are allowed.
        if passlength > 0:
            illegalCharacters = False
            for i in pw.lower():
                if (i in md5library) == False:
                    illegalCharacters = True
                    clear()
                    print(f"There seems to be an illegal character ({i}). Please try again.")
                    break
            if illegalCharacters == False:
                validates = True
        else:
            clear()
    return pw.lower()

def clear():
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
    max = len(library)
    currentValue = charCounts[digit]

    # Check to see if we're on the last character in the test library string. If so,
    # then we've exhausted all possible combinations and still have no solution. At 
    # that point we need to exit and go sulk in the corner for about 20 minutes. Otherwise
    # we need to set the counter back to 0 for this digit and increment the next 
    # digit by 1 and keep working. 
    if (currentValue + 1 == 0):
        newValue = currentValue + 1
    elif  (currentValue + 1) % max != 0:    
        newValue = currentValue + 1
    else: 
        if (digit == maxPassLength-1):
            print("I've tried everything with no luck. <Sad panda>")
            userPause('Press any key to exit.')
            sys.exit()
        nextCharacter = digit + 1    
        charCounts[nextCharacter] = incrementCount(nextCharacter)
    return newValue

def buildLibrary():
    # Concatenates a string of all available ascii characters to use for
    # sequential testing against the user's password. 

    global library, libraryString
    for x in string.ascii_lowercase:
        library.append(x)
    for x in string.ascii_uppercase:
        library.append(x)
    for x in string.digits:
        library.append(x)
    for x in string.punctuation:
        library.append(x)


    # Build a formatted display version of the library list as a string
    libraryString = ''
    for i in library:
        libraryString = libraryString + i
    
    # Return the library list
    return library

def printResults(startTime, testedCombos, testPW):
    clear()
    winsound.Beep(666, 666)

    print(f'{bcolors.BOLD}{bcolors.PASS_RESULT}\nF O U N D  I T !\n- - - - - - - - ')
    print(f"{bcolors.BOLD}{bcolors.PASS_RESULT}      {testPW}\n\n{bcolors.NORMAL}")
    finalLibraryString = ''
    for i in library:
        finalLibraryString  = finalLibraryString + i
    print(f"The test library sequence used for this round was: \n   {bcolors.YELLOW}{finalLibraryString}\n\n{bcolors.NORMAL}")
    endTime = int(time.time())
    calculateExecutionTime(startTime, endTime, testedCombos)
def userPause(message='Hit any key to continue...'):
    # Simple functions acts as a breakpoint on screen.
    input(message)

if __name__ == "__main__":
    # Clean up the terminal windows
    clear()

    # Execute the main program
    main()

    # Keep the window from closing instantly
    userPause()
