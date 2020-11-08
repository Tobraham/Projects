# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
#   Steganography Project
#   - - - - - - - - - - -
#       Toby Sheets
#       CU Boulder - TCP
#       Digital Forensics - Fall 2020
#
#       This project uses LSB steganography on JPG images.
#
#       INSTRUCTIONS
#           • Just launch the script and it walks you through the process.
#           • Script must be launched INSIDE the directory containing the
#               images to be used. When it asks for the image to use, do not
#               use the full path. It assumes the path is the current directory
#               and will look for- and store files in the current active
#               directory.
#
#       PROJECT REQUIREMENTS:
#     ✔   1) Display program use details or a help interface that allows users
#           to select either an embed or extract method.
#     ✔   2) The method will determine how your program will run. If the method
#           is'embed', your code and algorithm will embed the provided message
#           file into the carrier file. If the method is 'extract', your code
#           and algorithm will extract the hidden message from the carrier file
#           and write it to the screen.
#     ✔  3) When embedding, your solution must output the modified carrier to a
#           filename that is a derivative of the original carrier file.
#     ✔  4) Must output to screen, basic file information such as original
#           and modified file name and size.
#     ✔  5) Must provide a MD5 hash of the original and embedded carrier file.
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

import binascii             # for converting image data to and from binary
import codecs               # for string byte functions
import hashlib              # for calculating MD5 hashes
import imghdr               # tests for file type
from sys import exit        # for exiting the program

class ImageFile:
    # ImageFile class contains all of the various file signature constants
    # and the functions used to manipulate the images and their byte values

    START_OF_SCAN       = {'JPG' : b'\xff\xda'}
    END_OF_FILE         = { 'JPG' : b'\xff\xd9'}
    JPG_OFFSET = 32

    # Proprietary end-of-message signature '§§' to embed or look for
    # depending on the task chosen
    EOM_SIG_BINARY      = '1010011110100111'

    # Initialize image class values
    def __init__(self, filename):
        self.filename               = filename
        self.rawImageData           = self.openImageFile()
        self.md5                    = self.getMD5()
        self.fileSize               = self.getFileSize()
        self.imageType              = self.getImageType()
        self.imageStartByte         = self.getImageStartByte()
        self.imageEndByte           = self.getImageEndByte()
        self.imageHeader            = self.getImageHeaders()
        self.imageOriginalContent   = self.getOriginalImageContent()
        self.imageFooter            = self.getImageFooter()

    # - - - - - - - - - - - - - - - - - -
    # Initialize image class functions:
    # - - - - - - - - - - - - - - - - - -

    def openImageFile(self):
        # Open the file and read it as a byte string
        try:
            f = open(self.filename, 'rb')
        except:
            print('Could not open file.')
            exit()
            return False
        return f.read()

    def getMD5(self):
        # Returns MD5 hash value of the raw file
        return hashlib.md5(self.rawImageData).hexdigest()

    def getFileSize(self):
        # Returns the file size of the image
        return len(self.rawImageData)

    def getImageType(self):
        # Checks the file image type using the imghdr module
        if(imghdr.what(self.filename) == 'jpeg'):
            return 'jpg'
        else:
            print('That is not a valid image file for this project.\nPlease choose a valid JPG.')
            exit()

    def getImageStartByte(self):
        # Determine exactly where the image data begins in the file by finding
        # the image start header.

        if self.imageType == 'jpg':
            # JPG images begin after the Scan section, which is of a dynamic
            # length. The length of the scan section is displayed in the 2
            # bytes following the Start of Scan marker
            sosByte         = self.rawImageData.find(ImageFile.START_OF_SCAN['JPG'])
            scanMarkerSize  = int.from_bytes(self.rawImageData[int(sosByte + 2):int(sosByte + 4)], 'big')
            eosByte         = sosByte + 2 + scanMarkerSize
            # print(f"SOS: {sosByte} \tScan Marker Size: {scanMarkerSize} \tEOS {eosByte}")
            return eosByte

    def getImageEndByte(self):
        # Determine exactly where the image data ends in the file based on
        # byte location of the End of File signature.

        if self.imageType == 'jpg':
            endByte = self.rawImageData.find(ImageFile.END_OF_FILE['JPG'])
            return endByte

    def getImageHeaders(self):
        # Copy all data prior to the actual image content into a header for
        # reassembling the image later.

        header = self.rawImageData[0:self.imageStartByte]
        return header

    def getOriginalImageContent(self):
        # Carve out all of the actual image data for hiding/extracting data
        # and reassembling later.

        imageOriginalContent = self.rawImageData[self.imageStartByte : self.imageEndByte]
        return imageOriginalContent

    def getImageFooter(self):
        # Extract footer information for reassembling the image after processing
        if self.imageType == 'jpg':
            return ImageFile.END_OF_FILE['JPG']

    # - - - - - - - - - - - - - - - - - -
    # Embed secret message functions
    # - - - - - - - - - - - - - - - - - -

    def requestSecretMessage(self):
        # Ask for user input to be hidden inside the image
        message = ''
        while message == '':
            message = input("Type the message you wish to hide in the image ( do not use quotes ):\n")
            # Quick check to ensure our image is large enough to handle the message
            if (len(message) * 8 > len(self.imageOriginalContent) / 64):
                print("Message is too long for this image. Try a shorter message or a larger image file.")
                message = ''
        self.secretMessage = codecs.encode(message)
        return

    def convertMessageToBinary(self):
        # Convert secret message alphanumeric content to binary:
        # We iterate through each letter of the message and retrieve its
        # binary value by formatting it into an 8-bit, padded binary chunk.
        # Once we have the 8-bit value of each letter, we store each bit into
        # one long list that we will iterate through later in the embedding
        # function.
        secretMsg_BinaryList = []
        for letter in self.secretMessage:
            # Each letter is turned into a padded 8-bit binary value
            temp = str("{0:08b}".format(letter))
            for digit in temp:
                # The 8 bits are appended to a sequenced list to be iterated
                # through later.
                secretMsg_BinaryList.append(digit)
        for digit in self.EOM_SIG_BINARY:
            # Then we append our proprietary end-of-message (EOM) signature to the
            # list. The EOM will be used when extracting the message to signal to
            # our algorithm that we have reached the end of the secret message
            # and can stop processing.
            secretMsg_BinaryList.append(digit)
        return secretMsg_BinaryList

    def embedSecretMessage(self):
        # First we'll convert secret message into a binary string. Then
        # we'll convert the image byte content into a byte array so that we
        # can manipulate the values. We'll interate through that image
        # content byte array, skipping every 64 bytes so as not to alter any
        # one 8x8 jpg grid too much. We'll change the LSB to the next binary value
        # of our secret message and move on to the next one. Repeat until the
        # entire secret message has been embedded.
        # To ensure we don't damage the JPG decoding process, we CANNOT change
        # the LSB of any byte that begins with \xDx as it could be a rescan
        # marker. We also cannot alter any byte that is \xFF, because that is
        # an important JPG marker. Finally, we must leave alone any \xFE byte
        # values because if were to increment the LSB by one, it would become
        # an important JPG \xFF marker.

        # Convert all letters of message into binary string.
        secretMsg_BinaryList = self.convertMessageToBinary()
        msgBinaryLength = len(secretMsg_BinaryList)

        #Convert image content into a byte array for manipulation
        imageContentByteArray = bytearray(self.imageOriginalContent)

        # for tracking where we are in the secret message
        secretMsgCharacterPosition  = 0

        # Iterate through original image content and replace values.
        # We will skip every 64 bytes to avoid doing too much damage
        # to a single 8x8 pixel block of image data.


        for originalImageBytePosition in range (0, len(self.imageOriginalContent), self.JPG_OFFSET):
            # Keep iterating until we've embedded the entire secret message
            if(secretMsgCharacterPosition >= msgBinaryLength):
                break

            # Grab next byte value from image content, convert to binary
            imageByteValue = int(self.imageOriginalContent[originalImageBytePosition])
            imgOriginalBinaryValue = str('{0:08b}'.format(imageByteValue))

            # Check the current byte value and skip any \xDx, \xFE and \xFF
            if imgOriginalBinaryValue[0:4] == '1101':
                continue

            if imgOriginalBinaryValue[0:8] == '11111111' or imgOriginalBinaryValue[0:8] == '11111110':
                continue

            if imgOriginalBinaryValue[0:8] == '00000000':
                continue

            # Grab next bit from binary secret message
            newlsb = secretMsg_BinaryList[secretMsgCharacterPosition]

            # update the image's byte value by replacing LSB with the `newlsb` value from secret message
            imgNewBinaryValue = imgOriginalBinaryValue[0:7] + newlsb

            # Replace original image byte value with new byte value
            self.replaceImageByte(originalImageBytePosition, imgNewBinaryValue, imageContentByteArray)

            # update the pointer to proceed to the next binary value of the secret message
            secretMsgCharacterPosition +=1

        # Set self.newImageContent
        self.newImageContent = bytes(imageContentByteArray)

        # Put the image back together
        self.assembleNewImage()
        return

    def replaceImageByte(self, characterPosition, imgNewBinaryValue, imageContentByteArray):
        # Convert new binary value back to a decimal value
        newByteValue = int(imgNewBinaryValue, 2)
        imageContentByteArray[characterPosition] = newByteValue
        return

    def assembleNewImage(self):
        # Put the pieces of the image back together:
        # Header + Content + Footer
        newImageData        = self.imageHeader + self.newImageContent + self.imageFooter

        # Open new file with original filename prepended with 'steg_'
        newFilename         = 'steg_' + self.filename
        f = open(newFilename, 'wb')

        # Write steg image content and close the file
        f.write(newImageData)
        f.close()

        # Store the new steg image values in our image class
        self.stegFilename   = newFilename
        self.stegFileSize   = len(newImageData)
        self.stegMd5        = hashlib.md5(newImageData).hexdigest()

        return

    # - - - - - - - - - - - - - - - - - -
    # Exract secret message functions
    # - - - - - - - - - - - - - - - - - -

    def extractSecretMessage(self):
        # Open steg image, iterate through the image content as we did prior
        # with a cover image, skipping every 64 bytes and skipping any
        # bytes matching \xDx, \xFE, or \xFF. Grab the LSB and reassemble that
        # into our secret message string.

        secretMessageBinary = ''
        for originalImageBytePosition in range (0, len(self.imageOriginalContent), self.JPG_OFFSET):
            # Keep iterating until we've completed the entire secret message.
            # We will continue appending binary SLB values until the last 16
            # characters of our match the self.EOM_SIG_BINARY signature,
            # indicating we've reached the end of our message.

            # Stop if we have reached our proprietary End of Message (EOM) signature
            if len(secretMessageBinary) > 16 and secretMessageBinary[len(secretMessageBinary) - 16 :] == self.EOM_SIG_BINARY:
                break

            # Grab the image byte value in current originalImageBytePosition and
            # convert it to a binary string
            imageByteValue = int(self.imageOriginalContent[originalImageBytePosition])
            imgOriginalBinaryValue = str('{0:08b}'.format(imageByteValue))

            # Skip byte values of \xDx, \xFE and \xFF
            if imgOriginalBinaryValue[0:4] == '1101':
                continue
            if imgOriginalBinaryValue[0:8] == '11111111' or imgOriginalBinaryValue[0:8] == '11111110':
                continue
            if imgOriginalBinaryValue[0:8] == '00000000':
                continue

            # Append the LSB of the current image byte to our secret message string
            secretMessageBinary += imgOriginalBinaryValue[-1]
        if(secretMessageBinary.find(self.EOM_SIG_BINARY)) == -1:
            print("""
            \n\n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
            This is image does not appear to have a
            secret message in it that was embedded
            using our algorithm.
            \n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
            \n\n""")
            exit()

        return secretMessageBinary

    def displaySecretMessage(self, secretMessageBinary):
        # Takes the secret message binary string and converts it back to text values
        decodedMessage = ''
        secretMessageOffset = 0

        # We know the last 16 bits are our proprietary end-of-message marker
        # so we don't need to include them in our final output. We'll iterate
        # through the secret message binary string until we reach the last 16
        # bits and stop. As we iterate, we grab the data in 8-character chunks
        # and convert those back to decimal values, then we use the Python
        # char() function to get the text value of that decimal number and
        # append it to our final converted secret message text.
        while secretMessageOffset < len(secretMessageBinary) -16:
            letterDecimalValue = int(secretMessageBinary[secretMessageOffset:secretMessageOffset+8], 2)
            decodedMessage += chr(letterDecimalValue)
            secretMessageOffset += 8
        return decodedMessage

    def showSelfImageInfo(self, stegImageType):
        # Prints details about the original image. In HIDE mode,
        # this would be the cover image. In EXTRACT mode this would
        # be the steg image.
        print(f"{stegImageType + 'Filename:' : <18} {self.filename}" )
        print(f"{stegImageType + ' File Size:' : <18} {self.fileSize}")
        print(f"{stegImageType + ' MD5 Hash:' : <18} {self.md5}")

    def showStegImageInfo(self):
        # In EXTRACT mode, this prints details about the final steg image.
        print(' - - - - -')
        print(f"{'Steg Filename:' : <18} {self.stegFilename}" )
        print(f"{'Steg File Size:' : <18} {self.stegFileSize}")
        print(f"{'Steg MD5 Hash:' : <18} {self.stegMd5}")

def main():
    action = getActionFromUser()
    if action == '1': # EMBED
        # Request cover image
        imageIncomingFilename = requestImageFromUser(action)

        # Create image class
        myCoverImage = ImageFile(imageIncomingFilename)

        # Request message to hide
        myCoverImage.requestSecretMessage()

        # Embed message
        myCoverImage.embedSecretMessage()

        # Diplay results
        print('\n\n⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇\n')
        myCoverImage.showSelfImageInfo('Cover')
        myCoverImage.showStegImageInfo()
        print('\n⬆ ⬆ ⬆ ⬆ ⬆ ⬆ ⬆ ⬆\n')


    elif action == '2': # EXTRACT
        # Request stego image
        imageIncomingFilename   = requestImageFromUser(action)

        # Create image class
        myStegImage             = ImageFile(imageIncomingFilename)
        myStegImage.showSelfImageInfo('Steg')

        # Extract message
        secretMessageBinary     = myStegImage.extractSecretMessage()
        secretMessageText       = myStegImage.displaySecretMessage(secretMessageBinary)

        # Diplay results
        print('\nS E C R E T  M E S S A G E \n---------------------------\n⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇ ⬇\n\n')
        print(secretMessageText)
        print('\n\n')
    input('Press enter to exit.')
    exit()

def getActionFromUser():
    # Ask the user if they are hiding or extracting a message
    print("\nThis script MUST executed from WITHIN directory containing your cover and steg images.")
    input("Press enter to continue...\n")
    while True:
        action = input("What would you like to do?\n1 = Embed (hide a message)\n2 = Extract (recover a message)\n")
        if action == '1' or action == '2':
            return action
    return

def requestImageFromUser(action):
    # Continue asking for an image until we get a valid JPEG file that
    # we can open. Return the filename upon success.

    while True:
        if action == '1':                 # hide a msg, ask for cover image
            filename = input('What is the JPG filename to be used as the cover image?\n(Do not include the entire /path/to/file.jpg)\n')
        elif action == '2':               # recover a msg, ask for steg image
            filename = input('What is the filename of the steg image?\n')

        # Test to see if file exists.
        try:
            f = open(filename, 'r')
            f.close()
        except:
            print('Could not open file. Maybe try another file?')
            continue

        # Test to ensure file type is JPEG
        imgtype = imghdr.what(filename)
        if(imgtype != 'jpeg'):
            print(f"Image must be a jpg, not {imghdr.what(filename)}. Please, try again")
            continue
        else:
            return filename

if __name__ == "__main__":
    main()