#!/usr/bin/python -tt
__description__ = 'Parse and process email header to highlight possible evidence of spoofing'

import os
import sys
import re
import urllib2
from bs4 import BeautifulSoup
import argparse
import logging
import time

#For log file
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',datefmt='%m-%d-%Y %H:%M',filename='Email-header-processing.log',filemode='w')

console = logging.StreamHandler(os.sys.stdout)
# console.setLevel(logging.ERROR)
console.setLevel(logging.INFO)

consoleDisplayFormat = logging.Formatter('%(levelname)s - %(lineno)s %(funcName)s - %(message)s')
console.setFormatter(consoleDisplayFormat)
logger = logging.getLogger()
logger.addHandler(console)



#NAME:whoisLookUp
#INPUT:
#OUTPUT: 
#DESCRIPTION:
def whoisLookUp(input):     
    url = "https://www.whois.com/whois/"+str(input)
    
    http_hdr = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
        'Accept-Encoding': 'none',
        'Accept-Language': 'en-US,en;q=0.8',
        'Connection': 'keep-alive'}

    req = urllib2.Request(url, headers=http_hdr)
    success = False
    while not success:
        try:
            webpage = urllib2.urlopen(req, timeout=3)
            success = True
        except:
            print "Retrying urllib2.urlopen..."
            pass

    success = False
    while not success:
        try:
            content = webpage.read()
            success = True
        except:
            print "Retrying webpage.read... ..."

    soup = BeautifulSoup(content,"html.parser")
    
    #extracting results and saving them    
    for link in soup.findAll("div", { "class" : "whois_result" }):                
        with open(str(input) + ".txt", "a") as filehandle:
            #domain formatting is truncated hence the need to replace with new line
            # logger.info("Saving whois lookup for "+ str(input))
            filehandle.write(str(link).replace("<br>","\n"))

    for link in soup.findAll("pre", { "id" : "registryData" }):                
        with open(str(input) + ".txt", "a") as filehandle:
            #domain formatting is truncated hence the need to replace with new line
            # logger.info("Saving whois lookup for "+ str(input))
            filehandle.write(str(link).replace("<br>","\n"))

    #sleep to prevent overwhelming whois server, least they block us
    time.sleep(3)

#NAME: emailHeaderAnalysis
#INPUT:
#OUTPUT: 
#DESCRIPTION:
def emailHeaderAnalysis(emailHeaderTextFile):

# If you are investigating email on Windows systems, you should be aware of the Microsoft Messaging
# Application Programming Interface (MAPI) properties that will be present in messages passed through
# Microsoft Exchange orcreated with clients like Microsoft Outlook. You can think of MAPI properties as being
# an additional header added to a message. While these properties are not necessary for every investigation, they
# can provide an extra edge when doing deep dive analysis into message stores for cases like message forgery,
# time manipulation, orwhen attempting to prove that messages may be missing. Research continues on many of
# theseproperties, butsome that you may find useful in your cases are listed here.
# Mapi-Client-Submit-Time - This is the time ofthe local system when the email was submitted by the email
# client. It could be used to show that the local system time was set backwards (or forwards) when matched with
# other timestamps

# Mapi-Conversation-Index - A fascinating artifact that tracks how many child messages were part ofthe email
# chain AND records timestamps for each message in the chain. The format is challenging, but an excellent
# guide to parsing this value can befound at 
# http://www.meridiandiscovery.com/how-to/e-mail-conversation-index-metadata-computer-forensics/

# Mapi-EntrylD - Amessage identifier provided by the message store when an email is saved or sent. It is only
# unique to a particular store (i.e. .PST file) so it can help identify when messages are provided or opened from
# multiple different PST files. 
# Mapi-Message-Flags and Pr_Last_Verb_Executed - Provide detailed information onthe actions that occurred
# fora MAPI-aware email. Values include: read, unread, unsent, replied, forwarded. Outof Office mail, etc.


    #To mark RECEIVED ip address and domain name as a set
    traceCounter = 0

    with open(emailHeaderTextFile, 'r') as filehandle:
        fileContents = filehandle.readlines()

    for line in fileContents:        
        # Message-ID: Provided by the originating mail server and consisting of a unique identifier appended to
        # the server name with an symbol. It is similar to a tracking number for the message and is logged by
        # receiving mail servers. A search of mail server logs for the Message-ID will provide evidence of the email
        # passing through.
        if line.startswith("Message-ID"):            
            try:
                temp_list = line.split(":")        
                #to remove space and bracket                         
                forensic_messageid = temp_list[1][2:-2]
                logger.info("Message-ID is " + str(forensic_messageid))  
            except:
                logger.error("Unable to extract email Message-ID field")
                pass


        # If the In-Reply-To field is used, it records the message ID for the parent of the current e-mail message. This
        # field is less common and may eventually be deprecated. As an example, it Is a current practice for many e-mail
        # clients to check if the value in the In-Reply-To field is located in the References field, and if not, add it.
        # Thus the References field typically has the most complete information about previous messages inthe
        # thread. 
        # We can use information in these fields to identify other related e-mail messages. Since message IDs are supposed to be unique, they make great search terms.
        # Additionally, some ofthe more advanced e-mail forensics tools automate this process. They simply use the
        # References and In-Reply-To fields to reconstruct threads, providing a simpler review process and
        # eliminating redundant messages.

        if "In-Reply-To" in line:
            #Skip if in-reply-to field is from DKIM-Signature. 
            if "mime-version" not in line:             
                try:
                    temp_list = line.split(":")
                    #to remove space and bracket 
                    forensic_parentmessageid = temp_list[1][2:-2]
                    logger.info("In-Reply-To is " + str(forensic_parentmessageid))             
                except:
                    logger.error("Unable to extract email In-Reply-To field")
                    pass

        # The References field is more widely used and consists of a simple list of message IDs for each of the
        # preceding messages in the thread. Every time a reply message is generated, the message ID for the parent
        # message is appended to the end of the References field.

        if line.startswith("References"):
            try:
                temp_list = line.split(":")
                forensic_references = temp_list[1]
                logger.info("References is " + str(forensic_references))             
            except:
                logger.error("Unable to extract email References field")
                pass

        # 
        # X-Originating-IP (also X-IP) An optional tag that identifies the IP address of the computer used to send
        # the original message. It can be forged, but requires control of the originating e-mail MTA.                

        if "X-Originating-IP" in line:      
            try:                
                forensic_xoriginatingIPaddress = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line).group()
                logger.info("X-Originating-IP is : " + str(forensic_xoriginatingIPaddress))            
            except:
                logger.error("Unable to extract email X-Originating-IP field")
                pass


        if "X-IP" in line:                        
            try:
                temp_list = line.split(":")
                forensic_xIPaddress = temp_list[1]
                logger.info("X-IP is :" + str(forensic_xIPaddress))            
            except:
                logger.error("Unable to extract email X-IP field")
                pass
                
        # Even if an X-Originating-IP field is not present, the mail server may still record endpoint originating information in the
        # "Received" field (in addition the standard mail server IP addresses). Until recently, many web mail
        # solutions included this optional field. However there has been a recent trend towards removing it due to
        # privacy concerns. A sample entry looks like:
        # Received: from [74.241.5.37] by webl22206.mail.nel.yahoo.com via HTTP;
        # Mon, 02 Apr 2013 17:27:46 PDT

        # Received: You can trace the path a message took by reading the "Received" entries starting from the
        # bottom-most entry (the originating mail server). Each MTA traversed adds a "Received" entry and each
        # entry includes the server IPaddress, server name, date, time, and time zone. Keep in mind that Spammers
        # have been known to insert fake "Received" lines in messages. However, entries included by your own
        # MTAs should be trustworthy. 
        # A sample entry follows:
        # Received: from smtpl09.sbc.mail.re2.yahoo.com (68.142.229.96) by
        # mirl.raail.vip.sc5.yahoo.com with SMTP, 26 Oct 2005 07:56:20 -0000
        
        if line.startswith("Received:"):
            ipFound = False
            domainFound = False
            try:
                #Check if there is an IP address in the Received line
                forensic_receivedIPaddress = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line).group()
                logger.info("Received field has ip address : " + str(forensic_receivedIPaddress))

                traceCounter = traceCounter + 1

                whoisLookUp(forensic_receivedIPaddress)
                #To demarcate whois result as a set
                currentFilename = forensic_receivedIPaddress + ".txt"
                os.rename(currentFilename, str(traceCounter) + "-" + currentFilename)
                ipFound = True                
                              
            except:
                logger.info("IP address not available in Received: field")
                print str(line)
                pass

            if "(" in line:
                try:
                    temp_list = line.split(' ')
                    forensic_receivedDomain = str(temp_list[2])

                    #If the whole received line only have domain names (RARE)
                    if ipFound == False:
                        traceCounter = traceCounter + 1

                    whoisLookUp(forensic_receivedDomain)
                    #To demarcate whois result as a set
                    currentFilename = forensic_receivedDomain + ".txt"
                    os.rename(currentFilename, str(traceCounter) + "-" + currentFilename)

                    domainFound = True
                    logger.info("Received field has domain : " + str(forensic_receivedDomain))
                except:
                    logger.info("Unable to extract domain from Received: field")
                    pass

            #Compare forensic_receivedDomain and forensic_receivedIPaddress to identify spoofing            
            if domainFound:
                with open ( str(traceCounter) + "-" + forensic_receivedDomain + ".txt") as domainfilename:
                    for domainLine in domainfilename:                        
                        if "@" in domainLine:
                            temp_list = domainLine.split("@")
                            emailDomain = temp_list[1]                           
                            
                            if ipFound:
                                domainMatch = False
                                with open ( str(traceCounter) + "-" + forensic_receivedIPaddress + ".txt") as ipfilename:                                    
                                    for ipLine in ipfilename:
                                        if emailDomain in ipLine:
                                            domainMatch = True

                #There may be multiple domain in a single domain header. Only ONE have to match!
                if domainMatch == False:
                    logger.info("SPOOFING SUSPECTED AS " + forensic_receivedDomain + " and " + forensic_receivedIPaddress + " does not match!")




        # X-Mailer: Identifies the e-mail client used to create the e-mail message. Its inclusion is optional and it
        # can be a good indicator of whether the e-mail was created locally or via web-based client. This
        # information would be included by the Originating MTA.
        # X-Mailer: YahooMailWebService/0.8.116.338427
        if line.startswith("X-Mailer"):        
            try:
                temp_list = line.split(":")
                forensic_XMailer = temp_list[1]
                logger.info("X-Mailer is : " + str(forensic_XMailer))
            except:
                logger.error("Unable to extract email X-Mailer field")
                pass

    

#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():

    parser = argparse.ArgumentParser(description="Check email header for signs of spoofing")
    parser.add_argument('-t', dest='emailHeaderTextFile', type=str, required=True, help="Text file containing email header")        
    args = parser.parse_args()  
    
    emailHeaderAnalysis(args.emailHeaderTextFile)  
    
if __name__ == '__main__':
    main()



