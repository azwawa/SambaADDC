# Copyright (C) 2021 IMJW Consult
# All rights reserved.
#
#      IMJW Consult
#      Tour Cœur Défense
#      92400 Courbevoie
#      01 48 59 68 85
#      https://imjw-consult.com
#  
#      Direct Author : Walid Bendjoudi
#
#   DISCLAIMER OF WARRANTIES:
# -----------------------------------------------------------------------------------
#   Be aware that all scripts are run at your own risk and while every script 
#   has been written with the intention of minimising the potential for unintended 
#   consequences, the owners, hosting providers and contributers cannot be 
#   held responsible for any misuse or script problems.
# ------------------------------------------------------------------------------------
#
#   Script Utility 
# ------------------------------------------------------------------------------------
#   This script is composed of classes that contains unique functions.
#   The scripts fetches a csv attachment of users from an email, saves it to the desired location.
#   Then connects to your Samba DC server and creates the users.
#   The fields are firstname, lastname, jobtitle, mobile, department/
#   The mandatory fields are firstname, lastname, department, where department stands for the OU.
#   The firstname and lastname compose the upn/samaccountname like so : firstname.lastname@domain aswell as the email.
#   Value can be customed at the end of this file, start by modifying the log file location and other stuff you want
#   at the start of this file after.
# ------------------------------------------------------------------------------------
#
#!/usr/bin/python3
# -*- coding: utf-8 -*-

#import some libraries for general code formating and outputs
import sys
import traceback
import secrets
import string
import getpass
import ldb
import os
from datetime import datetime
import time
import logging
import shutil
import random as rand
from termcolor import colored

# import library to read csv
import pandas as pd

# import library to read regex pattern
import re

# import libraries for samba and user creation
from samba.auth import system_session
from samba.credentials import Credentials as sambacreds
from samba.dcerpc import security
from samba.dcerpc.security import dom_sid
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm
from samba.samdb import SamDB

# import other libraries to be used for email file fetching
from exchangelib import Account, Configuration, Credentials, DELEGATE, Folder, Message, \
FileAttachment, ItemAttachment, CalendarItem, HTMLBody, Mailbox


# set logging File
logfile = "/var/log/user_creation_flow/log.txt"
logging.basicConfig(handlers=[logging.FileHandler(filename=logfile, 
                                                 encoding='utf-8', mode='a+')],
                    format="%(asctime)s %(name)s:%(levelname)s:%(message)s", 
                    datefmt="%F %A %T", 
                    level=logging.INFO)

random_id = rand.uniform(1,1000)
unique_id = "id:" + str(random_id)
logging.info('\n\nInitiating logging to file task')
logging.info(unique_id)

dateoftheday = datetime.today()


##############################################################
#                   Fetch Email class
##############################################################

# fetch email class
class fetchemail:
    username = ""
    password = ""
    server = ""
    sender = ""
    subject_contains = ""
    attachmentpath = ""
    attachmentfilefullpath = ""

    # save attachment from email function
    def fetch(self):
        try:
            """
            Get Exchange account cconnection with server
            """
            creds = Credentials(username=self.username, password=self.password)
            config = Configuration(server=self.server, credentials=creds)
            account = Account(primary_smtp_address=self.username, autodiscover=False, config=config, access_type=DELEGATE)

            # delete existing files in folder
            for root, dirs, files in os.walk(self.attachmentpath):
                for f in files:
                    os.unlink(os.path.join(root, f))
                for d in dirs:
                    shutil.rmtree(os.path.join(root, d))

            filtered_items = account.inbox.filter(subject__contains=self.subject_contains, sender=self.sender)
            ordered_items = filtered_items.order_by('-datetime_received')[:5]               
            # or don't filter -> for item in account.inbox.all().order_by('-datetime_received')[:10]:
            for item in ordered_items:
                for attachment in item.attachments:
                    # check if there is an attachment
                    if isinstance(attachment, FileAttachment):
                        local_path = os.path.join(self.attachmentpath, attachment.name)
                        attachment_file = attachment.name
                        with open(local_path, 'wb') as f:
                            f.write(attachment.content) 
                        
                    else:
                        print(colored("\nNo attachment detected, closing session", 'red'))
                        logging.warning("No attachment detected, closing session")
                        exit()

            # Check if attachment was saved
            check_attachment = os.path.exists(f"{self.attachmentpath}/{attachment_file}")
            if check_attachment:
                print(colored(f"\nSaved attachment to {local_path}", 'cyan'))
                logging.info('Saved attachment to newarrivals directory')
                
                # if attachment dosen't have name defined by user using class rename it to what user has chosen
                if local_path == str(self.attachmentfilefullpath):
                    logging.warning("Attachment file name alredy has the right name")
                    print(colored("Attachment file name alredy has the right name", 'cyan'))
                    pass
                else:
                    os.rename(local_path, str(self.attachmentfilefullpath))
                    logging.info("Renamed attachment file")
                    print(colored("Renamed attachment file", 'cyan'))

            else:
                print (colored("\nFile not found in directory, closing session", 'red'))
                logging.error("File was not found despite being detected in email")
                exit() 

        except Exception as e:    
            print (colored('\nNot able to download all attachment, full logging trace at /var/log/user_creation_flow', 'red'))            
            print(colored(e, 'red'))
            logging.error("Not able to download attachment")
            logging.error(e, exc_info=True)
            exit()


##############################################################
#                       Create User class                      
##############################################################

class createuser:
    # file where user credentials are printed
    user_login_details = ""
    samba_username = ""
    samba_password = ""
    samba_url = ""
    users_ldap_search_ou_path = ""
    user_ldap_create_ou_path = ""
    user_domain = ""
    
    def create(self):
        # import File
        f =  fetch.attachmentfilefullpath     # f variable is linked to the above fetchemail class value you define
        check_attachment = os.path.exists(f)

        if check_attachment is True:
            # open LDAP session 
            lp = LoadParm()
            credentials = sambacreds()
            credentials.guess(lp)
            credentials.set_username(self.samba_username)
            credentials.set_password(self.samba_password)
            samdb = SamDB(url=self.samba_url, session_info=system_session(),credentials=credentials, lp=lp)

            # read file
            csv_f = pd.read_csv(f)                          

            # itterate over columns with ind as index and define variables
            for ind in csv_f.index:                         
                try:
                    firstname = (csv_f["firstname"][ind])
                    lastname = (csv_f["lastname"][ind])
                    department = (csv_f["department"][ind])
                    mobile_raw = (csv_f["mobile"][ind])
                    mobile = str(mobile_raw)
                    jobtitle = (csv_f["jobtitle"][ind])
                    user_create_ou_path = self.user_ldap_create_ou_path
                    users_ou_path = self.users_ldap_search_ou_path
                    domain = self.user_domain
                    

                    username = firstname.lower() + "." + lastname.lower()
                    userou = (f"OU={department},{user_create_ou_path}")
                    mailaddress = username + '@' + domain

                    # verify if user alredy exists
                    query = (f"(sAMAccountName={username})")
                    exists = samdb.search(users_ou_path, expression=query, scope=ldb.SCOPE_SUBTREE)

                    #if user dosen't already exists then create it
                    if not exists:
                
                        # generate random secured password uppercase, lowercase, number of 10 chars
                        password = ''.join((secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(10)))
                        # create Users
                        samdb.newuser(username=username,password=password,\
                            userou=userou,\
                            mailaddress=mailaddress,\
                            jobtitle=jobtitle,\
                            department=department,\
                            telephonenumber=mobile,\
                            scriptpath="/bin/bash")

                        # define variables to check of creation was successful
                        query = (f"(sAMAccountName={username})")
                        result = samdb.search(users_ou_path, expression=query, scope=ldb.SCOPE_SUBTREE)
                        
                        # verify user creation and print outcome
                        if result:
                            print (("\nUser"), colored(f"{firstname} {lastname}", 'green'), ("has been created !"))
                            logging.info(f"User {firstname} {lastname} has been created !")
                            original_stdout = sys.stdout
                            # write to user details file username password
                            with open(self.user_login_details, 'a') as f:
                                f.write("\n" + f"{firstname} {lastname}, login: {mailaddress}, password: {password}\n")


                        else:
                            print (colored(f"\nUser {firstname} {lastname} creation failed !", 'red'))
                            logging.warning(f"User {firstname} {lastname} creation failed !")
                            # write to user details file that he was not created
                            with open(self.user_login_details, 'a') as f:
                                f.write("\n" + f"{firstname} {lastname} was not created ! Support will take actions.\n")

                    # if user already exists then print the info and log it
                    else:
                        print (colored(f"\nUser {firstname} {lastname} already exists !", 'magenta'))
                        logging.warning(f"User {firstname} {lastname} already exists !")
                        # write to user details file that user alredy exists
                        with open(self.user_login_details, 'a') as f:
                                f.write("\n" + f"{firstname} {lastname} already exists ! No further actions needed\n")
                
                # handle error
                except Exception as e:
                    print (colored('\nAn error occurred during user creation, full logging trace at /var/log/user_creation_flow', 'red'))
                    print(colored(e, 'red'))
                    logging.critical(e, exc_info=True)
                
        # if attachment was not detected then exit
        else:
            print(colored("\nNo attachment detected, closing session", 'cyan'))
            logging.warning('No attachment detected, closing session')
            exit()


##############################################################
#                   Send Email to HR class
##############################################################

class sendemailtohr:
    username = ""
    password = ""
    server = ""
    recipient = ""
    # file where user credentials where printed in the createuser class
    user_login_details = ""

    # define send email function
    def send(self):
        try:

            # send an email to HR mailbox with user login details
            creds = Credentials(username=self.username, password=self.password)
            config = Configuration(server=self.server, credentials=creds)
            account = Account(primary_smtp_address=self.username, autodiscover=False, config=config, access_type=DELEGATE)
            user_login_details = self.user_login_details

            # read from login details file
            with open(os.path.abspath(user_login_details), "r", encoding="utf-8") as f:
                # add file content to the body variable
                body = f.read()
            m = Message(
            account=account,
            subject='Users have been created',
            body=body,
            to_recipients=[
                Mailbox(email_address=self.recipient)
            ])

            # call send function to send email
            m.send()

        # if email couldn't be sent then log the error
        except Exception as e:
                print (colored("\nEmail with login detail couldn't be sent, full logging trace at /var/log/user_creation_flow", 'red'))
                logging.error("Email with login detail couldn't be sent")
                logging.error(e, exc_info=True)
                print(colored(e, 'red'))


##############################################################
#                   Send Email to Admin class
##############################################################
class sendemailtoadmin:

    username = ""
    password = ""
    server = ""
    recipient = ""    

# define send email to admin function 
    def send(self):
        try:
            # get logs from log file of this particular execution
            # define regex pattern based on id defined at the start of the script, pattern finds all content after id
            # also filter for critical mentions
            pattern = re.compile((f"({unique_id}.*)"), flags=re.S)

            # read logfile 
            file = open(logfile,'r')
            file_read = file.read()
            
            # search for regex matches
            body_text = ""
            for match in pattern.finditer(file_read):
                # get the result into a tuple
                body_text = ((f"Backlog : {dateoftheday}\n\n") +  match.group())

            # send an email to Admin mailbox with user login details and backlog
            creds = Credentials(username=self.username, password=self.password)
            config = Configuration(server=self.server, credentials=creds)
            account = Account(primary_smtp_address=self.username, autodiscover=False, config=config, access_type=DELEGATE)

            m = Message(
            account=account,
            subject='User Creation Triggered',
            body=body_text,
            to_recipients=[
                Mailbox(email_address=self.recipient)
                #Mailbox(email_address='bob@example.com'),
            ])

            # call send function
            m.send()

        except Exception as e:
                print (colored("\nEmail with login detail couldn't be sent to admin, full logging trace at /var/log/user_creation_flow", 'red'))
                logging.error("Email with login detail couldn't be sent to admin")
                logging.error(e, exc_info=True)
                print(colored(e, 'red'))

##############################################################
#                   Call classes functions
##############################################################

# source email attachment credentials
f_email_cred_file = "/etc/.cred/.f_email_cred.csv" # credentials file
f_email_cred_r = pd.read_csv(f_email_cred_file) # read from csv with pandas
f_email_username = (f_email_cred_r["username"][0]) # must be an index from an array
f_email_password = (f_email_cred_r["password"][0]) # must be an index from an array


# call fetchemail class
fetch = fetchemail()
fetch.username = f_email_username
fetch.password = f_email_password
fetch.server = "outlook.office365.com"
fetch.sender = "MYSENDER"
fetch.subject_contains = "[HR] New Users"
fetch.attachmentpath = "/srv/.rh"
# the name of the attachment file is renamed to what you put here
fetch.attachmentfilefullpath = fetch.attachmentpath + "/.users.csv"
fetch.fetch()
time.sleep(5)


# samba credentials
samba_cred_file = "/etc/.cred/.samba_cred.csv" # credentials file
samba_cred_r = pd.read_csv(samba_cred_file) # read from csv with pandas
samba_username = (samba_cred_r["username"][0]) # must be an index from an array
samba_password = (samba_cred_r["password"][0]) # must be an index from an array


# call createuser class
create = createuser()
create.samba_username = samba_username
create.samba_password = samba_password
create.samba_url = "ldap://127.0.0.1:389"
create.user_login_details = "/srv/.rh/.user_login_details.txt"
create.user_domain = "c-finances.fr" # will get an email address like username@yourvalue
create.users_ldap_search_ou_path = 'OU=C-FINANCES USERS,DC=c-finances,DC=fr' # used to search if user already exists
create.user_ldap_create_ou_path = "OU=C-FINANCES USERS" # will be formated like OU=department, OU=YourValue during user creation
create.create()
time.sleep(5)


# sender email credentials (preferable to use a service generic email)
s_email_cred_file = "/etc/.cred/.s_email_cred.csv" # credentials file
s_email_cred_r = pd.read_csv(s_email_cred_file) # read from csv with pandas
s_email_username = (s_email_cred_r["username"][0]) # must be an index from an array
s_email_password = (s_email_cred_r["password"][0]) # must be an index from an array


# call sendemailtohr class
send_hr = sendemailtohr()
send_hr.username = s_email_username
send_hr.password = s_email_password
send_hr.server = "outlook.office365.com"
send_hr.recipient = "MYRECIPIENT"
send_hr.user_login_details = create.user_login_details # calls the file where user login detail were written
send_hr.send()


# send senemailtoadmin class (content of variable 'logfile' at the start of this script will be sent)
send_adm = sendemailtoadmin()
send_adm.username = s_email_username
send_adm.password = s_email_password
send_adm.server = "outlook.office365.com"
send_adm.recipient = "MYRECIPIENT"
send_adm.send()
