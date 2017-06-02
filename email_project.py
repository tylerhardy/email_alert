# Imports
from __future__ import print_function
from httplib2 import Http
import os, time, base64, email

from apiclient import discovery
from oauth2client import file, client, tools
from oauth2client.file import Storage
from apiclient import errors

# Variables
SCOPES = 'https://www.googleapis.com/auth/gmail.modify'
store = file.Storage('storage.json')
creds = store.get()
if not creds or creds.invalid:
    flow = client.flow_from_clientsecrets('client_secret.json', SCOPES)
    creds = tools.run_flow(flow, store)

GMAIL = discovery.build('gmail', 'v1', http=creds.authorize(Http()))
labels_list = GMAIL.users().labels().list(userId='me').execute()

# Functions
def CreateLabel(service, user_id, label_object):
    try:
        label = service.users().labels().create(userId=user_id, body=label_object).execute()
        print('Label ID: [{0}]'.format(label['id']))
        print('Label Name: [{0}]'.format(label['name']))
        return label
    except errors.HttpError as error:
        print('An error occurred: {0}'.format(error))

def MakeLabelObject(label_name, mlv='show', llv='labelShow'):
    label = {
        'messageListVisibility': mlv,
        'name': label_name,
        'labelListVisibility': llv
        }
    return label

def CheckForLabel(check_label_name, label_list, service):
    label_id = ''
    label_name = ''
    # print('Checking for label: [{0}]'.format(check_label_name))
    for label in label_list['labels']:
        if label['name'] == check_label_name:
            label_id = label['id']
            label_name = label['name']
            # print('Label [{0}] found with id:[{1}]'.format(check_label_name, label_id))
            break
    if label_id and label_name:
        # print('Label found with id: [{0}]'.format(label_id))
        return [label_id, label_name]
    else:
        # Create Label Objects if not exist
        # print('No label found')
        # print('Creating label object for [{0}]...'.format(check_label_name))
        label_object = MakeLabelObject(check_label_name)

        # Create Labels
        # print('Creating label for [{0}]...'.format(check_label_name))
        CreateLabel(service, 'me', label_object)

def LabelWatch(service, label_list_id_name):
    while True:
        print('Checking [{0}] for new alerts...'.format(label_list_id_name[1]))
        messages_object = service.users().messages().list(userId='me', labelIds=label_list_id_name[0]).execute().get('messages', [])
        # print(messages_object)
        msgs = len(messages_object)
        if messages_object:
            print('Found {0} new alert email(s)!'.format(str(msgs)))
            break
        time.sleep(15)
    GetMessage(service, messages_object)

def GetMessage(service, messages_object):
    print('Processing alert...')
    for message in messages_object:
        # print(message)
        try:
            message_data = service.users().messages().get(userId='me', id=message['id'], format='raw').execute()
            # print('Message snippet: [{0}]'.format(message_data['snippet']))
            # print(message_data)
            message_text = GetMimeMessage(service, message['id'])
            print(message_text)
            # return message_data
        except errors.HttpError as error:
            print('An error occurred: {0}'.format(error))

def GetMimeMessage(service, message_id):
    try:
        message = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        print('Message snippet: [{0}]'.format(message['snippet']))
        msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
        mime_msg = email.message_from_bytes(msg_str)
        return mime_msg
    except errors.HttpError as error:
        print('An error occurred: {0}'.format(error))

def GetMessageBody(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id, format='raw').execute()
        msg_str = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
        mime_msg = email.message_from_string(msg_str)
        messageMainType = mime_msg.get_content_maintype()
        if messageMainType == 'multipart':
            for part in mime_msg.get_payload():
                if part.get_content_maintype() == 'text':
                    return part.get_payload()
            return ""
        elif messageMainType == 'text':
            return mime_msg.get_payload()
    except errors.HttpError as error:
        print('An error occurred: {0}'.format(error))

def main():
    # Check if labels exist
    new_alerts_id = CheckForLabel('Malware Alerts New', labels_list, GMAIL)
    pending_alerts_id = CheckForLabel('Malware Alerts Pending', labels_list, GMAIL)
    cleaned_alerts_id = CheckForLabel('Malware Alerts Cleaned', labels_list, GMAIL)

    LabelWatch(GMAIL, new_alerts_id)

if __name__ == '__main__':
    main()