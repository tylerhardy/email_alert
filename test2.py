
from __future__ import print_function
from httplib2 import Http
import os, time

from apiclient import discovery
from oauth2client import file, client, tools
from oauth2client.file import Storage
from apiclient import errors


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
    print('Checking for label: [{0}]'.format(check_label_name))
    for label in label_list['labels']:
        if label['name'] == check_label_name:
            label_id = label['id']
            print('Label [{0}] found with id:[{1}]'.format(check_label_name, label_id))
            break
    if label_id:
        return label_id
    else:
        # Create Label Objects if not exist
        print('No label found')
        print('Creating label object for [{0}]...'.format(check_label_name))
        label_object = MakeLabelObject(check_label_name)

        # Create Labels
        print('Creating label for [{0}]...'.format(check_label_name))
        CreateLabel(service, 'me', label_object)

def CheckEmail(service, label_id):
    email_threads = service.users().threads().list(userId='me', labelIds=label_id).execute()
    print(email_threads)
    return(email_threads)

def LabelWatch(service, label_id):
    while True:
        print('Checking [{0}] for new alerts...'.format(label_id))
        if CheckEmail(service, label_id):
            print('Found new alert email!')
            break
        time.sleep(15)
    ProcessAlert()

def ProcessAlert():
    print('Processing alert...')

SCOPES = 'https://www.googleapis.com/auth/gmail.modify'
store = file.Storage('storage.json')
creds = store.get()
if not creds or creds.invalid:
    flow = client.flow_from_clientsecrets('client_secret.json', SCOPES)
    creds = tools.run_flow(flow, store)

GMAIL = discovery.build('gmail', 'v1', http=creds.authorize(Http()))
labels_list = GMAIL.users().labels().list(userId='me').execute()

# Check if labels exist
new_alerts_id = CheckForLabel('Malware Alerts New', labels_list, GMAIL)
pending_alerts_id = CheckForLabel('Malware Alerts Pending', labels_list, GMAIL)
cleaned_alerts_id = CheckForLabel('Malware Alerts Cleaned', labels_list, GMAIL)

LabelWatch(GMAIL, new_alerts_id)





'''
threads = GMAIL.users().threads().list(userId='me', q='from:SCCMAlert@weber.edu').execute().get('threads', [])


for thread in threads:
    tdata = GMAIL.users().threads().get(userId='me', id=thread['id']).execute()
    nmsgs = len(tdata['messages'])

    # if nmsgs > 2:
    msg = tdata['messages'][0]['payload']
    subject = ''
    for header in msg['headers']:
        if header['name'] == 'Subject':
            subject = header['value']
            break
    if subject:
        print('%s (%d msgs)' % (subject, nmsgs))
'''