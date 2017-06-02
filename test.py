import imaplib
import getpass

mail = imaplib.IMAP4_SSL('imap.gmail.com')
mail.login('tylerhardy@gmail.com', getpass.getpass())
mail.list()
# Out: list of "folders" aka labels in gmail.
mail.select("inbox") # connect to inbox.