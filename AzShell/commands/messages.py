import os, json
from bs4 import BeautifulSoup
from AzShell.utils.constants import Format

class Messages:
    
    def __init__(self, auth, request, search):
        self.auth = auth
        self.request = request
        self.search = search

    def __dump_message(self, message_file):
        base_dir = os.path.expanduser("~/.AzShell/Messages/")
        os.makedirs(base_dir, exist_ok=True)
        message_path = os.path.join(base_dir, message_file)
        f = open(message_path, "w")
        f.write(self.data)
        print(Format.GREEN + "\n[+] HTML message saved in " + message_path)
        f.close()

    def get_messages(self, userid, messageid, top, exit=False):
        if messageid is not None:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading the message " + Format.END)
            url = "https://graph.microsoft.com/v1.0/users/" + userid + "/messages/" + messageid
        elif self.search is None:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all messages" + Format.END)
            url = "https://graph.microsoft.com/v1.0/users/" + userid + "/messages?" + '$top=' + top
        else:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading messages [" + self.search + "]" + Format.END)
            url = 'https://graph.microsoft.com/v1.0/users/' + userid + '/messages?$search="{' + self.search + '}"&top=' + top
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            if messageid is None:
                messages_data = json.loads(response.content.decode('utf-8'))
                for message in messages_data["value"]:
                    if "from" in message:
                        print('\n' + Format.BOLD_START + Format.YELLOW + str(message["from"]["emailAddress"]["name"]) + " (" + str(message["from"]["emailAddress"]["address"]) + ") [" + str(message["receivedDateTime"]) +"]" + Format.END)
                    print(Format.BOLD_START + Format.CYAN + " " + str(message["subject"]) + Format.END )
                    print(Format.CYAN + " MessageId: " + Format.END + str(message["id"]) )
                    print(Format.CYAN + " Attachments: " + Format.END + str(message["hasAttachments"]))
                    bodypreview = str(message["bodyPreview"]).lstrip().split('\n')
                    parsed_bodypreview = ["  "+line for line in bodypreview if line.strip() != '']
                    print('\n'.join(parsed_bodypreview))
            else:
                message_data = json.loads(response.content.decode('utf-8'))
                if "from" in message_data:
                    print('\n' + Format.BOLD_START + Format.YELLOW + str(message_data["from"]["emailAddress"]["name"]) + " (" + str(message_data["from"]["emailAddress"]["address"]) + ") [" + str(message_data["receivedDateTime"]) +"]" + Format.END)
                print(Format.BOLD_START + Format.CYAN + " " + str(message_data["subject"]) + Format.END )
                print(Format.CYAN + " Attachments: " + Format.END + str(message_data["hasAttachments"]))
                self.data = str(message_data["body"]["content"])
                data_text = BeautifulSoup(self.data, "html.parser")
                print(data_text.get_text())
                filename = str(message_data["id"]) + ".html"
                self.__dump_message(filename)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.get_messages(userid, messageid, top, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_message(self, userid, subject, content, contentfile, contenttype, recipients, ccrecipients, exit=False):
        if contenttype.lower() != "text" and contenttype.lower() != "html":
            print(Format.BOLD_START + Format.YELLOW + '\n[!] --contenttype only allows "text" or "html"'  + Format.END)
        elif content is not None and contentfile is not None:
            print(Format.BOLD_START + Format.YELLOW + '\n[!] --content is incompatible with --contentfile'  + Format.END)
        else:
            if contentfile is not None:
                if os.path.isfile(contentfile):
                    file = open(contentfile, "r", encoding="utf-8")
                    content = file.read()
                else:
                    print(Format.BOLD_START + Format.YELLOW + '\n[!] The file does not exist'  + Format.END)
                    return
            url = 'https://graph.microsoft.com/v1.0/users/' + userid + '/sendMail'
            recipients_parse = recipients.split(",")
            toRecipients = []
            for recipient in recipients_parse:
                toRecipients.append({"emailAddress": {"address": recipient}})
            ccRecipients = []
            if ccrecipients is not None:
                ccrecipients_parse = ccrecipients.split(",")
                for ccrecipient in ccrecipients_parse:
                    ccRecipients.append({"emailAddress": {"address": ccrecipient}})
            body = {
              "message": {
                "subject": subject,
                "body": {
                  "contentType": contenttype,
                  "content":content
                },
                "toRecipients": toRecipients,
                "ccRecipients": ccRecipients
              },
              "saveToSentItems": "false"
            }
            response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
            if response.status_code == 202:
                print(Format.BOLD_START + Format.GREEN + "\n[+] Message sent!" + Format.END)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.add_message(userid, subject, content, contentfile, contenttype, recipients, ccrecipients, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_message(self, userid, messageid, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid + "/messages/" + messageid
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Message deleted!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_message(userid, messageid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)