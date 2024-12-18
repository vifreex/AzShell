import os, json
from bs4 import BeautifulSoup
from AzShell.utils.constants import Format

class Chats:
    
    def __init__(self, auth, request, search):
        self.auth = auth
        self.request = request
        self.search = search

    def get_chats(self, userid, chatid, top, nextlinkcount=0, nextlink=None, exit=False):
        if nextlink is not None:
            url = nextlink
        elif chatid is not None:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading messages" + Format.END)
            if top is None:
                top='5'
            url = "https://graph.microsoft.com/v1.0/users/" + userid + "/chats/" + chatid + "/messages?$nextLink"
        elif self.search is None:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all chats" + Format.END)
            if top is None:
                top='50'
            url = "https://graph.microsoft.com/v1.0/users/" + userid + "/chats?" + '$top=' + top + '&$expand=members'
        else:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading messages [" + self.search + "]" + Format.END)
            if top is None:
                top='10'
            url = 'https://graph.microsoft.com/v1.0/users/' + userid + '/chats/getAllMessages?'+ '$top=' + top
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            if chatid is None and self.search is not None:
                messages_data = json.loads(response.content.decode('utf-8'))
                for message in messages_data["value"]:
                    if self.search.lower() in message["body"]["content"].lower():
                        print(str(message["body"]["content"]) + " [" + message["chatId"]+ "]")
            elif chatid is None:
                chats_data = json.loads(response.content.decode('utf-8'))
                chats_list = []
                for chat in chats_data["value"]:
                    members_list = []
                    for member in chat["members"]:
                        if member["userId"] != userid and member["displayName"] is not None:
                            members_list.append(member["displayName"])
                    if members_list:
                        chats_list.append([str(chat["chatType"]), str(chat["id"]), ", ".join(members_list), str(chat["lastUpdatedDateTime"])])
                    else:
                        chats_list.append([str(chat["chatType"]), str(chat["id"]), "", str(chat["lastUpdatedDateTime"])])
                chats_list_sorted = sorted(chats_list, key=lambda x:x[3], reverse=True)
                for chats_sorted in chats_list_sorted:
                    if chats_sorted[0] == "oneOnOne":
                        print('\n' + Format.BOLD_START + Format.DARKCYAN + "[OneOnOne] " + Format.YELLOW + chats_sorted[2] + " [" + chats_sorted[3] +"]" + Format.END)
                        print(Format.CYAN + " ChatId: " + Format.END + chats_sorted[1])
                    elif chats_sorted[0] == "group":
                        print('\n' + Format.BOLD_START + Format.DARKCYAN + "[Group] " +  Format.YELLOW + chats_sorted[2] + " [" + chats_sorted[3] +"]" + Format.END)
                        print(Format.CYAN + " ChatId: " + Format.END + chats_sorted[1])
                        print(Format.CYAN + " Topic: " + Format.END + str(chat["topic"]))
                    elif chats_sorted[0] == "meeting":
                        print('\n' + Format.BOLD_START + Format.DARKCYAN + "[Meetings] " +  Format.YELLOW + chats_sorted[2] + " [" + chats_sorted[3] +"]" + Format.END)
                        print(Format.CYAN + " ChatId: " + Format.END + chats_sorted[1])
                        print(Format.CYAN + " Topic: " + Format.END + str(chat["topic"]))
            else:
                chat_data = json.loads(response.content.decode('utf-8'))
                messages_list = []
                if "@odata.nextLink" in chat_data and nextlinkcount < int(top):
                    nextlinkcount = nextlinkcount + 1
                    self.get_chats(userid, chatid, top, nextlinkcount, chat_data["@odata.nextLink"], True)
                for message in chat_data["value"]:
                    data_text = BeautifulSoup(message["body"]["content"], "html.parser")
                    if self.search is not None:
                        if self.search.lower() in str(data_text.get_text()).lower() and message["from"] is not None:
                            messages_list.append([str(message["from"]["user"]["displayName"]), str(message["createdDateTime"]), str(data_text.get_text())])
                    else:
                        if message["from"] is not None:
                            messages_list.append([str(message["from"]["user"]["displayName"]), str(message["createdDateTime"]), str(data_text.get_text())])
                messages_list_sorted = sorted(messages_list, key=lambda x:x[1])
                for message_sorted in messages_list_sorted:
                    print('\n' + Format.BOLD_START + Format.YELLOW + message_sorted[0] + " [" + message_sorted[1] +"]" + Format.END)
                    print(" " + message_sorted[2])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.get_chats(userid, chatid, top, nextlinkcount, nextlink, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_chatmessage(self, userid, chatid, content, exit=False):
        url = "https://graph.microsoft.com/v1.0/chats/" + chatid + "/messages"
        body ={
            "body": {
                "content": content
                }
            }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Chat message added!" + Format.END)
            message_data = json.loads(response.content.decode('utf-8'))
            print(Format.CYAN + " ChatMessageId: " + Format.END + message_data["id"])
            print(Format.CYAN + " Content: " + Format.END + message_data["body"]["content"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_chatmessage(userid, chatid, content, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_chatmessage(self, userid, chatid, messageid, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid + "/chats/" + chatid + "/messages/" + messageid + "/softDelete"
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Chat message deleted!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_chatmessage(userid, chatid, messageid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)