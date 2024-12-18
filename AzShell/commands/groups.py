import json, re, time, os
from AzShell.utils.constants import Format

class Groups:
    
    def __init__(self, auth, request, search, allinfo):
        self.auth = auth
        self.request = request
        self.search = search
        self.allinfo = allinfo
        self.data = []

    def __dump_groups(self, groups_file):
        base_dir = os.path.expanduser("~/.AzShell/Groups/")
        os.makedirs(base_dir, exist_ok=True)
        policies_path = os.path.join(base_dir, groups_file)
        f = open(policies_path, "w")
        json.dump(self.data, f)
        print(Format.GREEN + "\n[+] Full group information saved in " + policies_path + Format.END)
        f.close()   

    def __get_groupmembers(self, groupid, nextlink=None, exit=False):
        if nextlink is None:
            url = "https://graph.microsoft.com/v1.0/groups/" + groupid + "/members?$top=999&$nextLink"
        else:
            url = nextlink
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            members_data = json.loads(response.content.decode('utf-8'))
            if "@odata.nextLink" in members_data:
                self.__get_groupmembers(groupid, members_data["@odata.nextLink"])
            for member in members_data["value"]:
                self.data.append(member)
                if member["@odata.type"] == "#microsoft.graph.user":
                    print(Format.BLUE + "  [User] " + Format.YELLOW + member["displayName"] + ": " + Format.END + str(member["userPrincipalName"]) + " [" + str(member["id"]) + "]")
                elif member["@odata.type"] == "#microsoft.graph.group":
                    print(Format.BLUE + "  [Group] " + Format.YELLOW + member["displayName"] + ": " + Format.END + str(member["description"]) + " [" + str(member["id"]) + "]")
                else:
                    print(Format.BLUE + "  [Other] " + Format.YELLOW + member["displayName"] + " [" + str(member["id"]) + "]")
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_groupmembers(groupid, nextlink, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def get_groups(self, updatable=False, privesc=False, exit=False):
        if not self.allinfo and self.search is None and not privesc:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --search or --all have to be defined"  + Format.END)
        else:
            search_id = False
            if self.allinfo or privesc:
                if updatable:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all updatable groups" + Format.END)
                else:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all groups" + Format.END)
                url = "https://graph.microsoft.com/v1.0/groups"
            else:
                if updatable:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading updatable groups [" + self.search + "]" + Format.END)
                else:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading groups [" + self.search + "]" + Format.END)
                if re.match('^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$',self.search.lower()):
                    url = 'https://graph.microsoft.com/v1.0/groups/' + self.search + '?$orderby=displayName'
                    search_id = True
                else:
                    url = 'https://graph.microsoft.com/v1.0/groups?$search="displayName:' + self.search + '" OR "description:' + self.search +'"&$orderby=displayName'
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                groups_data = json.loads(response.content.decode('utf-8'))
                if search_id:
                    groups_data = {"value":[groups_data]}
                result_updatable = False
                for group in groups_data["value"]:
                    if updatable:
                        result_updatable = self.__get_updatable_group(group["id"])
                    if (updatable and result_updatable) or not updatable:
                        self.data.append(group)
                        print('\n' + Format.BOLD_START + Format.YELLOW + group["displayName"] + Format.END )
                        print(Format.CYAN + " GroupId: " + Format.END + group["id"])
                        print(Format.CYAN + " Description: " + Format.END + str(group["description"]))
                        print(Format.CYAN + " OnPremisesDomainName: " + Format.END + str(group["onPremisesDomainName"]))
                        print(Format.CYAN + " OnPremisesSamAccountName: " + Format.END + str(group["onPremisesSamAccountName"]))
                        print(Format.CYAN + " Members: " + Format.END )
                        self.__get_groupmembers(group["id"])
                if self.allinfo and not privesc:
                    groups_file = time.strftime("%Y%m%d-%H%M%S") + "_groups.json"
                    self.__dump_groups(groups_file)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.get_groups(updatable, privesc, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def __get_updatable_group(self, groupid, exit=False):
        url = "https://graph.microsoft.com/beta/roleManagement/directory/estimateAccess"
        body = {
            "resourceActionAuthorizationChecks": [
                {
                    "directoryScopeId": "/" + groupid,
                    "resourceAction": "microsoft.directory/groups/members/update"
                    }]
                }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 200:
            updatable_data = json.loads(response.content.decode('utf-8'))
            if updatable_data['value'][0]['accessDecision'] == "allowed":
                return True
            else:
                return False
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_updatable_group(groupid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)


    def add_group(self, description, displayName, mailNickname, exit=False):
        url = "https://graph.microsoft.com/v1.0/groups"
        body = {
          "description": description,
          "displayName": displayName,
          "groupTypes": [
            "Unified"
          ],
          "mailEnabled": True,
          "mailNickname": mailNickname,
          "securityEnabled": True,
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Group added!" + Format.END)
            response_parse = json.loads(response.content.decode('utf-8'))
            print('\n' + Format.BOLD_START + Format.YELLOW + response_parse["displayName"] + Format.END)
            print(Format.CYAN + " GroupId: " + Format.END + response_parse["id"])
            print(Format.CYAN + " Description: " + Format.END + str(response_parse["description"]))
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_group(description, displayName, mailNickname, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_group(self, groupid, exit=False):
        url = "https://graph.microsoft.com/v1.0/groups/" + groupid
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Group removed!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_group(groupid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_groupmember(self, userid, groupid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/groups/' + groupid + '/members/$ref'
        body = {
            '@odata.id':'https://graph.microsoft.com/v1.0/directoryObjects/' + userid
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] User added to group!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_groupmember(userid, groupid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_groupmember(self, objectid, groupid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/groups/' + groupid + '/members/' + objectid + '/$ref'
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] User removed from group!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_groupmember(objectid, groupid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END) 