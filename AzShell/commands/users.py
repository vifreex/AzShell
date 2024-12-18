import json, re, time, os
from AzShell.utils.constants import Format

class Users():

    def __init__(self, auth, request, search, allinfo):
        self.auth = auth
        self.request = request
        self.search = search
        self.allinfo = allinfo
        self.data = []

    def __dump_users(self, users_file):
        base_dir = os.path.expanduser("~/.AzShell/Users/")
        os.makedirs(base_dir, exist_ok=True)
        users_path = os.path.join(base_dir, users_file)
        f = open(users_path, "w")
        json.dump(self.data, f)
        print(Format.GREEN + "\n[+] Full user information saved in " + users_path + Format.END)
        f.close()   

    def get_userdevices(self, userid, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid + "/ownedDevices"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            try:
                devices_data = json.loads(response.content.decode('utf-8'))
                for i, device in enumerate(devices_data["value"]):
                    self.data.append(device)
                    print(Format.PURPLE + "  [Device "+ str(i+1) + "] " + Format.END + device["displayName"] + " (LastSignInDate: " + device["approximateLastSignInDateTime"] + ") [" + device["id"] +"]")
            except:
                print(Format.BOLD_START + Format.RED + "\n  [!] Error parsing data or bad permissions" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.get_userdevices(userid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def __get_userTransitiveMemberOf(self, userid, user_roles, user_groups, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid + "/transitiveMemberOf"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            transitivememberof_data = json.loads(response.content.decode('utf-8'))
            for transitivememberof in transitivememberof_data["value"]:
                if transitivememberof["@odata.type"] == "#microsoft.graph.group":
                    user_groups.append(transitivememberof["displayName"])
                elif transitivememberof["@odata.type"] == "#microsoft.graph.directoryRole":
                    user_roles.append(transitivememberof["displayName"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_userTransitiveMemberOf(userid, user_roles, user_groups, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def get_users(self, nextlink=None, exit=False):
        if not self.allinfo and self.search is None:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --search or --all have to be defined"  + Format.END)
        else:
            search_id = False
            if nextlink is not None:
                url = nextlink
            elif self.allinfo:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all users" + Format.END)
                url = "https://graph.microsoft.com/v1.0/users?$top=999&$nextLink"
            else:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading users [" + self.search + "]" + Format.END)
                if re.match('^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$',self.search.lower()):
                    url = 'https://graph.microsoft.com/v1.0/users/' + self.search + "?$select=id,userPrincipalName,mail,mobilePhone,onPremisesSamAccountName,OnPremisesImmutableId,displayName,accountEnabled,identities,lastPasswordChangeDateTime"
                    search_id = True
                else:
                    url = 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail,mobilePhone,onPremisesSamAccountName,OnPremisesImmutableId,displayName,accountEnabled,identities,lastPasswordChangeDateTime&$search="userPrincipalName:' + self.search + '" OR "mobilePhone:' + self.search + '" OR "displayName:' + self.search + '" OR "mail:' + self.search +'"&$orderby=displayName&$top=999&$nextLink'
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                users_data = json.loads(response.content.decode('utf-8'))
                if "@odata.nextLink" in users_data:
                    self.get_users(users_data["@odata.nextLink"])
                elif search_id:
                    users_data = {"value":[users_data]}
                for user in users_data["value"]:
                    self.data.append(user)
                    print('\n' + Format.BOLD_START + Format.YELLOW + user["displayName"] + Format.END )
                    print(Format.CYAN + " UserId: " + Format.END + user["id"])
                    print(Format.CYAN + " UserPrincipalName: " + Format.END + str(user["userPrincipalName"]))
                    if "onPremisesSamAccountName" in user:
                        print(Format.CYAN + " OnPremisesSamAccountName: " + Format.END + str(user["onPremisesSamAccountName"]))
                    if "onPremisesImmutableId" in user:
                        print(Format.CYAN + " ImmutableId: " + Format.END + str(user["onPremisesImmutableId"]))
                    if "accountEnabled" in user:
                        print(Format.CYAN + " Enabled: " + Format.END + str(user["accountEnabled"]))
                    print(Format.CYAN + " Mail: " + Format.END + str(user["mail"]))
                    print(Format.CYAN + " MobilePhone: " + Format.END + str(user["mobilePhone"]))
                    if "lastPasswordChangeDateTime" in user:
                        print(Format.CYAN + " LastPasswordChange: " + Format.END + str(user["lastPasswordChangeDateTime"]))
                    if not self.allinfo:
                        print(Format.CYAN + " Devices: " + Format.END)
                        self.get_userdevices(user["id"])
                    if "identities" in user:
                        print(Format.CYAN + " Identities: " + Format.END)
                        for identity in user["identities"]:
                            print(Format.PURPLE + "  ["+ str(identity["signInType"]) + "] " + Format.END +  str(identity["issuerAssignedId"]) + " (" + str(identity["issuer"]) + ")")
                    if not self.allinfo:
                        user_roles = []
                        user_groups = []
                        self.__get_userTransitiveMemberOf(user["id"], user_roles,user_groups)
                        print(Format.CYAN + " Roles: " + Format.END + ', '.join(user_roles))
                        print(Format.CYAN + " Groups: " + Format.END + ', '.join(user_groups))
                if self.allinfo and nextlink is None:
                    users_file = time.strftime("%Y%m%d-%H%M%S") + "_users.json"
                    self.__dump_users(users_file)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.get_users(nextlink, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        
    def add_user(self, displayName, mailNickname, userPrincipalName, password, exit=False):
        url = "https://graph.microsoft.com/v1.0/users"
        body = {
          "accountEnabled": True,
          "displayName": displayName,
          "mailNickname": mailNickname,
          "userPrincipalName": userPrincipalName,
          "passwordProfile" : {
            "forceChangePasswordNextSignIn": False,
            "password": password
          }
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            print(Format.BOLD_START + Format.GREEN + "\n[+] User added!" + Format.END)
            response_parse = json.loads(response.content.decode('utf-8'))
            print('\n' + Format.BOLD_START + Format.YELLOW + response_parse["displayName"] + Format.END)
            print(Format.CYAN + " UserId: " + Format.END + response_parse["id"])
            print(Format.CYAN + " UserPrincipalName: " + Format.END + response_parse["userPrincipalName"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_user(displayName, mailNickname, userPrincipalName, password, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_user(self, userid, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] User removed!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_user(userid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_guest(self, email, sendemail, tenantid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/invitations'
        body = {
            "invitedUserEmailAddress": email,
            "invitedUserType": "Guest",
            "sendInvitationMessage": sendemail,
            "inviteRedirectUrl": "https://account.activedirectory.windowsazure.com/?tenantid=" + tenantid + "&login_hint=" + email
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            invitation_data = json.loads(response.content.decode('utf-8'))
            if sendemail:
                print(Format.BOLD_START + Format.GREEN + "\n[+] Tenant invitation email sent!" + Format.END)
            else:
                print(Format.BOLD_START + Format.GREEN + "\n[+] Invitation created!" + Format.END)
            print(print(Format.CYAN + " Invitation URL: " + Format.END + invitation_data["inviteRedeemUrl"]))
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_guest(email, sendemail, tenantid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_newpassword(self, userid, newpassword, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid
        body = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": newpassword
                }
            }
        response = self.request.do_request(self.auth.graph_access_token, url, "PATCH", body)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Password updated!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_new_password(userid, newpassword, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_identity(self, userid, email, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid + "?$select=identities"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            identities_data = json.loads(response.content.decode('utf-8'))
            new_identity = {
            "signInType": "federated",
            "issuer": "mail",
            "issuerAssignedId": email
            }
            identities_data["identities"].append(new_identity)
            body = {
            "identities": identities_data["identities"]
            }
            response = self.request.do_request(self.auth.graph_access_token, url, "PATCH", body)
            if response.status_code == 204:
                print(Format.BOLD_START + Format.GREEN + "\n[+] Updated user identities!" + Format.END)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_identity(userid, email, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_identity(self, userid, email, exit=False):
        url = "https://graph.microsoft.com/v1.0/users/" + userid + "?$select=identities"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            identities_data = json.loads(response.content.decode('utf-8'))
            identities_list = []
            for identity in identities_data["identities"]:
                if identity["issuerAssignedId"] != email:
                    identities_list.append(identity)
            body = {
                "identities": identities_list
            }
            response = self.request.do_request(self.auth.graph_access_token, url, "PATCH", body)
            if response.status_code == 204:
                print(Format.BOLD_START + Format.GREEN + "\n[+] Updated user identities!" + Format.END)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_identity(userid, email, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)