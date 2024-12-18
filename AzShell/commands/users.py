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
        with open(users_path, "w") as f:
            json.dump(self.data, f)
            print(f"{Format.GREEN}\n[+] Full user information saved in {users_path}{Format.END}")

    def get_userdevices(self, userid, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{userid}/ownedDevices"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            try:
                devices_data = json.loads(response.content.decode('utf-8'))
                for i, device in enumerate(devices_data["value"]):
                    self.data.append(device)
                    print(f"{Format.PURPLE}  [Device {i+1}] {Format.END}{device['displayName']} (LastSignInDate: {device['approximateLastSignInDateTime']}) [{device['id']}]")
            except:
                print(f"{Format.BOLD_START}{Format.RED}\n  [!] Error parsing data or bad permissions{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.get_userdevices(userid, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')}{Format.END}")

    def __get_userTransitiveMemberOf(self, userid, user_roles, user_groups, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{userid}/transitiveMemberOf"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            transitivememberof_data = json.loads(response.content.decode('utf-8'))
            for transitivememberof in transitivememberof_data["value"]:
                if transitivememberof["@odata.type"] == "#microsoft.graph.group":
                    user_groups.append(transitivememberof["displayName"])
                elif transitivememberof["@odata.type"] == "#microsoft.graph.directoryRole":
                    user_roles.append(transitivememberof["displayName"])
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.__get_userTransitiveMemberOf(userid, user_roles, user_groups, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')}{Format.END}")

    def get_users(self, nextlink=None, exit=False):
        if not self.allinfo and self.search is None:
            print(f"{Format.BOLD_START}{Format.YELLOW}\n[!] At least --search or --all have to be defined{Format.END}")
        else:
            search_id = False
            if nextlink is not None:
                url = nextlink
            elif self.allinfo:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading all users{Format.END}")
                url = "https://graph.microsoft.com/v1.0/users?$top=999&$nextLink"
            else:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading users [{self.search}]{Format.END}")
                if re.match('^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$', self.search.lower()):
                    url = f'https://graph.microsoft.com/v1.0/users/{self.search}?$select=id,userPrincipalName,mail,mobilePhone,onPremisesSamAccountName,OnPremisesImmutableId,displayName,accountEnabled,identities,lastPasswordChangeDateTime'
                    search_id = True
                else:
                    url = f'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail,mobilePhone,onPremisesSamAccountName,OnPremisesImmutableId,displayName,accountEnabled,identities,lastPasswordChangeDateTime&$search="userPrincipalName:{self.search}" OR "mobilePhone:{self.search}" OR "displayName:{self.search}" OR "mail:{self.search}"&$orderby=displayName&$top=999&$nextLink'
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                users_data = json.loads(response.content.decode('utf-8'))
                if "@odata.nextLink" in users_data:
                    self.get_users(users_data["@odata.nextLink"])
                elif search_id:
                    users_data = {"value": [users_data]}
                for user in users_data["value"]:
                    self.data.append(user)
                    print(f'\n{Format.BOLD_START}{Format.YELLOW}{user["displayName"]}{Format.END}')
                    print(f"{Format.CYAN} UserId: {Format.END}{user['id']}")
                    print(f"{Format.CYAN} UserPrincipalName: {Format.END}{user['userPrincipalName']}")
                    if "onPremisesSamAccountName" in user:
                        print(f"{Format.CYAN} OnPremisesSamAccountName: {Format.END}{user['onPremisesSamAccountName']}")
                    if "onPremisesImmutableId" in user:
                        print(f"{Format.CYAN} ImmutableId: {Format.END}{user['onPremisesImmutableId']}")
                    if "accountEnabled" in user:
                        print(f"{Format.CYAN} Enabled: {Format.END}{user['accountEnabled']}")
                    print(f"{Format.CYAN} Mail: {Format.END}{user['mail']}")
                    print(f"{Format.CYAN} MobilePhone: {Format.END}{user['mobilePhone']}")
                    if "lastPasswordChangeDateTime" in user:
                        print(f"{Format.CYAN} LastPasswordChange: {Format.END}{user['lastPasswordChangeDateTime']}")
                    if not self.allinfo:
                        print(f"{Format.CYAN} Devices: {Format.END}")
                        self.get_userdevices(user["id"])
                    if "identities" in user:
                        print(f"{Format.CYAN} Identities: {Format.END}")
                        for identity in user["identities"]:
                            print(f"{Format.PURPLE}  [{identity['signInType']}] {Format.END}{identity['issuerAssignedId']} ({identity['issuer']})")
                    if not self.allinfo:
                        user_roles = []
                        user_groups = []
                        self.__get_userTransitiveMemberOf(user["id"], user_roles, user_groups)
                        print(f"{Format.CYAN} Roles: {Format.END}{', '.join(user_roles)}")
                        print(f"{Format.CYAN} Groups: {Format.END}{', '.join(user_groups)}")
                if self.allinfo and nextlink is None:
                    users_file = f"{time.strftime('%Y%m%d-%H%M%S')}_users.json"
                    self.__dump_users(users_file)
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("graph")
                if not exit:
                    self.get_users(nextlink, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

        
    def add_user(self, displayName, mailNickname, userPrincipalName, password, exit=False):
        url = "https://graph.microsoft.com/v1.0/users"
        body = {
            "accountEnabled": True,
            "displayName": displayName,
            "mailNickname": mailNickname,
            "userPrincipalName": userPrincipalName,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": password
            }
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[+] User added!{Format.END}")
            response_parse = json.loads(response.content.decode('utf-8'))
            print(f"\n{Format.BOLD_START}{Format.YELLOW}{response_parse['displayName']}{Format.END}")
            print(f"{Format.CYAN} UserId: {Format.END}{response_parse['id']}")
            print(f"{Format.CYAN} UserPrincipalName: {Format.END}{response_parse['userPrincipalName']}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.add_user(displayName, mailNickname, userPrincipalName, password, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def del_user(self, userid, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{userid}"
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[+] User removed!{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.del_user(userid, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def add_guest(self, email, sendemail, tenantid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/invitations'
        body = {
            "invitedUserEmailAddress": email,
            "invitedUserType": "Guest",
            "sendInvitationMessage": sendemail,
            "inviteRedirectUrl": f"https://account.activedirectory.windowsazure.com/?tenantid={tenantid}&login_hint={email}"
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            invitation_data = json.loads(response.content.decode('utf-8'))
            if sendemail:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[+] Tenant invitation email sent!{Format.END}")
            else:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[+] Invitation created!{Format.END}")
            print(f"{Format.CYAN} Invitation URL: {Format.END}{invitation_data['inviteRedeemUrl']}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.add_guest(email, sendemail, tenantid, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def add_newpassword(self, userid, newpassword, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{userid}"
        body = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": newpassword
            }
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "PATCH", body)
        if response.status_code == 204:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[+] Password updated!{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.add_newpassword(userid, newpassword, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def add_identity(self, userid, email, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{userid}?$select=identities"
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
                print(f"{Format.BOLD_START}{Format.GREEN}\n[+] Updated user identities!{Format.END}")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("graph")
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.add_identity(userid, email, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def del_identity(self, userid, email, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{userid}?$select=identities"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            identities_data = json.loads(response.content.decode('utf-8'))
            identities_list = [identity for identity in identities_data["identities"] if identity["issuerAssignedId"] != email]
            body = {
                "identities": identities_list
            }
            response = self.request.do_request(self.auth.graph_access_token, url, "PATCH", body)
            if response.status_code == 204:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[+] Updated user identities!{Format.END}")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("graph")
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.del_identity(userid, email, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
