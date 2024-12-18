import json
from AzShell.commands.users import Users
from AzShell.utils.constants import Format, Permissions

class Roles:

    def __init__(self, auth, request):
        self.auth = auth
        self.request = request
        self.data = []

    def __get_rolemembers(self, roleTemplateId, privesc=False, exit=False):
        if privesc:
            users = Users(self.auth, self.request, None, None)
        url = "https://graph.microsoft.com/beta/directoryRoles/roleTemplateId=" + roleTemplateId + "/members"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            members_data = json.loads(response.content.decode('utf-8'))
            for member in members_data["value"]:
                self.data.append(member)
                if member["@odata.type"] == "#microsoft.graph.user":
                    print( Format.BOLD_START + Format.BLUE + " [User] " + Format.END + Format.CYAN + member["displayName"] + ": " +  Format.END + str(member["userPrincipalName"]) + " [" + member["id"] + "]")
                    if privesc:
                        users.get_userdevices(member["id"])
                elif member["@odata.type"] == "#microsoft.graph.group":
                    print( Format.BOLD_START + Format.BLUE + " [Group] " + Format.END + Format.CYAN + member["displayName"] + ": " +  Format.END + str(member["description"]) + " [" + member["id"] + "]")
                elif member["@odata.type"] == "#microsoft.graph.servicePrincipal":
                    print( Format.BOLD_START + Format.BLUE + " [ServicePrincipal] " + Format.END + Format.CYAN + member["displayName"] +  Format.END + " [" + member["id"] + "]")
                else:
                    print( Format.BOLD_START + Format.BLUE + " [Other] " + Format.END + Format.CYAN + member["displayName"] +  Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_rolemembers(roleTemplateId, privesc, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def get_roles(self, privesc=False, exit=False):
        if privesc:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Interesting role members" + Format.END)
        else:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all roles" + Format.END)
        url = "https://graph.microsoft.com/v1.0/directoryRoles"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            roles_data = json.loads(response.content.decode('utf-8'))
            for role in roles_data["value"]:
                if privesc:
                    if role["roleTemplateId"] in Permissions.INTERESTING_DIRECTORY_ROLE:
                        print('\n' + Format.BOLD_START + Format.YELLOW + role["displayName"] + " [" + role["roleTemplateId"] + "]" + Format.END)
                        self.__get_rolemembers(role["roleTemplateId"], True)
                else:
                    print('\n' + Format.BOLD_START + Format.YELLOW + role["displayName"] + " [" + role["roleTemplateId"] + "]" + Format.END)
                    self.__get_rolemembers(role["roleTemplateId"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.get_roles(privesc, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
    
    def add_rolemember(self, userid, roleid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=' + roleid + '/members/$ref'
        body = {
            '@odata.id':'https://graph.microsoft.com/v1.0/directoryObjects/' + userid
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] User added to role!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_rolemember(userid, roleid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
            
    def del_rolemember(self, userid, roleid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=' + roleid + '/members/' + userid + '/$ref'
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] User removed to role!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_rolemember(userid, roleid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def __get_role_definition(self, roleDefinitionId, exit=False):
            url = "https://management.azure.com/" + roleDefinitionId + "?api-version=2022-04-01"
            response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
            if response.status_code == 200:
                roledefinition_data = json.loads(response.content.decode('utf-8'))
                print(Format.CYAN + " Role: " + Format.END + roledefinition_data["properties"]["roleName"])
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("arm")
                if not exit:
                    self.__get_role_definition(roleDefinitionId, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def __get_by_ids(self, principalId, exit=False):
        url = "https://graph.microsoft.com/v1.0/directoryObjects/microsoft.graph.getByIds"
        body = {
            'ids': principalId
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 200:
            ids_data = json.loads(response.content.decode('utf-8'))
            namedic = {}
            for ids in ids_data["value"]:
                namedic[ids["id"]] = ids["displayName"]
            return namedic
        elif response.status_code == 403:
            return None
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_by_ids(principalId, True)
            return None
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)
            return None

    def get_rbac(self, subscriptionId, exit=False):
        if self.auth.arm_access_token is not None:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading Azure RBAC assignment info" + Format.END)
            url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
            if response.status_code == 200:
                roleassignments_data = json.loads(response.content.decode('utf-8'))
                for roleassignment in roleassignments_data["value"]:
                    idlist = []
                    idlist.append(str(roleassignment["properties"]["principalId"]))
                    idlist.append(str(roleassignment["properties"]["createdBy"]))
                    namedic = self.__get_by_ids(idlist)
                    if namedic is not None:
                        if str(roleassignment["properties"]["principalId"]) in namedic:
                            print('\n' + Format.BOLD_START + Format.YELLOW + "[" + str(roleassignment["properties"]["principalType"]) + "] " + namedic[str(roleassignment["properties"]["principalId"])] + Format.END)
                        else:
                            print('\n' + Format.BOLD_START + Format.YELLOW + "[" + str(roleassignment["properties"]["principalType"]) + "] " + str(roleassignment["properties"]["principalId"]) + Format.END)
                    else:
                            print('\n' + Format.BOLD_START + Format.YELLOW + "[" + str(roleassignment["properties"]["principalType"]) + "] " + str(roleassignment["properties"]["principalId"]) + Format.END)
                    self.__get_role_definition(roleassignment["properties"]["roleDefinitionId"])
                    if namedic is not None:
                        if str(roleassignment["properties"]["createdBy"]) in namedic:
                            print(Format.CYAN + " CreatedBy: " + Format.END + namedic[str(roleassignment["properties"]["createdBy"])])
                        else:
                            print(Format.CYAN + " CreatedBy: " + Format.END + str(roleassignment["properties"]["createdBy"]))
                    else:
                            print(Format.CYAN + " CreatedBy: " + Format.END + str(roleassignment["properties"]["createdBy"]))
                    print(Format.CYAN + " Scope: " + Format.END + str(roleassignment["properties"]["scope"]))
                    print(Format.CYAN + " CreatedOn: " + Format.END + str(roleassignment["properties"]["createdOn"]))
                    print(Format.CYAN + " UpdatedOn: " + Format.END + str(roleassignment["properties"]["updatedOn"]))
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("arm")
                if not exit:
                    self.get_rbac(subscriptionId, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] No access token requested for ARM API" + Format.END)