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
        url = f"https://graph.microsoft.com/beta/directoryRoles/roleTemplateId={roleTemplateId}/members"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            members_data = json.loads(response.content.decode('utf-8'))
            for member in members_data["value"]:
                self.data.append(member)
                if member["@odata.type"] == "#microsoft.graph.user":
                    print(f"{Format.BOLD_START}{Format.BLUE} [User] {Format.END}{Format.CYAN}{member['displayName']}: {Format.END}{member['userPrincipalName']} [{member['id']}]")
                    if privesc:
                        users.get_userdevices(member["id"])
                elif member["@odata.type"] == "#microsoft.graph.group":
                    print(f"{Format.BOLD_START}{Format.BLUE} [Group] {Format.END}{Format.CYAN}{member['displayName']}: {Format.END}{member['description']} [{member['id']}]")
                elif member["@odata.type"] == "#microsoft.graph.servicePrincipal":
                    print(f"{Format.BOLD_START}{Format.BLUE} [ServicePrincipal] {Format.END}{Format.CYAN}{member['displayName']}{Format.END} [{member['id']}]")
                else:
                    print(f"{Format.BOLD_START}{Format.BLUE} [Other] {Format.END}{Format.CYAN}{member['displayName']}{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.__get_rolemembers(roleTemplateId, privesc, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')}{Format.END}")

    def get_roles(self, privesc=False, exit=False):
        if privesc:
            print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Interesting role members{Format.END}")
        else:
            print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading all roles{Format.END}")
        url = "https://graph.microsoft.com/v1.0/directoryRoles"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            roles_data = json.loads(response.content.decode('utf-8'))
            for role in roles_data["value"]:
                if privesc:
                    if role["roleTemplateId"] in Permissions.INTERESTING_DIRECTORY_ROLE:
                        print(f'\n{Format.BOLD_START}{Format.YELLOW}{role["displayName"]} [{role["roleTemplateId"]}]{Format.END}')
                        self.__get_rolemembers(role["roleTemplateId"], True)
                else:
                    print(f'\n{Format.BOLD_START}{Format.YELLOW}{role["displayName"]} [{role["roleTemplateId"]}]{Format.END}')
                    self.__get_rolemembers(role["roleTemplateId"])
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.get_roles(privesc, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def add_rolemember(self, userid, roleid, exit=False):
        url = f'https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId={roleid}/members/$ref'
        body = {
            '@odata.id': f'https://graph.microsoft.com/v1.0/directoryObjects/{userid}'
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 204:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[+] User added to role!{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.add_rolemember(userid, roleid, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

            
    def del_rolemember(self, userid, roleid, exit=False):
        url = f'https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId={roleid}/members/{userid}/$ref'
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[+] User removed to role!{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.del_rolemember(userid, roleid, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def __get_role_definition(self, roleDefinitionId, exit=False):
        url = f"https://management.azure.com/{roleDefinitionId}?api-version=2022-04-01"
        response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
        if response.status_code == 200:
            roledefinition_data = json.loads(response.content.decode('utf-8'))
            print(f"{Format.CYAN} Role: {Format.END}{roledefinition_data['properties']['roleName']}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("arm")
            if not exit:
                self.__get_role_definition(roleDefinitionId, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')}{Format.END}")

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
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.__get_by_ids(principalId, True)
            return None
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')}{Format.END}")
            return None

    def get_rbac(self, subscriptionId, exit=False):
        if self.auth.arm_access_token is not None:
            print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading Azure RBAC assignment info{Format.END}")
            url = f"https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
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
                            print(f'\n{Format.BOLD_START}{Format.YELLOW}[{str(roleassignment["properties"]["principalType"])}] {namedic[str(roleassignment["properties"]["principalId"])]}{Format.END}')
                        else:
                            print(f'\n{Format.BOLD_START}{Format.YELLOW}[{str(roleassignment["properties"]["principalType"])}] {str(roleassignment["properties"]["principalId"])}{Format.END}')
                    else:
                            print(f'\n{Format.BOLD_START}{Format.YELLOW}[{str(roleassignment["properties"]["principalType"])}] {str(roleassignment["properties"]["principalId"])}{Format.END}')
                    self.__get_role_definition(roleassignment["properties"]["roleDefinitionId"])
                    if namedic is not None:
                        if str(roleassignment["properties"]["createdBy"]) in namedic:
                            print(f"{Format.CYAN} CreatedBy: {Format.END}{namedic[str(roleassignment['properties']['createdBy'])]}")
                        else:
                            print(f"{Format.CYAN} CreatedBy: {Format.END}{str(roleassignment['properties']['createdBy'])}")
                    else:
                            print(f"{Format.CYAN} CreatedBy: {Format.END}{str(roleassignment['properties']['createdBy'])}")
                    print(f"{Format.CYAN} Scope: {Format.END}{str(roleassignment['properties']['scope'])}")
                    print(f"{Format.CYAN} RoleAssignmentId: {Format.END}{str(roleassignment['name'])}")
                    print(f"{Format.CYAN} CreatedOn: {Format.END}{str(roleassignment['properties']['createdOn'])}")
                    print(f"{Format.CYAN} UpdatedOn: {Format.END}{str(roleassignment['properties']['updatedOn'])}")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("arm")
                if not exit:
                    self.get_rbac(subscriptionId, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] No access token requested for ARM API{Format.END}")


    def add_rbac(self, principalid, roledefinitionid, scope, exit=False):
        if self.auth.arm_access_token is not None:
            url = f"https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleAssignments/{roledefinitionid}?api-version=2022-04-01"
            
            body = {
            "properties": {
                "roleDefinitionId": f"/{scope}/providers/Microsoft.Authorization/roleDefinitions/{roledefinitionid}",
                "principalId": principalid
                }
            }
            
            response = self.request.do_request(self.auth.arm_access_token, url, "PUT", body)
            if response.status_code == 201:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Role assigned successfully!{Format.END}")
                response_parse = json.loads(response.content.decode('utf-8'))
                print(f"{Format.CYAN} PrincipalId: {Format.END}{response_parse['properties']['principalId']}")
                print(f"{Format.CYAN} RoleDefinitionId: {Format.END}{roledefinitionid}")
                print(f"{Format.CYAN} ScopeId: {Format.END}{response_parse['properties']['scope']}")
                print(f"{Format.CYAN} RoleAssignmentId: {Format.END}{response_parse['name']}")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("arm")
                if not exit:
                    self.add_rbac(principalid, roledefinitionid, scope, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: {response.content.decode('utf-8')}{Format.END}")
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] No access token requested for ARM API{Format.END}")


    def del_rbac(self, roleassignmentid, scope, exit=False):
        if self.auth.arm_access_token is not None:
            url = f"https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleAssignments/{roleassignmentid}?api-version=2022-04-01"
            
            response = self.request.do_request(self.auth.arm_access_token, url, "DELETE", None)
            if response.status_code == 200:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Role removed successfully!{Format.END}")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("arm")
                if not exit:
                    self.del_rbac(roleassignmentid, scope, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: {response.content.decode('utf-8')}{Format.END}")
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] No access token requested for ARM API{Format.END}")
