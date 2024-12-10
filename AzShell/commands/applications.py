import json, re, os, time
from AzShell.utils.constants import Format, Permissions

class Applications:
    
    def __init__(self, auth, request, search, allinfo):
        self.auth = auth
        self.request = request
        self.search = search
        self.allinfo = allinfo
        self.data = []

    def __dump_applications(self, file):
        base_dir = os.path.expanduser("~/.AzShell/Applications/")
        os.makedirs(base_dir, exist_ok=True)
        apps_path = os.path.join(base_dir, file)
        f = open(apps_path, "w")
        json.dump(self.data, f)
        print(Format.GREEN + "\n[+] Full information saved in " + apps_path + Format.END)
        f.close()  

    def __get_applicationowners(self, appid, exit=False):
        url = "https://graph.microsoft.com/v1.0/applications/" + appid + "/owners"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            owners_data = json.loads(response.content.decode('utf-8'))
            for owner in owners_data["value"]:
                self.data.append(owner)
                print("  " + owner["displayName"] + " [" + owner["id"] + "]")
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_applicationowners(appid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def __get_serviceprincipalowners(self, serviceprincipalid, exit=False):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals/" + serviceprincipalid + "/owners"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            owners_data = json.loads(response.content.decode('utf-8'))
            for owner in owners_data["value"]:
                self.data.append(owner)
                print("  " + owner["displayName"] + " [" + owner["id"] + "]")
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_serviceprincipalowners(serviceprincipalid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def __get_approleassignments(self, appid, exit=False):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='{" + appid + "}')/appRoleAssignments"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            approles_data = json.loads(response.content.decode('utf-8'))
            for approle in approles_data["value"]:
                self.data.append(approle)
                msgraph_roles = {}
                for msgraphrole in self.auth.msgraphdata["appRoles"]:
                    msgraph_roles[msgraphrole["id"]] = msgraphrole["value"]
                if approle["appRoleId"] in msgraph_roles:
                    print(Format.PURPLE + "  [Application] " + Format.END + msgraph_roles[approle["appRoleId"]])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_approleassignments(appid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def __get_delegated_permissions(self, clientid, exit=False):
        url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/?$filter=clientId eq '" + clientid + "'"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            dpermissions_data = json.loads(response.content.decode('utf-8'))
            for dpermission in dpermissions_data["value"]:
                self.data.append(dpermission)
                if dpermission["resourceId"] == self.auth.msgraphdata["id"]:
                    for parse_dpermission in dpermission["scope"].split(" "):
                        print(Format.PURPLE + "  [Delegated] " + Format.END + parse_dpermission)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_delegated_permissions(clientid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def get_apps(self, exit=False):
        if not self.allinfo and self.search is None:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --search or --all have to be defined"  + Format.END)
        else:
            search_id = False
            if self.allinfo:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all applications" + Format.END)
                url = "https://graph.microsoft.com/v1.0/applications"
            else:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading applications [" + self.search + "]" + Format.END)
                if re.match('^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$',self.search.lower()):
                    url = 'https://graph.microsoft.com/v1.0/applications/' + self.search + '?$orderby=displayName'
                    search_id = True
                else:
                    url = 'https://graph.microsoft.com/v1.0/applications?$search="displayName:' + self.search + '" OR "publisherDomain:' + self.search + '" OR "identifierUris:' + self.search + '" OR "appId:' + self.search + '"&$orderby=displayName'
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                applications_data = json.loads(response.content.decode('utf-8'))
                if search_id:
                    applications_data = {"value":[applications_data]}
                for application in applications_data["value"]:
                    self.data.append(application)
                    print('\n' + Format.BOLD_START + Format.YELLOW + application["displayName"] + Format.END)
                    print(Format.CYAN + " ObjectId: " + Format.END + application["id"])
                    print(Format.CYAN + " AppId: " + Format.END + application["appId"])
                    print(Format.CYAN + " CreatedDateTime: " + Format.END + str(application["createdDateTime"]))
                    print(Format.CYAN + " PublisherDomain: " + Format.END + str(application["publisherDomain"]))
                    print(Format.CYAN + " ApplicationRoles: " + Format.END)
                    for approles in application["appRoles"]:
                        print("  " + approles["displayName"] + ": " + approles["description"] + " (Origin: " + approles["origin"] + ", isEnabled: " + str(approles["isEnabled"]) + ") [" + approles["id"] +"]")
                    print(Format.CYAN + " KeyCredentials: " + Format.END + str(application["keyCredentials"]))
                    print(Format.CYAN + " PasswordCredentials: " + Format.END)
                    for passwordcredentials in application["passwordCredentials"]:
                        print("  " + str(passwordcredentials["displayName"]) + ": " + str(passwordcredentials["hint"]) + "***** " + "(startDateTime: " + str(passwordcredentials["startDateTime"]) + ", endDateTime: " + str(passwordcredentials["endDateTime"]) + ") [" + str(passwordcredentials["keyId"]) +"]")
                    print(Format.CYAN + " Owners: " + Format.END)
                    self.__get_applicationowners(application["id"])
                if self.allinfo:
                    applications_file = time.strftime("%Y%m%d-%H%M%S") + "_applications.json"
                    self.__dump_applications(applications_file)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.get_apps(True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def get_serviceprincipals(self, exit=False):
        if not self.allinfo and self.search is None:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --search or --all have to be defined"  + Format.END)
        else:
            search_id = False
            if self.allinfo:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all service principals" + Format.END)
                url = "https://graph.microsoft.com/v1.0/serviceprincipals"
            else:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading service principals [" + self.search + "]" + Format.END)
                if re.match('^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$',self.search.lower()):
                    url = 'https://graph.microsoft.com/v1.0/serviceprincipals/' + self.search + '?$orderby=displayName'
                    search_id = True
                else:
                    url = 'https://graph.microsoft.com/v1.0/serviceprincipals?$search="displayName:' + self.search + '" OR "appId:' + self.search + '"&$orderby=displayName'
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                serviceprincipals_data = json.loads(response.content.decode('utf-8'))
                if search_id:
                    serviceprincipals_data = {"value":[serviceprincipals_data]}
                for serviceprincipal in serviceprincipals_data["value"]:
                    self.data.append(serviceprincipal)
                    print('\n' + Format.BOLD_START + Format.YELLOW + serviceprincipal["displayName"] + Format.END)
                    print(Format.CYAN + " ObjectId: " + Format.END + serviceprincipal["id"])
                    print(Format.CYAN + " AppId: " + Format.END + serviceprincipal["appId"])
                    print(Format.CYAN + " Description: " + Format.END + str(serviceprincipal["description"]))
                    print(Format.CYAN + " CreatedDateTime: " + Format.END + str(serviceprincipal["createdDateTime"]))
                    print(Format.CYAN + " Alternative Names: " + Format.END + str(serviceprincipal["alternativeNames"]))
                    print(Format.CYAN + " Application roles: " + Format.END)
                    for approles in serviceprincipal["appRoles"]:
                        print("  " + approles["displayName"] + ": " + approles["description"] + " (Origin: " + approles["origin"] + ", isEnabled: " + str(approles["isEnabled"]) + ") [" + approles["id"] +"]")
                    print(Format.CYAN + " Key credentials: " + Format.END + str(serviceprincipal["keyCredentials"]))
                    print(Format.CYAN + " Password credentials: " + Format.END)
                    for passwordcredentials in serviceprincipal["passwordCredentials"]:
                        print("  " + str(passwordcredentials["displayName"]) + ": " + str(passwordcredentials["hint"]) + "***** " + "(startDateTime: " + str(passwordcredentials["startDateTime"]) + ", endDateTime: " + str(passwordcredentials["endDateTime"]) + ") [" + str(passwordcredentials["keyId"]) +"]")
                    print(Format.CYAN + " Permissions: " + Format.END)
                    self.__get_approleassignments(serviceprincipal["appId"])
                    self.__get_delegated_permissions(serviceprincipal["id"])
                    print(Format.CYAN + " Owners: " + Format.END)
                    self.__get_serviceprincipalowners(serviceprincipal["id"])
                if self.allinfo:
                    serviceprincipals_file = time.strftime("%Y%m%d-%H%M%S") + "_serviceprincipals.json"
                    self.__dump_applications(serviceprincipals_file)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.get_serviceprincipals(True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def get_apps_privesc(self, nextlink=None, exit=False):
        if nextlink is None:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Applications with interesting permissions" + Format.END)
            url = "https://graph.microsoft.com/v1.0/servicePrincipals?$expand=appRoleAssignments&$top=999&$nextLink"
        else:
            url = nextlink
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            serviceprincipals_data = json.loads(response.content.decode('utf-8'))
            if "@odata.nextLink" in serviceprincipals_data:
                self.get_apps_privesc(serviceprincipals_data["@odata.nextLink"])
            for serviceprincipal in serviceprincipals_data["value"]:
                approleassignments = []
                for roleassignments in serviceprincipal["appRoleAssignments"]:
                    if roleassignments["appRoleId"] in Permissions.INTERESTING_APP_PERMISSIONS:
                        approleassignments.append(Format.PURPLE + "\n  [Application] " + Format.END + Permissions.INTERESTING_APP_PERMISSIONS[roleassignments["appRoleId"]])
                if approleassignments:
                    print('\n' + Format.BOLD_START + Format.YELLOW + serviceprincipal["appDisplayName"] + Format.END)
                    print(Format.CYAN + " AppId: " + Format.END + serviceprincipal["appId"])
                    print(Format.CYAN + " Service Principal ID: " + Format.END + serviceprincipal["id"])
                    print(Format.CYAN + " Permissions: " + Format.END + ''.join(approleassignments))
                    print(Format.CYAN + " Owners:" + Format.END)
                    self.__get_serviceprincipalowners(serviceprincipal["id"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.get_apps_privesc(nextlink, True)
        else:
            if("Your request is throttled temporarily" in response.content or "Too many requests" in response.content):
                time.sleep(21)

    def add_application(self, name, exit=False):
        url = "https://graph.microsoft.com/v1.0/applications"
        body = {
            'displayName':name
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Application added!" + Format.END)
            response_parse = json.loads(response.content.decode('utf-8'))
            print('\n' + Format.BOLD_START + Format.YELLOW + response_parse["displayName"] + Format.END)
            print(Format.CYAN + " ObjectId: " + Format.END + response_parse["id"])
            print(Format.CYAN + " AppId: " + Format.END + response_parse["appId"])
            print(Format.CYAN + " Description: " + Format.END + str(response_parse["description"]))
            print(Format.CYAN + " CreatedDateTime: " + Format.END + str(response_parse["createdDateTime"]))
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_application(name, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_serviceprincipal(self, appid, exit=False):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        body = {
            'appId':appid
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Service principal added!" + Format.END)
            response_parse = json.loads(response.content.decode('utf-8'))
            print('\n' + Format.BOLD_START + Format.YELLOW + response_parse["appDisplayName"] + Format.END)
            print(Format.CYAN + " ObjectId: " + Format.END + response_parse["id"])
            print(Format.CYAN + " AppId: " + Format.END + response_parse["appId"])
            print(Format.CYAN + " Description: " + Format.END + str(response_parse["description"]))
            print(Format.CYAN + " CreatedDateTime: " + Format.END + str(response_parse["createdDateTime"]))
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_serviceprincipal(appid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_serviceprincipalsecret(self, serviceprincipalid, secretname, exit=False):
        url = "https://graph.microsoft.com/v1.0/serviceprincipals/" + serviceprincipalid + "/addPassword"
        body = {
            'passwordCredential':{'displayName':secretname}
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 200:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Secret added!" + Format.END)
            response_parse = json.loads(response.content.decode('utf-8'))
            print('\n' + Format.BOLD_START + Format.YELLOW + response_parse["displayName"] + Format.END)
            print(Format.CYAN + " Password: " + Format.END + response_parse["secretText"])
            print(Format.CYAN + " KeyId: " + Format.END + response_parse["keyId"])
            print(Format.CYAN + " StartDateTime: " + Format.END + response_parse["startDateTime"])
            print(Format.CYAN + " EndDateTime: " + Format.END + response_parse["endDateTime"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_serviceprincipalsecret(serviceprincipalid, secretname, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_application(self, appid, exit=False):
        url = "https://graph.microsoft.com/v1.0/applications/" + appid
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Application removed!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_application(appid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
            
    def del_serviceprincipal(self, serviceprincipalid, exit=False):
        url = "https://graph.microsoft.com/v1.0/serviceprincipals/" + serviceprincipalid
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Service principal removed!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_serviceprincipal(serviceprincipalid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_serviceprincipalsecret(self, serviceprincipalid, keyid, exit=False):
        url = "https://graph.microsoft.com/v1.0/serviceprincipals/" + serviceprincipalid + "/removePassword"
        body = {
            'keyId':keyid
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Secret removed!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_serviceprincipalsecret(serviceprincipalid, keyid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_appsecret(self, appid, secretname, exit=False):
        url = "https://graph.microsoft.com/v1.0/applications(appId='{" + appid + "}')/addPassword"
        body = {
            'passwordCredential':{'displayName':secretname}
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 200:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Secret added!" + Format.END)
            response_parse = json.loads(response.content.decode('utf-8'))
            print('\n' + Format.BOLD_START + Format.YELLOW + response_parse["displayName"] + Format.END)
            print(Format.CYAN + " Password: " + Format.END + response_parse["secretText"])
            print(Format.CYAN + " KeyId: " + Format.END + response_parse["keyId"])
            print(Format.CYAN + " StartDateTime: " + Format.END + response_parse["startDateTime"])
            print(Format.CYAN + " EndDateTime: " + Format.END + response_parse["endDateTime"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_appsecret(appid, secretname, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_appsecret(self, appid, keyid, exit=False):
        url = "https://graph.microsoft.com/v1.0/applications(appId='{" + appid + "}')/removePassword"
        body = {
            'keyId':keyid
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Secret removed!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_appsecret(appid, keyid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_approleassignment(self, serviceprincipalid, resourceid, approleid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + serviceprincipalid + '/appRoleAssignedTo'
        body = {
            'principalId':serviceprincipalid,
            'resourceId':resourceid,
            'appRoleId':approleid
        }
        response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
        if response.status_code == 201:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Application role assignment granted!" + Format.END)
            response_parse = json.loads(response.content.decode('utf-8'))
            print('\n' + Format.BOLD_START + Format.YELLOW + response_parse["principalDisplayName"] + Format.END)
            print(Format.CYAN + " AppRoleAssignmentId: " + Format.END + response_parse["id"])
            print(Format.CYAN + " ResourceDisplayName: " + Format.END + response_parse["resourceDisplayName"])
            print(Format.CYAN + " PermissionId: " + Format.END + response_parse["appRoleId"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.add_approleassignment(serviceprincipalid, resourceid, approleid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
            
    def del_approleassignment(self, serviceprincipalid, approleassignmentid, exit=False):
        url = 'https://graph.microsoft.com/v1.0/servicePrincipals/' + serviceprincipalid + '/appRoleAssignedTo/' + approleassignmentid
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(Format.BOLD_START + Format.GREEN + "\n[+] Application role assignment removed!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_approleassignment(serviceprincipalid, approleassignmentid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)