import os, msal, json, base64, datetime
from AzShell.utils.constants import Format, Permissions

class Auth:

    authority_url = 'https://login.microsoftonline.com/'
    graph_scope = ["https://graph.microsoft.com/.default"]
    arm_scope = ["https://management.azure.com/.default"]
    vault_scope = ["https://vault.azure.net/.default"]
    tokengraph_file = ".token_graph_data"
    tokenarm_file = ".token_arm_data"

    def __init__(self, request, tenantid, upn, clientid, password, graph_access_token=None, graph_refresh_token=None):
        self.request = request
        self.graph_access_token = graph_access_token
        self.graph_refresh_token = graph_refresh_token
        self.arm_access_token = None
        self.arm_refresh_token = None
        self.vault_access_token = None
        self.vault_refresh_token = None
        self.msgraphdata = None
        self.graph_context = None
        self.arm_context = None
        self.tenantid = tenantid
        self.upn = upn
        self.clientid = clientid
        self.password = password

    def __dump_tokendata(self, scope, token_owner, tokendata):
        base_dir = os.path.expanduser("~/.AzShell/")
        os.makedirs(base_dir, exist_ok=True)
        if scope == self.arm_scope:
            token_file = os.path.join(base_dir, self.tokenarm_file)
        else:
            token_file = os.path.join(base_dir, self.tokengraph_file)
        f = open(token_file, "w")
        tokendata['token_owner'] = token_owner
        json.dump(tokendata, f)
        f.close()
        print(f"{Format.GREEN}\n[+] Tokendata saved in {token_file}")

    def cache_tokendata(self):
        base_dir = os.path.expanduser("~/.AzShell/")
        tokengraph_file = os.path.join(base_dir, self.tokengraph_file)
        if os.path.isfile(tokengraph_file):
            f_graph = open(tokengraph_file, "r")
            tokencache = json.load(f_graph)
            f_graph.close()
            if self.upn == tokencache["token_owner"] or self.clientid == tokencache["token_owner"]:
                use_cache = True
                if "error_description" in tokencache:
                    print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: [{tokencache['error_description']}] {Format.END}")
                    exit()
                if "id_token_claims" in tokencache:
                    if self.clientid is not None and self.clientid != tokencache["id_token_claims"]["aud"]:
                        use_cache = False
                if use_cache:
                    if "access_token" in tokencache:
                        self.graph_access_token = tokencache["access_token"]
                    if "refresh_token" in tokencache:
                        self.graph_refresh_token = tokencache["refresh_token"]
        tokenarm_file = os.path.join(base_dir, self.tokenarm_file)
        if os.path.isfile(tokenarm_file):
            f_arm = open(tokenarm_file, "r")
            tokencache = json.load(f_arm)
            f_arm.close()
            if self.upn == tokencache["token_owner"] or self.clientid == tokencache["token_owner"]:
                use_cache = True
                if "error_description" in tokencache:
                    print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: [{tokencache['error_description']}] {Format.END}")
                    exit()
                if "id_token_claims" in tokencache:
                    if self.clientid is not None and self.clientid != tokencache["id_token_claims"]["aud"]:
                        use_cache = False
                if use_cache:
                    if "access_token" in tokencache:
                        self.arm_access_token = tokencache["access_token"]
                    if "refresh_token" in tokencache:
                        self.arm_refresh_token = tokencache["refresh_token"]

    def __request_token_by_username_password(self, scope):
        if self.clientid is not None:
            client_id = self.clientid
        else:
            client_id = "1950a258-227b-4e31-a9cf-717495945fc2"
        msal_app = msal.PublicClientApplication(
            client_id,
            authority = self.authority_url + self.tenantid
            )
        flow = msal_app.initiate_device_flow(scopes=scope)
        if "error" in flow:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: [{flow['error_description']}] {Format.END}")
            exit()
        else:
            print(f"{Format.BOLD_START}\n{flow['message']} {Format.END}")
            tokendata = msal_app.acquire_token_by_device_flow(flow)
            if "access_token" in tokendata:
                if scope == self.graph_scope:
                    self.graph_access_token = tokendata["access_token"]
                    self.graph_refresh_token = tokendata["refresh_token"]
                else:
                    self.arm_access_token = tokendata["access_token"]
                    self.arm_refresh_token = tokendata["refresh_token"]
                self.__dump_tokendata(scope, self.upn, tokendata)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: [{tokendata['error_description']}] {Format.END}")
                exit()

    def __request__token_by_refresh_token(self, refresh_token, scope):
        if self.clientid is not None:
            client_id = self.clientid
        else:
            client_id = "1950a258-227b-4e31-a9cf-717495945fc2"
        msal_app = msal.PublicClientApplication(
            client_id,
            authority = self.authority_url+self.tenantid
            )
        tokendata = msal_app.acquire_token_by_refresh_token(refresh_token=refresh_token, scopes=scope)
        if "access_token" in tokendata:
            if scope == self.graph_scope:
                self.graph_access_token = tokendata["access_token"]
                self.graph_refresh_token = tokendata["refresh_token"]
                self.upn = tokendata["id_token_claims"]["preferred_username"]
                self.__dump_tokendata(scope, self.upn, tokendata)
            elif scope == self.arm_scope:
                self.arm_access_token = tokendata["access_token"]
                self.arm_refresh_token = tokendata["refresh_token"]
                self.__dump_tokendata(scope, self.upn, tokendata)
            else:
                self.vault_access_token = tokendata["access_token"]
                self.vault_refresh_token = tokendata["refresh_token"]
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: [{tokendata['error_description']}] {Format.END}")

    def __request_token_for_client(self, scope):
        msal_app = msal.ConfidentialClientApplication(
            client_id = self.clientid,
            client_credential = self.password,
            authority = self.authority_url+self.tenantid
            )
        tokendata = msal_app.acquire_token_for_client(scopes=scope)
        if "access_token" in tokendata:
            if scope == self.graph_scope:
                self.graph_access_token = tokendata["access_token"]
                self.__dump_tokendata(scope, self.clientid, tokendata)
            elif scope == self.arm_scope:
                self.arm_access_token = tokendata["access_token"]
                self.__dump_tokendata(scope, self.clientid, tokendata)
            else:
                self.vault_access_token = tokendata["access_token"]
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Error: [{tokendata['error_description']}] {Format.END}")
            exit()

    def __create_user_context_graph(self, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{self.upn}?$select=id,userPrincipalName,onPremisesSamAccountName,displayName,lastPasswordChangeDateTime&$expand=transitiveMemberOf"
        response = self.request.do_request(self.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            self.get_msgraph_data()
            response_parse = json.loads(response.content.decode('utf-8'))
            self.graph_context = f"{Format.CYAN} Name: {Format.END}{response_parse['displayName']}\n"
            self.graph_context += f"{Format.CYAN} UserId: {Format.END}{response_parse['id']}\n"
            self.graph_context += f"{Format.CYAN} UserPrincipalName: {Format.END}{response_parse['userPrincipalName']}\n"
            if "onPremisesSamAccountName" in response_parse:
                self.graph_context += f"{Format.CYAN} OnPremisesSamAccountName: {Format.END}{response_parse['onPremisesSamAccountName']}\n"
            if "lastPasswordChangeDateTime" in response_parse:
                self.graph_context += f"{Format.CYAN} LastPasswordChange: {Format.END}{response_parse['lastPasswordChangeDateTime']}\n"
            if self.msgraphdata is not None:
                self.graph_context += f"{Format.CYAN} ObjectId (MSGraph): {Format.END}{self.msgraphdata['id']}\n"
            groups_count = 0
            roles_count = 0
            assigned_roles = ""
            for transitivememberof in response_parse["transitiveMemberOf"]:
                if transitivememberof["@odata.type"] == "#microsoft.graph.group":
                    groups_count += 1
                elif transitivememberof["@odata.type"] == "#microsoft.graph.directoryRole":
                    roles_count += 1
                    if transitivememberof["roleTemplateId"] in Permissions.INTERESTING_DIRECTORY_ROLE:
                        assigned_roles += f"  {Permissions.INTERESTING_DIRECTORY_ROLE[transitivememberof['roleTemplateId']]} \n"
                    else:
                        assigned_roles += f"  {transitivememberof['displayName']} \n"
            self.graph_context += f"{Format.CYAN} Roles: {Format.END}{roles_count}\n"
            if assigned_roles:
                self.graph_context += assigned_roles
            self.graph_context += f"{Format.CYAN} Groups: {Format.END}{groups_count}\n"
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one... {Format.END}")
            self.request_token("graph")
            if not exit:
                self.__create_user_context_graph(True)

    def __create_context_arm(self, exit=False):
        url = "https://management.azure.com/subscriptions?api-version=2021-01-01"
        response = self.request.do_request(self.arm_access_token, url, "GET", None)
        if response.status_code == 200:
            subscription_data = json.loads(response.content.decode('utf-8'))
            subscription_count = 0
            for subscription in subscription_data["value"]:
                subscription_count += 1
            self.arm_context = f"{Format.CYAN} Subscription: {Format.END}{subscription_count}"
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one... {Format.END}")
            self.request_token("arm")
            if not exit:
                self.__create_context_arm(True)

    def __create_user_context(self):
        if self.graph_access_token is not None:
            self.__create_user_context_graph()
        if self.arm_access_token is not None:
            self.__create_context_arm()
        print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Auth context{Format.END}")
        print(f'\n{Format.BOLD_START}{Format.YELLOW}{self.upn}{Format.END}')
        output_context = ""
        if self.graph_context is not None:
            output_context += self.graph_context
        if self.arm_context is not None:
            output_context += self.arm_context
        print(output_context)
            
    def __create_client_context_graph(self, exit=False):
        url = f"https://graph.microsoft.com/v1.0/servicePrincipals(appId='{self.clientid}')?$expand=appRoleAssignments"
        response_serviceprincipal = self.request.do_request(self.graph_access_token, url, "GET", None)
        if response_serviceprincipal.status_code == 200:
            self.get_msgraph_data()
            response_serviceprincipal_parse = json.loads(response_serviceprincipal.content.decode('utf-8'))
            self.graph_context = f"{Format.CYAN} Name: {Format.END}{response_serviceprincipal_parse['appDisplayName']}\n"
            self.graph_context += f"{Format.CYAN} ObjectId (ServicePrincipal): {Format.END}{response_serviceprincipal_parse['id']}\n"
            if self.msgraphdata is not None:
                self.graph_context += f"{Format.CYAN} ObjectId (MSGraph): {Format.END}{self.msgraphdata['id']}\n"
            self.graph_context += f"{Format.CYAN} Permissions: {Format.END}\n"
            url = f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/?$filter=clientId eq '{response_serviceprincipal_parse['id']}'"
            response_delegatedroles = self.request.do_request(self.graph_access_token, url, "GET", None)
            if response_delegatedroles.status_code == 200:
                response_parse_delegatedroles = json.loads(response_delegatedroles.content.decode('utf-8'))
                msgraph_roles = {}
                if self.msgraphdata["appRoles"]:
                    for msgraphrole in self.msgraphdata["appRoles"]:
                        msgraph_roles[msgraphrole["id"]] = msgraphrole["value"]
                    for approle in response_serviceprincipal_parse["appRoleAssignments"]:
                        if approle["appRoleId"] in msgraph_roles:
                            if approle["appRoleId"] in Permissions.INTERESTING_APP_PERMISSIONS:
                                self.graph_context += f"{Format.PURPLE}  [Application] {Format.END}{Permissions.INTERESTING_APP_PERMISSIONS[approle['appRoleId']]} \n"
                            else:
                                self.graph_context += f"{Format.PURPLE}  [Application] {Format.END}{msgraph_roles[approle['appRoleId']]} \n"
                    for delegatedrole in response_parse_delegatedroles["value"]:
                        if delegatedrole["resourceId"] == self.msgraphdata["id"]:
                            for parse_delegatedrole in delegatedrole["scope"].split(" "):
                                self.graph_context += Format.PURPLE + "  [Delegated] " + Format.END + parse_delegatedrole + "\n"

        elif response_serviceprincipal.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one... {Format.END}")
            self.request_token("graph")
            if not exit:
                self.__create_client_context_graph(True)

    def __create_client_context(self):
        if self.graph_access_token is not None:
            self.__create_client_context_graph()
        if self.arm_access_token is not None:
            self.__create_context_arm()
        print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Auth context{Format.END}")
        print(f"\n{Format.BOLD_START}{Format.YELLOW}{self.clientid}{Format.END}")
        output_context = ""
        if self.graph_context is not None:
            output_context += self.graph_context
        if self.arm_context is not None:
            output_context += self.arm_context
        print(output_context)

    def __jwt_parse(self, token):
        token_parts = token.split(".")
        jwt_payload_bytes = base64.urlsafe_b64decode(token_parts[1] + '=' * (-len(token_parts[1]) % 4))
        return json.loads(jwt_payload_bytes.decode("utf-8"))

    def __create_accesstoken_context(self):
        print(f"{Format.BOLD_START}{Format.BLUE}[*] Auth context{Format.END}")
        jwt_payload = self.__jwt_parse(self.graph_access_token)
        if "upn" in jwt_payload.keys():
            print(f'\n{Format.BOLD_START}{Format.YELLOW}{jwt_payload["upn"]}{Format.END}')
            print(f"{Format.CYAN} AppName: {Format.END}{str(jwt_payload['app_displayname'] if 'app_displayname' in jwt_payload.keys() else None)}")
        elif "app_displayname" in jwt_payload.keys():
            print(f'\n{Format.BOLD_START}{Format.YELLOW}{jwt_payload["app_displayname"]}{Format.END}')
        print(f"{Format.CYAN} AppId: {Format.END}{str(jwt_payload['appid'] if 'appid' in jwt_payload.keys() else None)}")
        print(f"{Format.CYAN} Resource (aud): {Format.END}{jwt_payload['aud']}")
        print(f"{Format.CYAN} Expiration Date: {Format.END}{str(datetime.datetime.fromtimestamp(jwt_payload['exp']).strftime('%A, %d %B %Y %H:%M:%S'))}")
        if "roles" in jwt_payload:
            if jwt_payload["roles"] is not None:
                print(f"{Format.CYAN} Permissions: {Format.END}{', '.join(jwt_payload['roles']) if 'roles' in jwt_payload else None}")
        if self.msgraphdata is not None:
            print(f"{Format.CYAN} ObjectId (MSGraph): {Format.END}{str(self.msgraphdata['id'])}")

    def request_token(self, api):
        if api == "graph":
            if self.graph_refresh_token is not None:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Requesting a new Graph token using refresh token...{Format.END}")
                self.__request__token_by_refresh_token(self.graph_refresh_token, self.graph_scope)
                if self.graph_access_token is None:
                    print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Refresh token expired, requesting a new one...{Format.END}")
                    self.__request_token_by_username_password(self.graph_scope)
            elif self.upn is None:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Requesting a new Graph token using client credentials...{Format.END}")
                self.__request_token_for_client(self.graph_scope)
            else:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Requesting a new Graph token...{Format.END}")
                self.__request_token_by_username_password(self.graph_scope)
        elif api == "arm":
            if self.arm_refresh_token is not None:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Requesting a new ARM token using refresh token...{Format.END}")
                self.__request__token_by_refresh_token(self.arm_refresh_token, self.arm_scope)
                if self.arm_access_token is None:
                    print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Refresh token expired, requesting a new one...{Format.END}")
                    self.__request_token_by_username_password(self.arm_scope)
            elif self.graph_refresh_token is not None:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Requesting a new ARM token using Graph refresh token...{Format.END}")
                self.__request__token_by_refresh_token(self.graph_refresh_token, self.arm_scope)
                if self.arm_access_token is None:
                    print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Invalid refresh token, requesting a new ARM token...{Format.END}")
                    self.__request_token_by_username_password(self.arm_scope)
            elif self.clientid is not None:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Requesting a new ARM token...{Format.END}")
                self.__request_token_for_client(self.arm_scope)
            else:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Requesting a new ARM token...{Format.END}")
                self.__request_token_by_username_password(self.arm_scope)
        else:
            if self.arm_refresh_token is not None:
                self.__request__token_by_refresh_token(self.arm_refresh_token, self.vault_scope)
                if self.vault_access_token is None and self.graph_refresh_token is not None:
                    self.__request__token_by_refresh_token(self.graph_refresh_token, self.arm_scope)
                    if self.arm_access_token is None:
                        self.__request_token_by_username_password(self.arm_scope)
                    else:
                        self.__request__token_by_refresh_token(self.arm_refresh_token, self.vault_scope)
            elif self.clientid is not None:
                self.__request_token_for_client(self.vault_scope)

    def create_context(self):
        if self.upn is not None:
            self.__create_user_context()
        elif self.clientid is not None:
            self.__create_client_context()
        elif self.graph_access_token is not None:
            self.__create_accesstoken_context()
        elif self.graph_refresh_token is not None:
            self.__create_user_context()

    def check_context(self):
        if self.graph_context is None and self.arm_context is None:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Error creating context [UPN not found in the tenant, Access token invalid or no permissions]{Format.END}")

    def get_msgraph_data(self):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'"
        response = self.request.do_request(self.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            self.msgraphdata = json.loads(response.content.decode('utf-8'))["value"][0]
            return "Success"
        else:
            return response.content.decode('utf-8')

    def get_tokens(self, renew):
        if renew:
            self.request_token("graph")
            self.request_token("arm")
        if self.graph_access_token is not None:
            print(f'\n{Format.BOLD_START}{Format.YELLOW}GRAPH API (https://graph.microsoft.com){Format.END}')
            jwt_payload = self.__jwt_parse(self.graph_access_token)
            print(f'\n{Format.CYAN} Access Token [Valid until {str(datetime.datetime.fromtimestamp(jwt_payload["exp"]).strftime("%A, %d %B %Y %H:%M:%S"))}]: {Format.END}{str(self.graph_access_token)}')
            print(f'\n{Format.CYAN} Refresh Token: {Format.END}{str(self.graph_refresh_token)}')
        if self.arm_access_token is not None:
            print(f'\n{Format.BOLD_START}{Format.YELLOW}ARM API (https://management.azure.com){Format.END}')
            jwt_payload = self.__jwt_parse(self.arm_access_token)
            print(f'\n{Format.CYAN} Access Token [Valid until {str(datetime.datetime.fromtimestamp(jwt_payload["exp"]).strftime("%A, %d %B %Y %H:%M:%S"))}]: {Format.END}{str(self.arm_access_token)}')
            print(f'\n{Format.CYAN} Refresh Token: {Format.END}{str(self.arm_refresh_token)}')
        if self.vault_access_token is not None:
            print(f'\n{Format.BOLD_START}{Format.YELLOW}VAULT API (https://vault.azure.net){Format.END}')
            jwt_payload = self.__jwt_parse(self.vault_access_token)
            print(f'\n{Format.CYAN} Access Token [Valid until {str(datetime.datetime.fromtimestamp(jwt_payload["exp"]).strftime("%A, %d %B %Y %H:%M:%S"))}]: {Format.END}{str(self.vault_access_token)}')
            print(f'\n{Format.CYAN} Refresh Token: {Format.END}{str(self.vault_refresh_token)}')