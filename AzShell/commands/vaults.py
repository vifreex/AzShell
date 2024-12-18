import json, re
from AzShell.utils.constants import Format

class Vaults():
    def __init__(self, auth, request, search):
        self.auth = auth
        self.request = request
        self.search = search

    def __get_vault_secrets(self, vaulturl, exit=False):
        if self.auth.vault_access_token is not None:
            url = f"{vaulturl}/secrets?api-version=7.3"
            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
            if response.status_code == 200:
                secrets_data = json.loads(response.content.decode('utf-8'))
                for i, secret in enumerate(secrets_data["value"]):
                    print(f"{Format.PURPLE}  [Secret {i+1}] {Format.END} {str(secret['id']).split('/')[-1]} (Enabled:{str(secret['attributes']['enabled'])}, Created:{str(secret['attributes']['created'])}, Updated:{str(secret['attributes']['updated'])}) [{str(secret['id'])}]")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n  [!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("vault")
                if not exit:
                    self.__get_vault_secrets(vaulturl, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')}{Format.END}")
        else:
            self.auth.request_token("vault")
            if not exit:
                self.__get_vault_secrets(vaulturl, True)

    def __get_vault_keys(self, vaulturl, exit=False):
        if self.auth.vault_access_token is not None:
            url = f"{vaulturl}/keys?api-version=7.3"
            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
            if response.status_code == 200:
                keys_data = json.loads(response.content.decode('utf-8'))
                for i, key in enumerate(keys_data["value"]):
                    print(f"{Format.PURPLE}  [Key {i+1}] {Format.END} {str(key['kid']).split('/')[-1]} (Enabled:{str(key['attributes']['enabled'])}, Created:{str(key['attributes']['created'])}, Updated:{str(key['attributes']['updated'])}, Exportable:{str(key['attributes']['exportable'])}) [{str(key['kid'])}]")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n  [!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("vault")
                if not exit:
                    self.__get_vault_keys(vaulturl, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')}{Format.END}")
        else:
            self.auth.request_token("vault")
            if not exit:
                self.__get_vault_keys(vaulturl, True)

    def get_vaults(self, subscriptionId, exit=False):
        if self.auth.arm_access_token is not None:
            if self.search is None:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading vault info{Format.END}")
                url = f"https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
            else:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading vault info [{self.search}]{Format.END}")
                url = f"https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?$filter={self.search}&api-version=2022-07-01"
            response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
            if response.status_code == 200:
                vaults_data = json.loads(response.content.decode('utf-8'))
                for vault in vaults_data["value"]:
                    print(f'\n{Format.BOLD_START}{Format.YELLOW}{vault["name"]}{Format.END}')
                    print(f"{Format.CYAN} VirtualMachineId: {Format.END} {vault['id']}")
                    print(f"{Format.CYAN} Type: {Format.END} {str(vault['type'])}")
                    resourceGroup = re.search(r'/resourceGroups/([^/]+)/', vault["id"]).group(1)
                    print(f"{Format.CYAN} Resource Group: {Format.END} {str(resourceGroup)}")
                    print(f"{Format.CYAN} Last Modified By: {Format.END} {str(vault['systemData']['lastModifiedBy'])}")
                    print(f"{Format.CYAN} Last Modified At: {Format.END} {str(vault['systemData']['lastModifiedAt'])}")
                    if "networkAcls" in vault["properties"].keys():
                        print(f"{Format.CYAN} Network ACLs: {Format.END}")
                        print(f"{Format.PURPLE}  [DefaultAction]: {Format.END} {str(vault['properties']['networkAcls']['defaultAction'])}")
                        print(f"{Format.PURPLE}  [IP Rules]: {Format.END} {str(vault['properties']['networkAcls']['ipRules'])}")
                        print(f"{Format.PURPLE}  [Virtual Network Rules]: {Format.END} {str(vault['properties']['networkAcls']['virtualNetworkRules'])}")
                    print(f"{Format.CYAN} EnableRbacAuthorizationt: {Format.END} {str(vault['properties']['enableRbacAuthorization'])}")
                    print(f"{Format.CYAN} PublicNetworkAccess URL: {Format.END} {str(vault['properties']['publicNetworkAccess'])}")
                    print(f"{Format.CYAN} Vault URL: {Format.END} {str(vault['properties']['vaultUri'])}")
                    print(f"{Format.CYAN} Secrets: {Format.END}")
                    self.__get_vault_secrets(str(vault["properties"]["vaultUri"]))
                    print(f"{Format.CYAN} Keys: {Format.END}")
                    self.__get_vault_keys(str(vault["properties"]["vaultUri"]))

            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("arm")
                if not exit:
                    self.get_vaults(subscriptionId, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] No access token requested for ARM API{Format.END}")

    def get_vaultsecrets(self, vaulturl, secretname, allsecrets, exit=False):
        if self.auth.vault_access_token is not None:
            if secretname is None and not allsecrets:
                print(f"{Format.BOLD_START}{Format.YELLOW}\n[!] At least --secretname or --all have to be defined{Format.END}")
            else:
                if allsecrets:
                    print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading all secrets{Format.END}")
                    url = f"{vaulturl}/secrets?api-version=7.3"
                else:
                    print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading secret [{secretname}]{Format.END}")
                    url = f"{vaulturl}/secrets/{secretname}?api-version=7.3"
                response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                if response.status_code == 200:
                    secrets_data = json.loads(response.content.decode('utf-8'))
                    if allsecrets:
                        for i, secret in enumerate(secrets_data["value"]):
                            name = str(secret["id"]).split('/')[-1]
                            url = f"{vaulturl}/secrets/{name}?api-version=7.3"
                            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                            if response.status_code == 200:
                                secretvalue = json.loads(response.content.decode('utf-8'))
                                print(f"{Format.PURPLE}  [Secret {i+1}] {Format.END} {name}:{secretvalue['value']} (Enabled:{str(secret['attributes']['enabled'])}, Created:{str(secret['attributes']['created'])}, Updated:{str(secret['attributes']['updated'])}) [{str(secret['id'])}]")
                            elif response.status_code == 403:
                                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
                            elif response.status_code == 401:
                                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                                self.auth.request_token("vault")
                                if not exit:
                                    self.get_vaultsecrets(vaulturl, secretname, allsecrets, True)
                            else:
                                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
                    else:
                        print(f'\n{Format.BOLD_START}{Format.YELLOW}{secretname}{Format.END}')
                        print(f"{Format.CYAN} Secret value: {Format.END} {str(secrets_data['value'])}")
                        print(f"{Format.CYAN} Enabled: {Format.END} {str(secrets_data['attributes']['enabled'])}")
                        print(f"{Format.CYAN} Created: {Format.END} {str(secrets_data['attributes']['created'])}")
                        print(f"{Format.CYAN} Updated: {Format.END} {str(secrets_data['attributes']['updated'])}")
                        print(f"{Format.CYAN} RecoveryLevel: {Format.END} {str(secrets_data['attributes']['recoveryLevel'])}")
                        print(f"{Format.CYAN} Recoverable Days: {Format.END} {str(secrets_data['attributes']['recoverableDays'])}")
                elif response.status_code == 403:
                    print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
                elif response.status_code == 401:
                    print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                    self.auth.request_token("vault")
                    if not exit:
                        self.get_vaultsecrets(vaulturl, secretname, allsecrets, True)
                else:
                    print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
        else:
            self.auth.request_token("vault")
            if not exit:
                self.get_vaultsecrets(vaulturl, secretname, allsecrets, True)

    def get_vaultkeys(self, vaulturl, keyname, allkeys, exit=False):
        if self.auth.vault_access_token is not None:
            if keyname is None and not allkeys:
                print(f"{Format.BOLD_START}{Format.YELLOW}\n[!] At least --keyname or --all have to be defined{Format.END}")
            else:
                if allkeys:
                    print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading all keys{Format.END}")
                    url = f"{vaulturl}/keys?api-version=7.3"
                else:
                    print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading key [{keyname}]{Format.END}")
                    url = f"{vaulturl}/keys/{keyname}?api-version=7.3"
                response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                if response.status_code == 200:
                    keys_data = json.loads(response.content.decode('utf-8'))
                    if allkeys:
                        for i, key in enumerate(keys_data["value"]):
                            name = str(key["kid"]).split('/')[-1]
                            url = f"{vaulturl}/keys/{name}?api-version=7.3"
                            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                            if response.status_code == 200:
                                keyvalue = json.loads(response.content.decode('utf-8'))
                                print(f"{Format.PURPLE}  [Key {i+1}] {Format.END} {name} (n: {keyvalue['key']['n']}, e: {keyvalue['key']['e']}, Enabled:{str(key['attributes']['enabled'])}, Created:{str(key['attributes']['created'])}, Updated:{str(key['attributes']['updated'])}) [{str(key['kid'])}]")
                            elif response.status_code == 403:
                                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
                            elif response.status_code == 401:
                                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                                self.auth.request_token("vault")
                                if not exit:
                                    self.get_vaultkeys(vaulturl, keyname, allkeys, True)
                            else:
                                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
                    else:
                        print(f'\n{Format.BOLD_START}{Format.YELLOW}{keyname}{Format.END}')
                        print(f"{Format.CYAN} Key ID: {Format.END} {str(keys_data['key']['kid'])}")
                        print(f"{Format.CYAN} Key Type: {Format.END} {str(keys_data['key']['kty'])}")
                        print(f"{Format.CYAN} Key Operations: {Format.END} {str(keys_data['key']['key_ops'])}")
                        print(f"{Format.CYAN} Modulus (n): {Format.END} {str(keys_data['key']['n'])}")
                        print(f"{Format.CYAN} Exponent (e): {Format.END} {str(keys_data['key']['e'])}")
                        print(f"{Format.CYAN} Enabled: {Format.END} {str(keys_data['attributes']['enabled'])}")
                        print(f"{Format.CYAN} Created: {Format.END} {str(keys_data['attributes']['created'])}")
                        print(f"{Format.CYAN} Updated: {Format.END} {str(keys_data['attributes']['updated'])}")
                        print(f"{Format.CYAN} RecoveryLevel: {Format.END} {str(keys_data['attributes']['recoveryLevel'])}")
                        print(f"{Format.CYAN} Recoverable Days: {Format.END} {str(keys_data['attributes']['recoverableDays'])}")
                elif response.status_code == 403:
                    print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
                elif response.status_code == 401:
                    print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                    self.auth.request_token("vault")
                    if not exit:
                        self.get_vaultkeys(vaulturl, keyname, allkeys, True)
                else:
                    print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
        else:
            self.auth.request_token("vault")
            if not exit:
                self.get_vaultkeys(vaulturl, keyname, allkeys, True)
