import json, re
from AzShell.utils.constants import Format

class Vaults():
    def __init__(self, auth, request, search):
        self.auth = auth
        self.request = request
        self.search = search

    def __get_vault_secrets(self, vaulturl, exit=False):
        if self.auth.vault_access_token is not None:
            url = vaulturl + "/secrets?api-version=7.3"
            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
            if response.status_code == 200:
                secrets_data = json.loads(response.content.decode('utf-8'))
                for i, secret in enumerate(secrets_data["value"]):
                    print(Format.PURPLE + "  [Secret " + str(i+1) + "] " + Format.END + str(secret["id"]).split('/')[-1] + " (Enabled:" + str(secret["attributes"]["enabled"]) + ", Created:" + str(secret["attributes"]["created"]) + ", Updated:" + str(secret["attributes"]["updated"]) + ") [" + str(secret["id"]) + "]")
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("vault")
                if not exit:
                    self.__get_vault_secrets(vaulturl, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)
        else:
            self.auth.request_token("vault")
            if not exit:
                self.__get_vault_secrets(vaulturl, True)

    def __get_vault_keys(self, vaulturl, exit=False):
        if self.auth.vault_access_token is not None:
            url = vaulturl + "/keys?api-version=7.3"
            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
            if response.status_code == 200:
                keys_data = json.loads(response.content.decode('utf-8'))
                for i, key in enumerate(keys_data["value"]):
                    print(Format.PURPLE + "  [Key " + str(i+1) + "] " + Format.END + str(key["kid"]).split('/')[-1] + " (Enabled:" + str(key["attributes"]["enabled"]) + ", Created:" + str(key["attributes"]["created"]) + ", Updated:" + str(key["attributes"]["updated"]) + ", Exportable:" + str(key["attributes"]["exportable"]) + ") [" + str(key["kid"]) + "]")
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("vault")
                if not exit:
                    self.__get_vault_keys(vaulturl, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)
        else:
            self.auth.request_token("vault")
            if not exit:
                self.__get_vault_keys(vaulturl, True)

    def get_vaults(self, subscriptionId, exit=False):
        if self.auth.arm_access_token is not None:
            if self.search is None:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading vault info" + Format.END)
                url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
            else:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading vault info [" + self.search + "]" + Format.END)
                url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.KeyVault/vaults?$filter=" + self.search + "&api-version=2022-07-01"
            response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
            if response.status_code == 200:
                vaults_data = json.loads(response.content.decode('utf-8'))
                for vault in vaults_data["value"]:
                    print('\n' + Format.BOLD_START + Format.YELLOW + vault["name"] + Format.END)
                    print(Format.CYAN + " VirtualMachineId: " + Format.END + vault["id"])
                    print(Format.CYAN + " Type: " + Format.END + str(vault["type"]))
                    resourceGroup = re.search(r'/resourceGroups/([^/]+)/', vault["id"]).group(1)
                    print(Format.CYAN + " Resource Group: " + Format.END + str(resourceGroup))
                    print(Format.CYAN + " Last Modified By: " + Format.END + str(vault["systemData"]["lastModifiedBy"]))
                    print(Format.CYAN + " Last Modified At: " + Format.END + str(vault["systemData"]["lastModifiedAt"]))
                    if "networkAcls" in vault["properties"].keys():
                        print(Format.CYAN + " Network ACLs: " + Format.END)
                        print(Format.PURPLE + "  [DefaultAction]: " + Format.END + str(vault["properties"]["networkAcls"]["defaultAction"]))
                        print(Format.PURPLE + "  [IP Rules]: " + Format.END + str(vault["properties"]["networkAcls"]["ipRules"]))
                        print(Format.PURPLE + "  [Virtual Network Rules]: " + Format.END + str(vault["properties"]["networkAcls"]["virtualNetworkRules"]))
                    print(Format.CYAN + " EnableRbacAuthorizationt: " + Format.END + str(vault["properties"]["enableRbacAuthorization"]))
                    print(Format.CYAN + " PublicNetworkAccess URL: " + Format.END + str(vault["properties"]["publicNetworkAccess"]))
                    print(Format.CYAN + " Vault URL: " + Format.END + str(vault["properties"]["vaultUri"]))
                    print(Format.CYAN + " Secrets: " + Format.END)
                    self.__get_vault_secrets(str(vault["properties"]["vaultUri"]))
                    print(Format.CYAN + " Keys: " + Format.END)
                    self.__get_vault_keys(str(vault["properties"]["vaultUri"]))

            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("arm")
                if not exit:
                    self.get_vaults(subscriptionId, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] No access token requested for ARM API" + Format.END)

    def get_vaultsecrets(self, vaulturl, secretname, allsecrets, exit=False):
        if self.auth.vault_access_token is not None:
            if secretname is None and not allsecrets:
                print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --secretname or --all have to be defined"  + Format.END)
            else:
                if allsecrets:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all secrets" + Format.END)
                    url = vaulturl + "/secrets?api-version=7.3"
                else:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading secret [" + secretname + "]" + Format.END)
                    url = vaulturl + "/secrets/" + secretname + "?api-version=7.3"
                response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                if response.status_code == 200:
                    secrets_data = json.loads(response.content.decode('utf-8'))
                    if allsecrets:
                        for i,secret in enumerate(secrets_data["value"]):
                            name = str(secret["id"]).split('/')[-1]
                            url = vaulturl + "/secrets/" + name + "?api-version=7.3"
                            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                            if response.status_code == 200:
                                secretvalue = json.loads(response.content.decode('utf-8'))
                                print(Format.PURPLE + "  [Secret " + str(i+1) + "] " + Format.END + name + ":" + secretvalue["value"] + " (Enabled:" + str(secret["attributes"]["enabled"]) + ", Created:" + str(secret["attributes"]["created"]) + ", Updated:" + str(secret["attributes"]["updated"]) + ") [" + str(secret["id"]) + "]")
                            elif response.status_code == 403:
                                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
                            elif response.status_code == 401:
                                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                                self.auth.request_token("vault")
                                if not exit:
                                    self.get_vaultsecrets(vaulturl, secretname, allsecrets, True)
                            else:
                                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
                    else:
                        print('\n' + Format.BOLD_START + Format.YELLOW + secretname + Format.END)
                        print(Format.CYAN + " Secret value: " + Format.END + str(secrets_data["value"]))
                        print(Format.CYAN + " Enabled: " + Format.END + str(secrets_data["attributes"]["enabled"]))
                        print(Format.CYAN + " Created: " + Format.END + str(secrets_data["attributes"]["created"]))
                        print(Format.CYAN + " Updated: " + Format.END + str(secrets_data["attributes"]["updated"]))
                        print(Format.CYAN + " RecoveryLevel: " + Format.END + str(secrets_data["attributes"]["recoveryLevel"]))
                        print(Format.CYAN + " Recoverable Days: " + Format.END + str(secrets_data["attributes"]["recoverableDays"]))
                elif response.status_code == 403:
                    print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
                elif response.status_code == 401:
                    print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                    self.auth.request_token("vault")
                    if not exit:
                        self.get_vaultsecrets(vaulturl, secretname, allsecrets, True)
                else:
                    print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        else:
            self.auth.request_token("vault")
            if not exit:
                self.get_vaultsecrets(vaulturl, secretname, allsecrets, True)

    def get_vaultkeys(self, vaulturl, keyname, allkeys, exit=False):
        if self.auth.vault_access_token is not None:
            if keyname is None and not allkeys:
                print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --keyname or --all have to be defined"  + Format.END)
            else:
                if allkeys:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all keys" + Format.END)
                    url = vaulturl + "/keys?api-version=7.3"
                else:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Reading key [" + keyname + "]" + Format.END)
                    url = vaulturl + "/keys/" + keyname + "?api-version=7.3"
                response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                if response.status_code == 200:
                    keys_data = json.loads(response.content.decode('utf-8'))
                    if allkeys:
                        for i,key in enumerate(keys_data["value"]):
                            name = str(key["kid"]).split('/')[-1]
                            url = vaulturl + "/keys/" + name + "?api-version=7.3"
                            response = self.request.do_request(self.auth.vault_access_token, url, "GET", None)
                            if response.status_code == 200:
                                keyvalue = json.loads(response.content.decode('utf-8'))
                                print(Format.PURPLE + "  [Key " + str(i+1) + "] " + Format.END + name + " (n: "+ keyvalue["key"]["n"] + ", e: " + keyvalue["key"]["e"] + ", Enabled:" + str(key["attributes"]["enabled"]) + ", Created:" + str(key["attributes"]["created"]) + ", Updated:" + str(key["attributes"]["updated"]) + ") [" + str(key["kid"]) + "]")
                            elif response.status_code == 403:
                                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
                            elif response.status_code == 401:
                                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                                self.auth.request_token("vault")
                                if not exit:
                                    self.get_vaultkeys(vaulturl, keyname, allkeys, True)
                            else:
                                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
                    else:
                        print('\n' + Format.BOLD_START + Format.YELLOW + keyname + Format.END)
                        print(Format.CYAN + " Key ID: " + Format.END + str(keys_data["key"]["kid"]))
                        print(Format.CYAN + " Key Type: " + Format.END + str(keys_data["key"]["kty"]))
                        print(Format.CYAN + " Key Operations: " + Format.END + str(keys_data["key"]["key_ops"]))
                        print(Format.CYAN + " Modulus (n): " + Format.END + str(keys_data["key"]["n"]))
                        print(Format.CYAN + " Exponent (e): " + Format.END + str(keys_data["key"]["e"]))
                        print(Format.CYAN + " Enabled: " + Format.END + str(keys_data["attributes"]["enabled"]))
                        print(Format.CYAN + " Created: " + Format.END + str(keys_data["attributes"]["created"]))
                        print(Format.CYAN + " Updated: " + Format.END + str(keys_data["attributes"]["updated"]))
                        print(Format.CYAN + " RecoveryLevel: " + Format.END + str(keys_data["attributes"]["recoveryLevel"]))
                        print(Format.CYAN + " Recoverable Days: " + Format.END + str(keys_data["attributes"]["recoverableDays"]))
                elif response.status_code == 403:
                    print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
                elif response.status_code == 401:
                    print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                    self.auth.request_token("vault")
                    if not exit:
                        self.get_vaultkeys(vaulturl, keyname, allkeys, True)
                else:
                    print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        else:
            self.auth.request_token("vault")
            if not exit:
                self.get_vaultkeys(vaulturl, keyname, allkeys, True)