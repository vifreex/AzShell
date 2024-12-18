import json, re, time, os
from AzShell.utils.constants import Format

class Policies:
    
    def __init__(self, auth, request, search, allinfo):
        self.auth = auth
        self.request = request
        self.search = search
        self.allinfo = allinfo

    def __dump_policies(self, policies_file):
        base_dir = os.path.expanduser("~/.AzShell/Policies/")
        os.makedirs(base_dir, exist_ok=True)
        policies_path = os.path.join(base_dir, policies_file)
        f = open(policies_path, "w")
        json.dump(self.data, f)
        print(Format.GREEN + "\n[+] Full policy information saved in " + policies_path + Format.END)
        f.close()   

    def __get_transitiveMembersSearch(self, groupid, userid, nextlink=None, exit=False):
        if nextlink is None:
            url = "https://graph.microsoft.com/v1.0/groups/" + groupid + "/transitiveMembers/microsoft.graph.user?$top=999&$nextLink"
        else:
            url = nextlink
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            transitiveMembers_data = json.loads(response.content.decode('utf-8'))
            for transitiveMember in transitiveMembers_data["value"]:
                if userid == transitiveMember["id"]:
                    return True
            if "@odata.nextLink" in transitiveMembers_data:
                    return self.__get_transitiveMembersSearch(groupid, userid, transitiveMembers_data["@odata.nextLink"])
            else:
                return False
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            return False
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_transitiveMembersSearch(groupid, userid, nextlink, True)
            return False
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
            return False

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

    def __get_roles(self, exit=False):
            url = "https://graph.microsoft.com/v1.0/directoryRoles"
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                roles_data = json.loads(response.content.decode('utf-8'))
                rolesdic = {}
                for role in roles_data["value"]:
                    rolesdic[role["roleTemplateId"]] = role["displayName"]
                return rolesdic
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.get_roles(True)
                return None
            else:
                return None

    def __get_rolemembers(self, roleid, userid, exit=False):
        url = "https://graph.microsoft.com/beta/directoryRoles/roleTemplateId=" + roleid + "/members"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            members_data = json.loads(response.content.decode('utf-8'))
            for member in members_data["value"]:
                if member["@odata.type"] == "#microsoft.graph.user":
                    if member["id"] == userid:
                        return True
                elif member["@odata.type"] == "#microsoft.graph.group":
                    if self.__get_transitiveMembersSearch(member["id"], userid):
                        return True
            return False
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
            return False
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.__get_rolemembers(roleid, userid, True)
            return False
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)
            return False

    def get_policies(self, userid, exit=False):
        if not self.allinfo and self.search is None and userid is None:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --search, --userid or --all have to be defined"  + Format.END)
        else:
            if self.allinfo:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all policies" + Format.END)
            elif self.search is not None:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading policies [" + self.search + "]" + Format.END)
            else:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading policies that apply to user " + userid + Format.END)
            url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                self.data = json.loads(response.content.decode('utf-8'))
                for policy in self.data["value"]:
                    print_policy = False
                    if self.allinfo:
                        print_policy = True
                    elif self.search is not None:
                        if self.search.lower() == policy["id"].lower():
                            print_policy = True
                        elif self.search.lower() in policy["displayName"].lower() and policy["state"] != "disabled":
                            print_policy = True
                    else: 
                        if 'All' in policy["conditions"]["users"]["includeUsers"] and policy["state"] != "disabled":
                            print_policy = True
                        elif userid in policy["conditions"]["users"]["includeUsers"] and policy["state"] != "disabled":
                            print_policy = True
                        else:
                            if policy["conditions"]["users"]["includeGroups"] and policy["state"] != "disabled":
                                for includeGroup in policy["conditions"]["users"]["includeGroups"]:
                                    if not print_policy:
                                        print_policy = self.__get_transitiveMembersSearch(includeGroup, userid)
                                    else:
                                        break
                            if policy["conditions"]["users"]["includeRoles"] and policy["state"] != "disabled":
                                for includeRole in policy["conditions"]["users"]["includeRoles"]:
                                    if not print_policy:
                                        print_policy = self.__get_rolemembers(includeRole, userid)
                                    else:
                                        break
                    if print_policy:
                        print('\n' + Format.BOLD_START + Format.YELLOW + policy["displayName"] + Format.END)
                        print(Format.CYAN + " PolicyId: " + Format.END + policy["id"])
                        print(Format.CYAN + " State: " + Format.END + str(policy["state"]))
                        print(Format.CYAN + " CreatedDateTime: " + Format.END + str(policy["createdDateTime"]))
                        print(Format.CYAN + " ModifiedDateTime: " + Format.END + str(policy["modifiedDateTime"]))
                        print(Format.CYAN + " Conditions: " + Format.END )
                        policylist = []
                        policydic = {}
                        roles = False
                        if policy["conditions"]["applications"]["includeApplications"]:
                            policylist += policy["conditions"]["applications"]["includeApplications"]
                            policydic['IncludeApplications'] = policy["conditions"]["applications"]["includeApplications"]
                        if policy["conditions"]["applications"]["excludeApplications"]:
                            policylist += policy["conditions"]["applications"]["excludeApplications"]
                            policydic['ExcludeApplications'] = policy["conditions"]["applications"]["excludeApplications"]
                        if policy["conditions"]["users"]["includeUsers"]:
                            policylist += policy["conditions"]["users"]["includeUsers"]
                            policydic['IncludeUsers'] = policy["conditions"]["users"]["includeUsers"]
                        if policy["conditions"]["users"]["excludeUsers"]:
                            policylist += policy["conditions"]["users"]["excludeUsers"]
                            policydic['ExcludeUsers'] = policy["conditions"]["users"]["excludeUsers"]
                        if policy["conditions"]["users"]["includeGroups"]:
                            policylist += policy["conditions"]["users"]["includeGroups"]
                            policydic['IncludeGroups'] = policy["conditions"]["users"]["includeGroups"]
                        if policy["conditions"]["users"]["excludeGroups"]:
                            policylist += policy["conditions"]["users"]["excludeGroups"]
                            policydic['ExcludeGroups'] = policy["conditions"]["users"]["excludeGroups"]
                        if policy["conditions"]["users"]["includeRoles"]:
                            roles = True
                            policylist += policy["conditions"]["users"]["includeRoles"]
                            policydic['IncludeRoles'] = policy["conditions"]["users"]["includeRoles"]
                        if policy["conditions"]["users"]["excludeRoles"]:
                            roles = True
                            policylist += policy["conditions"]["users"]["excludeRoles"]
                            policydic['excludeRoles'] = policy["conditions"]["users"]["ExcludeRoles"]
                        if policy["conditions"]["users"]["includeGuestsOrExternalUsers"]:
                            policylist += policy["conditions"]["users"]["includeGuestsOrExternalUsers"]
                            policydic['IncludeGuestsOrExternalUsers'] = policy["conditions"]["users"]["includeGuestsOrExternalUsers"]
                        if policy["conditions"]["users"]["excludeGuestsOrExternalUsers"]:
                            policylist += policy["conditions"]["users"]["excludeGuestsOrExternalUsers"]
                            policydic['ExcludeGuestsOrExternalUsers'] = policy["conditions"]["users"]["excludeGuestsOrExternalUsers"]
                        rolesdic = {}
                        if roles:
                            rolesdic = self.__get_roles()
                        idlist = []
                        for policyid in policylist:
                            if re.match('^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$',policyid.lower()):
                                idlist.append(policyid)
                        namedic = self.__get_by_ids(idlist)
                        for policyvalue in policydic:
                            print(Format.PURPLE + "  " + policyvalue + ": " + Format.END)
                            for policyelement in policydic[policyvalue]:
                                if policyelement in namedic:
                                    print("    " +  namedic[policyelement] + " [" + policyelement + "]")
                                elif policyelement in rolesdic:
                                    print("    " +  rolesdic[policyelement] + " [" + policyelement + "]")
                                else:
                                    print("    " +  policyelement)
                        if policy["grantControls"] is not None:
                            print(Format.PURPLE +"  GrantControls: " + Format.END)
                            if policy["grantControls"]["builtInControls"]:
                                print("    builtInControls: " + ",".join(policy["grantControls"]["builtInControls"]))
                            if policy["grantControls"]["customAuthenticationFactors"]:
                                print("    customAuthenticationFactors:" + ",".join(policy["grantControls"]["customAuthenticationFactors"]))
                            if policy["grantControls"]["authenticationStrength"]:
                                print("    authenticationStrength: ")
                                print("     " + policy["grantControls"]["authenticationStrength"]["displayName"] + " [" + policy["grantControls"]["authenticationStrength"]["id"] + "]")
                                if "requirementsSatisfied" in policy["grantControls"]["authenticationStrength"]:
                                    print("      requirementsSatisfied: " + policy["grantControls"]["authenticationStrength"]["requirementsSatisfied"])
                                if "allowedCombinations" in policy["grantControls"]["authenticationStrength"]:
                                    print("      allowedCombinations: " + str(policy["grantControls"]["authenticationStrength"]["allowedCombinations"]))
                        if policy["sessionControls"] is not None:
                            print(Format.PURPLE +"  SessionControls: " + Format.END)
                            print("    disableResilienceDefaults: " + str(policy["sessionControls"]["disableResilienceDefaults"]))
                            print("    applicationEnforcedRestrictions: " + str(policy["sessionControls"]["applicationEnforcedRestrictions"]))
                            print("    cloudAppSecurity: " + str(policy["sessionControls"]["cloudAppSecurity"]))
                            print("    persistentBrowser: " + str(policy["sessionControls"]["persistentBrowser"]))
                            print("    signInFrequency: " + str(policy["sessionControls"]["signInFrequency"]))
                if self.allinfo:
                    policies_file = time.strftime("%Y%m%d-%H%M%S") + "_policies.json"
                    self.__dump_policies(policies_file)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.get_policies(userid, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def add_excludeuserpolicy(self, policyid, userid, exit=False):
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/" + policyid
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            policy_data = json.loads(response.content.decode('utf-8'))
            if userid in policy_data["conditions"]["users"]["excludeUsers"]:
                print(Format.BOLD_START + Format.RED + "\n[!] The user is already added!" + Format.END)
            else:
                policy_data["conditions"]["users"]["excludeUsers"].append(userid)
                body = {
                "conditions": policy_data["conditions"]
                }
                response = self.request.do_request(self.auth.graph_access_token, url, "PATCH", body)
                if response.status_code == 204:
                    print(Format.BOLD_START + Format.GREEN + "\n[+] Updated policy, excluded user added!" + Format.END)
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
                self.add_excludeuserpolicy(policyid, userid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)

    def del_excludeuserpolicy(self, policyid, userid, exit=False):
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/" + policyid
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            policy_data = json.loads(response.content.decode('utf-8'))
            if userid in policy_data["conditions"]["users"]["excludeUsers"]:
                policy_data["conditions"]["users"]["excludeUsers"].remove(userid)
                body = {
                "conditions": policy_data["conditions"]
                }
                response = self.request.do_request(self.auth.graph_access_token, url, "PATCH", body)
                if response.status_code == 204:
                    print(Format.BOLD_START + Format.GREEN + "\n[+] Updated policy, excluded user deleted!" + Format.END)
                elif response.status_code == 403:
                    print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
                elif response.status_code == 401:
                    print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                    self.auth.request_token("graph")
                else:
                    print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] The specified user is not added to excluded users!" + Format.END)
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.del_excludeuserpolicy(policyid, userid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)