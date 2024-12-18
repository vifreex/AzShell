import json, re, time
from AzShell.utils.constants import Format

class VMs():
    def __init__(self, auth, request, search):
        self.auth = auth
        self.request = request
        self.search = search

    def __get_public_ip_address(self, publicipid, exit=False):
        url = "https://management.azure.com/" + publicipid + "?api-version=2023-09-01"
        response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
        if response.status_code == 200:
            publicip_data = json.loads(response.content.decode('utf-8'))
            if "ipAddress" in publicip_data["properties"].keys():
                print(Format.PURPLE + "  [publicIPAddress]: " + Format.END + str(publicip_data["properties"]["ipAddress"]))
            if "dnsSettings" in publicip_data["properties"].keys():
                if "fqdn" in publicip_data["properties"]["dnsSettings"].keys():
                    print(Format.PURPLE + "  [FQDN]: " + Format.END + str(publicip_data["properties"]["dnsSettings"]["fqdn"]))
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("arm")
            if not exit:
                self.__get_public_ip_address(publicipid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def __get_instanceview(self, vmid, exit=False):
        url = "https://management.azure.com/" + vmid + "/instanceView?api-version=2024-03-01"
        response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
        if response.status_code == 200:
            instanceview_data = json.loads(response.content.decode('utf-8'))
            for status in instanceview_data["statuses"]:
                if "PowerState" in status["code"]:
                    print(Format.CYAN + " Status: " + Format.END + status["displayStatus"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("arm")
            if not exit:
                self.__get_instanceview(vmid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)


    def __get_network_interface(self, networkinterfaceid, exit=False):
        url = "https://management.azure.com/" + networkinterfaceid + "?api-version=2023-09-01"
        response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
        if response.status_code == 200:
            networkinterface_data = json.loads(response.content.decode('utf-8'))
            for ipConfigurations in networkinterface_data["properties"]["ipConfigurations"]:
                 print(Format.CYAN + " NetworkInterface: " + Format.END + str(ipConfigurations["name"]))
                 if "privateIPAddress" in ipConfigurations["properties"].keys():
                    print(Format.PURPLE + "  [privateIPAddress]: " + Format.END + str(ipConfigurations["properties"]["privateIPAddress"]))
                 if "publicIPAddress" in ipConfigurations["properties"].keys():
                    self.__get_public_ip_address(ipConfigurations["properties"]["publicIPAddress"]["id"])
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n  [!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("arm")
            if not exit:
                self.__get_network_interface(networkinterfaceid, True)
        else:
            print(Format.BOLD_START + Format.RED + "\n  [!] " + response.content.decode('utf-8') + Format.END)

    def get_vms(self, subscriptionId, resourcegroup, exit=False):
        if self.auth.arm_access_token is not None:
            if resourcegroup is None:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading virtual machine info" + Format.END)
                url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01"
            else:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading virtual machine info [" + resourcegroup + "]" + Format.END)
                url = "https://management.azure.com/subscriptions/" + subscriptionId + "/resourceGroups/"+ resourcegroup + "/providers/Microsoft.Compute/virtualMachines?api-version=2024-03-01"
            response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
            if response.status_code == 200:
                vms_data = json.loads(response.content.decode('utf-8'))
                for vm in vms_data["value"]:
                    print('\n' + Format.BOLD_START + Format.YELLOW + vm["name"] + Format.END)
                    print(Format.CYAN + " VirtualMachineId: " + Format.END + vm["id"])
                    print(Format.CYAN + " Type: " + Format.END + str(vm["type"]))
                    resourceGroup = re.search(r'/resourceGroups/([^/]+)/', vm["id"]).group(1)
                    print(Format.CYAN + " Resource Group: " + Format.END + str(resourceGroup))
                    self.__get_instanceview(vm["id"])
                    if "storageProfile" in vm["properties"].keys():
                        if "imageReference" in vm["properties"]["storageProfile"].keys():
                            print(Format.CYAN + " Offer: " + Format.END + str(vm["properties"]["storageProfile"]["imageReference"]["offer"]))
                            print(Format.CYAN + " Sku: " + Format.END + str(vm["properties"]["storageProfile"]["imageReference"]["sku"]))
                    if "osProfile" in vm["properties"].keys():
                        print(Format.CYAN + " Computer Name: " + Format.END + str(vm["properties"]["osProfile"]["computerName"]))
                        print(Format.CYAN + " Admin Username: " + Format.END + str(vm["properties"]["osProfile"]["adminUsername"]))
                    if "networkProfile" in vm["properties"].keys():
                        for networkinterface in vm["properties"]["networkProfile"]["networkInterfaces"]:
                            self.__get_network_interface(str(networkinterface["id"]))
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("arm")
                if not exit:
                    self.get_vms(subscriptionId, resourcegroup, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] No access token requested for ARM API" + Format.END)

    def get_vm_perms(self, subscriptionId, resourcegroup, vmname, exit=False):
            if self.auth.arm_access_token is not None:
                url = "https://management.azure.com/subscriptions/" + subscriptionId + "/resourceGroups/" + resourcegroup + "/providers/Microsoft.Compute/virtualMachines/" + vmname + "/providers/Microsoft.Authorization/permissions?api-version=2015-07-01"
                response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
                if response.status_code == 200:
                    vms_data = json.loads(response.content.decode('utf-8'))
                    print('\n' + Format.BOLD_START + Format.YELLOW + vmname + Format.END)
                    print(Format.CYAN + " Resource Group: " + Format.END + resourcegroup)
                    print(Format.CYAN + " Actions: " + Format.END)
                    for data in vms_data["value"]:
                        print(Format.PURPLE + "  {}".format(data["actions"]) + Format.END)
                elif response.status_code == 403:
                    print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
                elif response.status_code == 401:
                    print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                    self.auth.request_token("arm")
                    if not exit:
                        self.get_vm_perms(subscriptionId, resourcegroup, vmname, True)
                else:
                    print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] No access token requested for ARM API" + Format.END)

    def add_vmcommand(self, subscriptionId, resourceGroup, vmname, system, payloadfile, exit=False):
        if self.auth.arm_access_token is not None:
            url = "https://management.azure.com/subscriptions/" + subscriptionId + "/resourceGroups/" + resourceGroup +"/providers/Microsoft.Compute/virtualMachines/" + vmname + "/runCommand?api-version=2022-03-01"
            with open(payloadfile, "r") as file:
                payload = [line.strip() for line in file if line.strip()]
            if system.lower() == "windows":
                commandId = "RunPowerShellScript"
            elif system.lower() == "linux":
                commandId = "RunShellScript"
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] Invalid OS system" + Format.END)
                return
            body = {
                "commandId": commandId,
                "script": payload
            }
            response = self.request.do_request(self.auth.arm_access_token, url, "POST", body)
            if response.status_code == 202:
                if "Location" in response.headers and "Azure-Asyncoperation" in response.headers:
                    print(Format.BOLD_START + Format.BLUE + "\n[*] Executing script in virtual machine [" + vmname + "]" + Format.END)
                    azure_asyncoperation = response.headers["Azure-Asyncoperation"]
                    tries = 0
                    max_tries = 3
                    while True: #Poll status since it's asynchronous
                        tries += 1
                        response_async = self.request.do_request(self.auth.arm_access_token, azure_asyncoperation, "GET", None)
                        if response_async.status_code == 200:
                            command_result = json.loads(response_async.content.decode('utf-8'))
                            if command_result["status"] == "Succeeded":
                                print('\n' + Format.CYAN + "Name: " + Format.END + command_result["name"])
                                print(Format.CYAN + "Status: " + Format.END + command_result["status"])
                                print(Format.CYAN + "Start Time: " + Format.END + command_result["startTime"])
                                print(Format.CYAN + "End Time: " + Format.END + command_result["endTime"])
                                command_output = command_result["properties"]["output"]["value"]
                                print(Format.CYAN + "Output:\n" + Format.END)
                                for output_res in command_output:
                                    print(output_res["message"])
                                break
                            else:
                                if tries == max_tries:
                                    break
                                else:
                                    time.sleep(10)
                                    continue
                        else:
                            break
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("arm")
                if not exit:
                    self.add_vmcommand(subscriptionId, resourceGroup, vmname, system, payloadfile, True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] No access token requested for ARM API" + Format.END)