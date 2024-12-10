import json, re, time, os
from AzShell.utils.constants import Format

class Devices:
    
    def __init__(self, auth, request, search, allinfo):
        self.auth = auth
        self.request = request
        self.search = search
        self.allinfo = allinfo
        self.data = []

    def __dump_devices(self, devices_file):
        base_dir = os.path.expanduser("~/.AzShell/Devices/")
        os.makedirs(base_dir, exist_ok=True)
        devices_path = os.path.join(base_dir, devices_file)
        f = open(devices_path, "w")
        json.dump(self.data, f)
        print(Format.GREEN + "\n[+] Full device information saved in " + devices_path + Format.END)
        f.close()   

    def get_devices(self, exit=False):
        if not self.allinfo and self.search is None:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --search or --all have to be defined"  + Format.END)
        else:
            search_id = False
            if self.allinfo:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading all devices" + Format.END)
                url = "https://graph.microsoft.com/v1.0/devices"
            else:
                print(Format.BOLD_START + Format.BLUE + "\n[*] Reading devices [" + self.search + "]" + Format.END)
                if re.match('^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$',self.search.lower()):
                    url = 'https://graph.microsoft.com/v1.0/devices/' + self.search + '?$orderby=displayName'
                    search_id = True
                else:
                    url = 'https://graph.microsoft.com/v1.0/devices?$search="displayName:' + self.search + '" OR "operatingSystem:' + self.search + '" OR "operatingSystemVersion:' + self.search + '" OR "model:' + self.search + '" OR "manufacturer:' + self.search +'"&$orderby=displayName'
            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                devices_data = json.loads(response.content.decode('utf-8'))
                if search_id:
                    devices_data = {"value":[devices_data]}
                for device in devices_data["value"]:
                    self.data.append(device)
                    print('\n' + Format.BOLD_START + Format.YELLOW + device["displayName"] + Format.END)
                    print(Format.CYAN + " DeviceId: " + Format.END + device["id"])
                    print(Format.CYAN + " CreatedDateTime: " + Format.END + str(device["createdDateTime"]))
                    print(Format.CYAN + " OperatingSystem: " + Format.END + str(device["operatingSystem"]))
                    print(Format.CYAN + " OperatingSystemVersion: " + Format.END + str(device["operatingSystemVersion"]))
                    print(Format.CYAN + " Manufacturer: " + Format.END + str(device["manufacturer"]))
                    print(Format.CYAN + " Model: " + Format.END + str(device["model"]))
                if self.allinfo:
                    devices_file = time.strftime("%Y%m%d-%H%M%S") + "_devices.json"
                    self.__dump_devices(devices_file)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("graph")
                if not exit:
                    self.get_devices(True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)