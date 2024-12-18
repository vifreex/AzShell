import json
from AzShell.utils.constants import Format

class Domains:
    
    def __init__(self, auth, request):
        self.auth = auth
        self.request = request

    def get_domains(self, exit=False):
        print(Format.BOLD_START + Format.BLUE + "\n[*] Reading domain info" + Format.END)
        url = "https://graph.microsoft.com/v1.0/domains"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            domains_data = json.loads(response.content.decode('utf-8'))
            for domain in domains_data["value"]:
                print('\n' + Format.BOLD_START + Format.YELLOW + domain["id"] + Format.END)
                print(Format.CYAN + " IsVerified: " + Format.END + str(domain["isVerified"]))             
                print(Format.CYAN + " AuthenticationType: " + Format.END + str(domain["authenticationType"]))
        elif response.status_code == 403:
            print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
        elif response.status_code == 401:
            print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
            self.auth.request_token("graph")
            if not exit:
                self.get_domains(True)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)