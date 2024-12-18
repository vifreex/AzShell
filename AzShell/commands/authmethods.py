import json
from AzShell.utils.constants import Format

class AuthMethods:
    
    def __init__(self, auth, request):
        self.auth = auth
        self.request = request

    def get_mfa(self, userid, exit=False):
        print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading all multifactor authentications{Format.END}")
        url = f"https://graph.microsoft.com/beta/users/{userid}/authentication/methods"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            self.data = json.loads(response.content.decode('utf-8'))
            print(f'\n{Format.BOLD_START}{Format.YELLOW}Authentication Methods{Format.END}')
            for authmethod in self.data["value"]:
                if authmethod["@odata.type"] == "#microsoft.graph.phoneAuthenticationMethod":
                    print(f"{Format.BOLD_START}{Format.CYAN} [Phone] {Format.END}{authmethod['phoneNumber']} [{authmethod['id']}]")
                elif authmethod["@odata.type"] == "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
                    print(f"{Format.BOLD_START}{Format.CYAN} [Microsoft Authenticator] {Format.END}{authmethod['displayName']}{Format.END} [{authmethod['id']}]")
                elif authmethod["@odata.type"] == "#microsoft.graph.emailAuthenticationMethod":
                    print(f"{Format.BOLD_START}{Format.CYAN} [Email] {Format.END}{authmethod['emailAddress']}{Format.END} [{authmethod['id']}]")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.get_mfa(userid, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def add_mfaphone(self, userid, phonenumber, phonetype, exit=False):
        if phonetype.lower() != "mobile" and phonetype.lower() != "alternatemobile" and phonetype.lower() != "office":
            print(f"{Format.BOLD_START}{Format.YELLOW}\n[!] --phonetype only allows 'mobile', 'alternateMobile' and 'office'{Format.END}")
        else:
            url = f"https://graph.microsoft.com/v1.0/users/{userid}/authentication/phoneMethods"
            body = {
                'phoneNumber': phonenumber,
                'phoneType': phonetype
            }
            response = self.request.do_request(self.auth.graph_access_token, url, "POST", body)
            if response.status_code == 201:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[+] Phone authentication method added!{Format.END}")
                phone_data = json.loads(response.content.decode('utf-8'))
                print(f"{Format.CYAN} PhoneId: {Format.END}{phone_data['id']}")
                print(f"{Format.CYAN} PhoneNumber: {Format.END}{phone_data['phoneNumber']}")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("graph")
                if not exit:
                    self.add_mfaphone(userid, phonenumber, phonetype, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")

    def del_mfaphone(self, userid, phoneid, exit=False):
        url = f"https://graph.microsoft.com/v1.0/users/{userid}/authentication/phoneMethods/{phoneid}"
        response = self.request.do_request(self.auth.graph_access_token, url, "DELETE", None)
        if response.status_code == 204:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[+] Phone authentication method removed!{Format.END}")
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.del_mfaphone(userid, phoneid, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")