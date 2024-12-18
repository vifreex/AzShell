import json
from AzShell.utils.constants import Format

class Subscriptions():
    def __init__(self, auth, request):
        self.auth = auth
        self.request = request

    def get_subscriptions(self, exit=False):
        if self.auth.arm_access_token is not None:
            print(Format.BOLD_START + Format.BLUE + "\n[*] Reading subscription info" + Format.END)
            url = "https://management.azure.com/subscriptions?api-version=2021-01-01"
            response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
            if response.status_code == 200:
                subscription_data = json.loads(response.content.decode('utf-8'))
                if len(subscription_data["value"]) == 0:
                    print(Format.GREEN + "\n[!] No subscriptions found!" + Format.END)
                else:
                    for subscription in subscription_data["value"]:
                        print('\n' + Format.BOLD_START + Format.YELLOW + subscription["displayName"] + Format.END)
                        print(Format.CYAN + " SubscriptionId: " + Format.END + str(subscription["subscriptionId"]) + Format.END)
                        print(Format.CYAN + " TenantId: " + Format.END + str(subscription["tenantId"]) + Format.END)
                        print(Format.CYAN + " State: " + Format.END + str(subscription["state"]) + Format.END)
            elif response.status_code == 403:
                print(Format.BOLD_START + Format.RED + "\n[!] Insufficient privileges to complete the operation" + Format.END)
            elif response.status_code == 401:
                print(Format.BOLD_START + Format.GREEN + "\n[*] Access token expired, requesting a new one..." + Format.END)
                self.auth.request_token("arm")
                if not exit:
                    self.get_subscriptions(True)
            else:
                print(Format.BOLD_START + Format.RED + "\n[!] " + response.content.decode('utf-8') + Format.END)
        else:
            print(Format.BOLD_START + Format.RED + "\n[!] No access token requested for ARM API" + Format.END)