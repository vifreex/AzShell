import json
from AzShell.utils.constants import Format

class Subscriptions():
    def __init__(self, auth, request):
        self.auth = auth
        self.request = request

    def get_subscriptions(self, exit=False):
        if self.auth.arm_access_token is not None:
            print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading subscription info{Format.END}")
            url = "https://management.azure.com/subscriptions?api-version=2021-01-01"
            response = self.request.do_request(self.auth.arm_access_token, url, "GET", None)
            if response.status_code == 200:
                subscription_data = json.loads(response.content.decode('utf-8'))
                if len(subscription_data["value"]) == 0:
                    print(f"{Format.GREEN}\n[!] No subscriptions found!{Format.END}")
                else:
                    for subscription in subscription_data["value"]:
                        print(f'\n{Format.BOLD_START}{Format.YELLOW}{subscription["displayName"]}{Format.END}')
                        print(f"{Format.CYAN} SubscriptionId: {Format.END}{subscription['subscriptionId']}{Format.END}")
                        print(f"{Format.CYAN} TenantId: {Format.END}{subscription['tenantId']}{Format.END}")
                        print(f"{Format.CYAN} State: {Format.END}{subscription['state']}{Format.END}")
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("arm")
                if not exit:
                    self.get_subscriptions(True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')}{Format.END}")
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] No access token requested for ARM API{Format.END}")
