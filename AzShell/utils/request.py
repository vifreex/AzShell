import requests, time, random

class Request:

    def __init__(self, delay, useragent, proxy):
        self.delay = delay
        self.useragent = useragent
        self.proxy = proxy

    def do_request(self, token, url, method, body):
        if self.delay is not None:
            time.sleep(delay)
        else:
            delay = random.randint(60, 150)/100
            time.sleep(delay)
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        headers = {
        'User-Agent': self.useragent,
        'Content-Type': 'application/json',
        'ConsistencyLevel': 'eventual',
        'Origin': 'https://portal.azure.com',
        'Referer' : 'https://portal.azure.com/',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'Authorization': 'Bearer ' + token 
        }
        if method == "GET":
            response = requests.get(url, headers=headers, proxies=proxies, verify=False)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=body, proxies=proxies, verify=False)
        elif method == "PATCH":
            response = requests.patch(url, headers=headers, json=body, proxies=proxies, verify=False)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, proxies=proxies, verify=False)
        return response