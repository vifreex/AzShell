import os, json
from AzShell.utils.constants import Format

class Files:
    
    def __init__(self, auth, request, search):
        self.auth = auth
        self.request = request
        self.search = search

    def __dump_file(self, filename):
        base_dir = os.path.expanduser("~/.AzShell/Files/")
        os.makedirs(base_dir, exist_ok=True)
        files_path = os.path.join(base_dir, filename)
        with open(files_path, "wb") as f:
            f.write(self.data)
        print(f"{Format.GREEN}\n[+] File saved in {files_path}")

    def __download_file(self, userid, siteid, fileid, filename, exit=False):
        if userid is not None:
            url = f"https://graph.microsoft.com/v1.0/users/{userid}/drive/items/{fileid}/content"
        else:
            url = f"https://graph.microsoft.com/v1.0/sites/{siteid}/drive/items/{fileid}/content"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            self.data = response.content
            self.__dump_file(filename)
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.__download_file(userid, siteid, fileid, filename, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n  [!] {response.content.decode('utf-8')} {Format.END}")

    def get_files(self, userid, folderid, fileid, siteid, top, exit=False):
        if fileid is not None and userid is None and siteid is None:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] At least --userid or --siteid have to be defined to download files{Format.END}")
        else:
            if userid is not None:
                url = f"https://graph.microsoft.com/v1.0/users/{userid}"
            elif siteid is not None:
                url = f"https://graph.microsoft.com/v1.0/sites/{siteid}"
            else:
                url = "https://graph.microsoft.com/v1.0/"

            if fileid is not None:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Downloading the file [File {fileid}]{Format.END}")
                url = f"{url}/drive/items/{fileid}"
            elif folderid is not None:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading folder [Folder {folderid}]{Format.END}")
                url = f"{url}/drive/items/{folderid}/children?$top={top}"
            elif self.search is not None:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading files [Search '{self.search}']{Format.END}")
                url = f"{url}/drive/search(q='{self.search}')?$top={top}"
            else:
                print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading files{Format.END}")
                url = f"{url}/drive/root/children?$top={top}"

            response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
            if response.status_code == 200:
                files_data = json.loads(response.content.decode('utf-8'))
                if fileid is None:
                    files_list = []
                    for file in files_data["value"]:
                        if "email" in file["createdBy"]["user"]:
                            user_email = str(file["createdBy"]["user"]["email"])
                        else:
                            user_email = None
                        if "folder" in file:
                            file_type = "folder"
                            size = str(file["folder"]["childCount"])
                        else:
                            file_type = "file"
                            size = str(int(file["size"]/1024))
                        files_list.append([user_email, str(file["name"]), str(file["lastModifiedDateTime"]), str(file["id"]), str(file["parentReference"]["siteId"]), str(file["createdBy"]["user"]["displayName"]), file_type, size])

                    file_list_sorted = sorted(files_list, key=lambda x: x[2], reverse=True)
                    for file in file_list_sorted:
                        if str(file[6]) == "folder":
                            print(f'\n{Format.BOLD_START}{Format.DARKCYAN}[Folder] {Format.YELLOW}{file[1]} [Modified: {str(file[2])}]{Format.END} {Format.CYAN}\n FolderId: {Format.END}{str(file[3])}')
                            print(f"{Format.CYAN} SiteId: {Format.END}{str(file[4])}")
                            print(f"{Format.CYAN} CreatedBy: {Format.END}{str(file[5])} ({str(file[0])})")
                            print(f"{Format.CYAN} ChildItems: {Format.END}{str(file[7])}")
                        else:
                            print(f'\n{Format.BOLD_START}{Format.DARKCYAN}[File] {Format.YELLOW}{file[1]} [Modified: {str(file[2])}]{Format.END} {Format.CYAN}\n FileId: {Format.END}{str(file[3])}')
                            print(f"{Format.CYAN} SiteId: {Format.END}{str(file[4])}")
                            print(f"{Format.CYAN} CreatedBy: {Format.END}{str(file[5])} ({str(file[0])})")
                            print(f"{Format.CYAN} Size: {Format.END}{str(file[7])} KB")
                else:
                    self.__download_file(userid, siteid, fileid, files_data["name"])
            elif response.status_code == 403:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
            elif response.status_code == 401:
                print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
                self.auth.request_token("graph")
                if not exit:
                    self.get_sites(userid, folderid, fileid, siteid, top, True)
            else:
                print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')} {Format.END}")


    def get_sites(self, top, exit=False):
        if self.search is None:
            print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading all sites{Format.END}")
            url = f"https://graph.microsoft.com/v1.0/sites?$top={top}"
        else:
            print(f"{Format.BOLD_START}{Format.BLUE}\n[*] Reading sites [{self.search}]{Format.END}")
            url = f"https://graph.microsoft.com/v1.0/sites?search={self.search}&$top={top}"
        response = self.request.do_request(self.auth.graph_access_token, url, "GET", None)
        if response.status_code == 200:
            sites_data = json.loads(response.content.decode('utf-8'))
            for site in sites_data["value"]:
                print(f'\n{Format.BOLD_START}{Format.DARKCYAN}[Site] {Format.YELLOW}{str(site["displayName"])} [Created: {str(site["createdDateTime"])}]{Format.END} {Format.CYAN}\n SiteId: {Format.END}{str(site["id"])}')
        elif response.status_code == 403:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] Insufficient privileges to complete the operation{Format.END}")
        elif response.status_code == 401:
            print(f"{Format.BOLD_START}{Format.GREEN}\n[*] Access token expired, requesting a new one...{Format.END}")
            self.auth.request_token("graph")
            if not exit:
                self.get_sites(top, True)
        else:
            print(f"{Format.BOLD_START}{Format.RED}\n[!] {response.content.decode('utf-8')} {Format.END}")
