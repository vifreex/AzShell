class Format:
    BOLD_START = '\033[1m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    YELLOW_BACK = '\033[43m'
    RED = '\033[91m'
    RED_BACK = '\033[41m'

class Permissions:
    INTERESTING_DIRECTORY_ROLE = {
        "62e90394-69f5-4237-9190-012177145e10": f"{Format.BOLD_START}{Format.RED}{Format.YELLOW_BACK}Global Administrator{Format.END}",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": f"{Format.BOLD_START}{Format.RED_BACK}Application Administrator{Format.END} [add app-secret, add service-principal-secret]",
        "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
        "9360feb5-f418-4baa-8175-e2a00bac4301": "Directory Writers",
        "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
        "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
        "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
        "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
        "11451d60-acb2-45eb-a7d6-43d0f0125c13": "Windows 365 Administrator",
        "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
        "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing administrator",
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access administrator",
        "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange administrator",
        "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk administrator",
        "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password administrator",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged authentication administrator",
        "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security administrator",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint administrator",
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator"
    }

    INTERESTING_APP_PERMISSIONS = {
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": f"{Format.BOLD_START}{Format.RED_BACK}RoleManagement.ReadWrite.Directory{Format.END} [add role-member]",
        "2672f8bb-fd5e-42e0-85e1-ec764dd2614e": f"{Format.BOLD_START}{Format.RED_BACK}Policy.ReadWrite.PermissionGrant{Format.END}",
        "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All" + " [get users, add user, del user]",
        "c529cfca-c91b-489c-af2b-d92990b66ce6": "User.ManageIdentities.All",
        "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All" + " [get groups, add group, del group, add group-member, del group-member]",
        "06b708a9-e830-4db3-a914-8e69da51d44f": f"{Format.BOLD_START}{Format.RED_BACK}AppRoleAssignment.ReadWrite.All{Format.END} [add app-role-assigment]",
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All" + " [get applications, get service-principals, add application, add service-principal, add app-secret, add service-principal-secret]",
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
        "292d869f-3427-49a8-9dab-8c70152b74e9": "Organization.ReadWrite.All",
        "01c0a623-fc9b-48e9-b794-0756f8e8f067": "Policy.ReadWrite.ConditionalAccess" + " [get policies, add exclude-user-policy]",
        "246dd0d5-5bd0-4def-940b-0421030a5b68": "Policy.Read.All" + " [get policies]",
        "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All" + " [get mfa, add mfa-phone, del mfap-hone]",
        "78145de6-330d-4800-a6ce-494ff2d33d07": "DeviceManagementApps.ReadWrite.All",
        "5b07b0dd-2377-4e44-a38d-703f09a0dc3c": "DeviceManagementManagedDevices.PrivilegedOperations.All",
        "810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read" + " [get messages]",
        "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite" + " [get messages, add message, del message]",
        "6931bccd-447a-43d1-b442-00a195474933": "MailboxSettings.ReadWrite",
        "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All" + " [get files]",
        "01d4889c-1287-42c6-ac1f-5d1e02578ef6": "Files.Read.All" + " [get files]",
        "332a536c-c7ef-4017-ab91-336970924f0d": "Sites.Read.All" + " [get sites]",
        "9492366f-7969-46a4-8d15-ed1a20078fff": "Sites.ReadWrite.All" + " [get sites]",
        "0c0bf378-bf22-4481-8f81-9e89a9b4960a": "Sites.Manage.All" + " [get sites]",
        "a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All" + " [get sites]",
        "3aeca27b-ee3a-4c2b-8ded-80376e2134a4": "Notes.Read.All",
        "0c458cef-11f3-48c2-a568-c66751c238c0": "Notes.ReadWrite.All",
        "6b7d71aa-70aa-4810-a8d9-5d9fb2830017": "Chat.Read.All" + " [get chats]",
        "294ce7c9-31ba-490a-ad7d-97a7d075e4ed": "Chat.ReadWrite.All" + " [get chats]",
    }
