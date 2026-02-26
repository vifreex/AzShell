# AzShell

<div align="center">
  <img src="https://raw.githubusercontent.com/vifreex/AzShell/refs/heads/main/.github/logo.png" alt="logo">
</div>
<br>

Tool to interact with Azure through the **Microsoft Graph API (graph.microsoft.com)** and **Azure Resource Manager (ARM) (management.azure.com)**. Designed to facilitate resource enumeration and detection of misconfigurations for potential abuse in Azure environments.

<div align="center">
  <img src="https://raw.githubusercontent.com/vifreex/AzShell/refs/heads/main/.github/azshell.gif" alt="AzShell" width="740">
</div>
<br>

```
usage: azshell [-h] -t TENANTID [-u UPN] [-p PASSWORD] [-c CLIENTID] [-a ACCESSTOKEN] [-r REFRESHTOKEN] [--user-agent USERAGENT] [--proxy PROXY] [--delay DELAY] [--only-graph]

optional arguments:
  -h, --help            show this help message and exit
  -t TENANTID, --tenant-id TENANTID
                        tenant name or tenant id
  -u UPN, --upn UPN     user principal name [User authentication]
  -p PASSWORD, --password PASSWORD
                        password or client secret
  -c CLIENTID, --client-id CLIENTID
                        client ID (Default for user authentication: Microsoft PowerShell client ID)
  -a ACCESSTOKEN, --access-token ACCESSTOKEN
                        graph access token
  -r REFRESHTOKEN, --refresh-token REFRESHTOKEN
                        refresh token
  --user-agent USERAGENT
                        user-agent header (Default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")
  --proxy PROXY         proxy URL [HTTP, SOCKS] (Example: http://127.0.0.1:8080 or socks://user:pass@127.0.0.1:1080)
  --delay DELAY         seconds delay between requests (Default: random delay)
  --only-graph          API Graph authentication only

Example:
  azshell -t example.com -u geralt@example.com
  azshell -t a21a8321-8bcc-4c65-1106-3432b1da0bb2b -c 1234df7b-efd2-113e-ca51-hdaf1ded2bas -p "DAS1~XZQ~zwd..."
```
## Installation

**Requires Python ≥ 3.9** 

```
pip install azshell
azshell -h
```
Or
```
git clone https://github.com/vifreex/AzShell.git
cd AzShell
pip install .
azshell -h
```

## Authentication

To perform authentication, the tenant name or tenant ID must be specified. If authentication is to be done using the tenant ID, it can be retrieved as follows:

- `https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration`
- `https://login.microsoftonline.com/<TENANT NAME>.onmicrosoft.com/.well-known/openid-configuration`

Authentication will obtain one token for **Microsoft Graph API** and another for **Azure Resource Manager (ARM)**. The access token will be used to interact with both APIs.

_If the **--onlygraph** flag is set, only a token for the Graph API will be requested, and no token for the ARM API will be obtained._

Token caching is managed automatically by AzShell, and if any token expires, it will attempt to renew it using the appropriate `refresh_token`.

### Username and password

```
azshell -t example.com -u geralt@example.com
```

Username and password authentication uses a device code. This method allows you to access via a browser and enter the device code displayed by AzShell, enabling authentication with a password, or directly using cookies. It also supports authentication processes that involve ADFS or third-party authentication providers.

**The steps performed by AzShell to obtain the tokens are as follows:**

1. A token for Microsoft Graph is requested, and the `access_token` and `refresh_token` are saved in a `.token_graph_data` file.
2. The `refresh_token` is used to request a token for Azure Resource Manager (ARM), and the `access_token` and `refresh_token` are saved in a `.token_arm_data` file.
3. The user's context is generated using both tokens (the tokens are validated)."

### Client Application ID and secret

```
azshell -t example.com -c 1234df7b-efd2-113e-ca51-hdaf1ded2bas -p "DAS1~XZQ~zwd.SsdvyEeM0eSDT"
```

When using Client ID and Secret for authentication, AzShell directly requests tokens for Microsoft Graph and Azure Resource Manager (ARM). 

**The steps performed by AzShell to obtain the tokens are as follows:**

1. A token for Microsoft Graph is requested, and the `access_token` is saved in a `.token_graph_data` file.
2. A token for Azure Resource Manager (ARM) is requested directly, and the `access_token` is saved in a `.token_arm_data` file.
3. The application context is generated using both tokens (the tokens are validated).

### Refresh token

```
azshell -t example.com -r "0.AQUAktgDm4z-BU6A8TLpKKFroliiUBl7IjFOqc9xdJ..."
```

Using the provided refresh token, AzShell will attempt to request the necessary tokens for the Microsoft Graph API and the Azure Resource Manager (ARM).

### Access token (Only Graph)

```
azshell -t example.com -a "eyJ0eXAdssAJKV1QiLCJub25jZSI6Inl2Q242sZsdfLC..."
```

Using the provided access token, AzShell will retrieve the token's context, which includes details about the token itself and the associated permissions. This functionality is specifically available when using a Microsoft Graph API access token. 


## Modules

AzShell has three different modules: **get**, **add** and **del**.

### get
    context                     interesting information about the authentication context
    tokens                      print tokens used by AzShell
    privesc                     print interesting roles and applications
    users                       print users
    groups                      print groups
    devices                     print devices
    roles                       print roles
    updatable-groups            print the groups that can be updated by the current user
    applications                print applications
    service-principals          print service principals
    policies                    print policies
    domains                     print domains
    mfa                         print user authentication methods
    files                       enumeration in OneDrive
    sites                       site enumeration in SharePoint
    messages                    messages enumeration
    chats                       chats enumeration
    subscriptions               print subscriptions
    vms                         print virtual machines
    vm-perms                    print virtual machine permissions
    rbac                        print Azure RBAC assignments
    vaults                      print vaults
    vault-secrets               print the secrets associated with a vault
    vault-keys                  print the keys associated with a vault

### add
    app-secret                  add a password to an existing application
    service-principal-secret    add a password to an existing service service
    application                 creates a new application
    service-principal           creates a new service principal associated with an application
    role-member                 assigns a user to a role
    group-member                assigns a user to a group
    app-role-assigment          add and grant permissions to an application
    user                        add a user
    guest                       add a invited user
    group                       add a group
    new-password                resets a user's password to a new one
    message                     send a new message
    chat-message                send a new chat message
    identity                    add a new identity to a user
    mfa-phone                   add phone authentication method to a user
    exclude-user-policy         exclude a user from a policy
    vm-command                  executes commands on virtual machine
    rbac                        assign an Azure RBAC role to a principal

### del
    app-secret                  remove a password from an existing app
    service-principal-secret    remove a password from an existing service principal
    message                     delete a message
    role-member                 remove a user from a role
    group-member                remove a user from a group
    app-role-assigment          remove permissions from an application
    identity                    remove an identity from a user
    mfa-phone                   remove phone authentication method from a user
    user                        remove a user
    application                 remove an application
    service-principal           remove a service principal associated with an application
    group                       remove a group
    exclude-user-policy         removes the excluded user from a policy
    rbac                        remove an Azure RBAC role to a principal


