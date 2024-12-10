# GENERAL IMPORTS
import os, argparse, sys,  warnings
from cmd2 import with_argparser, Cmd, style, Fg, Bg
from AzShell.utils.request import Request
from AzShell.utils.constants import Format

# GRAPH IMPORTS
from AzShell.commands.auth import Auth
from AzShell.commands.users import Users
from AzShell.commands.groups import Groups
from AzShell.commands.devices import Devices
from AzShell.commands.roles import Roles
from AzShell.commands.domains import Domains
from AzShell.commands.applications import Applications
from AzShell.commands.files import Files
from AzShell.commands.messages import Messages
from AzShell.commands.chats import Chats
from AzShell.commands.policies import Policies
from AzShell.commands.authmethods import AuthMethods

# ARM IMPORTS
from AzShell.commands.subscriptions import Subscriptions
from AzShell.commands.vms import VMs
from AzShell.commands.vaults import Vaults

# Disable warning messages
warnings.filterwarnings('ignore')

####################################################################################################################################
############################################### A R G P A R S E    O P T I O N S ###################################################
####################################################################################################################################

example_text = '''Example:
  azshell -t example.com -u geralt@example.com
  azshell -t a21a8321-8bcc-4c65-1106-3432b1da0bb2b -c 1234df7b-efd2-113e-ca51-hdaf1ded2bas -p "DAS1~XZQ~zwd.SsdvyEeM0eSDT"'''

#################################
########## AUTH PARSE ###########
#################################
parser_auth = argparse.ArgumentParser(epilog=example_text, formatter_class=argparse.RawDescriptionHelpFormatter)
parser_auth.add_argument('-t', '--tenantid', help='tenant name or tenant id\n', required=True)
parser_auth.add_argument('-u', '--upn', help='user principal name [User authentication]\n', required=False)
parser_auth.add_argument('-p', '--password', dest='password', action='store', help='password or client secret\n', required=False)
parser_auth.add_argument('-c', '--clientid', dest='clientid', action='store', help='client ID (Default for user authentication: Microsoft PowerShell client ID)\n', required=False)
parser_auth.add_argument('-a', '--accesstoken', dest='accesstoken', action='store', help='graph access token\n', required=False)
parser_auth.add_argument('-r', '--refreshtoken', dest='refreshtoken', action='store', help='refresh token\n', required=False)
parser_auth.add_argument('--useragent', dest='useragent', action='store', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36', help='user-agent header (Default: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")\n', required=False)
parser_auth.add_argument('--proxy', dest='proxy', action='store', help='proxy URL [HTTP, SOCKS] (Example: http://127.0.0.1:8080 or socks://user:pass@127.0.0.1:1080)\n', required=False)
parser_auth.add_argument('--delay', dest='delay', action='store', help='seconds delay between requests (Default: random delay)\n', required=False)
parser_auth.add_argument('--onlygraph', dest='onlygraph', action='store_true', default=False, help='API Graph authentication only\n', required=False)

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(required=True)

#################################
########### GET PARSE ###########
#################################
parser_get = subparsers.add_parser('get', help='[context, tokens, privesc, users, groups, devices, roles, applications, serviceprincipals, policies, domains, mfa, files, sites, messages, chats, subscriptions, vms, vmperms, rbac, vaults, vaultsecrets, vaultkeys]\n')
subparsers_get = parser_get.add_subparsers(required=True)

parser_get_context = subparsers_get.add_parser('context', help='interesting information about the authentication context\n')
parser_get_context.add_argument('--getcontext', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_tokens = subparsers_get.add_parser('tokens', help='print tokens used by AzShell\n')
parser_get_tokens.add_argument('--renew', action='store_true', help='request new access tokens and update them in AzShell\n', required=False)
parser_get_tokens.add_argument('--gettokens', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_privesc = subparsers_get.add_parser('privesc', help='print interesting roles and applications\n')
parser_get_privesc.add_argument('--onlyroles', action='store_true', help='get only the interesting roles\n', required=False)
parser_get_privesc.add_argument('--onlyapps', action='store_true', help='get only the interesting applications\n', required=False)
parser_get_privesc.add_argument('--getprivesc', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_user = subparsers_get.add_parser('users', help='print users\n')
parser_get_user.add_argument('--search', type=str, help='user id or user principal name\n', required=False)
parser_get_user.add_argument('--all',action='store_true', help='dump all users data to a json\n', required=False)
parser_get_user.add_argument('--getusers', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_group = subparsers_get.add_parser('groups', help='print groups\n')
parser_get_group.add_argument('--search', type=str, help='group name or search term\n', required=False)
parser_get_group.add_argument('--all', action='store_true', help='dump all group data to a json\n', required=False)
parser_get_group.add_argument('--getgroups', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_device = subparsers_get.add_parser('devices', help='print devices\n')
parser_get_device.add_argument('--search', type=str, help='device name or search term\n', required=False)
parser_get_device.add_argument('--all', action='store_true', help='dump all device data to a json\n', required=False)
parser_get_device.add_argument('--getdevices', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_role = subparsers_get.add_parser('roles', help='print roles\n')
parser_get_role.add_argument('--getroles', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_application = subparsers_get.add_parser('applications', help='print applications\n')
parser_get_application.add_argument('--search', type=str, help='application name or search term\n', required=False)
parser_get_application.add_argument('--all', action='store_true', help='dump all application data to a json\n', required=False)
parser_get_application.add_argument('--getapplications', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_serviceprincipal = subparsers_get.add_parser('serviceprincipals', help='print service principals\n')
parser_get_serviceprincipal.add_argument('--search', type=str, help='service principal name or search term\n', required=False)
parser_get_serviceprincipal.add_argument('--all', action='store_true', help='dump all service principal data to a json\n', required=False)
parser_get_serviceprincipal.add_argument('--getserviceprincipals', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_policy = subparsers_get.add_parser('policies', help='print policies\n')
parser_get_policy.add_argument('--search', type=str, help='policie name or search term\n', required=False)
parser_get_policy.add_argument('--userid', type=str, help='userid to search in policies\n', required=False)
parser_get_policy.add_argument('--all', action='store_true', help='dump all policy data to a json\n', required=False)
parser_get_policy.add_argument('--getpolicies', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_domain = subparsers_get.add_parser('domains', help='print domains\n')
parser_get_domain.add_argument('--getdomains', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_mfa = subparsers_get.add_parser('mfa', help='print user authentication methods\n')
parser_get_mfa.add_argument('--userid', type=str, help='user id\n', required=True)
parser_get_mfa.add_argument('--getmfa', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_files = subparsers_get.add_parser('files', help='enumeration in OneDrive\n')
parser_get_files.add_argument('--search', type=str, help='string to search\n', required=False)
parser_get_files.add_argument('--folderid', type=str, help='folder id to list content\n', required=False)
parser_get_files.add_argument('--fileid', type=str, help='file id to download\n', required=False)
parser_get_files.add_argument('--siteid', type=str, help='site id (SharePoint)\n', required=False)
parser_get_files.add_argument('--userid', type=str, help='user id\n', required=False)
parser_get_files.add_argument('--top', type=str, default='50', help='top\n', required=False)
parser_get_files.add_argument('--getfiles', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_sites = subparsers_get.add_parser('sites', help='site enumeration in SharePoint\n')
parser_get_sites.add_argument('--search', type=str, dest='search', action='store', help='string to search\n', required=False)
parser_get_sites.add_argument('--top', type=str, dest='top', default='50', action='store', help='top\n', required=False)
parser_get_sites.add_argument('--getsites', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_messages = subparsers_get.add_parser('messages', help='messages enumeration\n')
parser_get_messages.add_argument('--search', type=str, help='string to search\n', required=False)
parser_get_messages.add_argument('--top', type=str, default='20', help='top\n', required=False)
parser_get_messages.add_argument('--messageid', type=str, help='message id\n', required=False)
parser_get_messages.add_argument('--userid', type=str, help='user id\n', required=True)
parser_get_messages.add_argument('--getmessages', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_chats = subparsers_get.add_parser('chats', help='chats enumeration\n')
parser_get_chats.add_argument('--search', type=str, help='string to search\n', required=False)
parser_get_chats.add_argument('--top', type=str, help='top\n', required=False)
parser_get_chats.add_argument('--chatid', type=str, help='chat id\n', required=False)
parser_get_chats.add_argument('--userid', type=str, help='user id\n', required=True)
parser_get_chats.add_argument('--getchats', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_subscriptions = subparsers_get.add_parser('subscriptions', help='print subscriptions\n')
parser_get_subscriptions.add_argument('--getsubscriptions', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_vms = subparsers_get.add_parser('vms', help='print virtual machines\n')
parser_get_vms.add_argument('--subscriptionid', type=str, help='subscription id\n', required=True)
parser_get_vms.add_argument('--resourcegroup', type=str, help='virtual machine resource group\n', required=False)
parser_get_vms.add_argument('--getvms', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_vm_perms = subparsers_get.add_parser('vmperms', help='print virtual machine permissions\n')
parser_get_vm_perms.add_argument('--subscriptionid', type=str, help='subscription id\n', required=True)
parser_get_vm_perms.add_argument('--resourcegroup', type=str, help='virtual machine resource group\n', required=True)
parser_get_vm_perms.add_argument('--vmname', type=str, help='virtual machine name\n', required=True)
parser_get_vm_perms.add_argument('--getvmperms', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_rbac = subparsers_get.add_parser('rbac', help='print Azure RBAC assignments\n')
parser_get_rbac.add_argument('--subscriptionid', type=str, help='subscription id\n', required=True)
parser_get_rbac.add_argument('--getrbac', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_vaults = subparsers_get.add_parser('vaults', help='print vaults\n')
parser_get_vaults.add_argument('--subscriptionid', type=str, help='subscription id\n', required=True)
parser_get_vaults.add_argument('--getvaults', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_vaultsecrets = subparsers_get.add_parser('vaultsecrets', help='print the secrets associated with a vault\n')
parser_get_vaultsecrets.add_argument('--vaulturl', type=str, help='vault URL (Example: https://testingvault.vault.azure.net)\n', required=True)
parser_get_vaultsecrets.add_argument('--secretname', type=str, help='extract secret by name\n', required=False)
parser_get_vaultsecrets.add_argument('--all', action='store_true', help='extract all secrets from vault\n', required=False)
parser_get_vaultsecrets.add_argument('--getvaultsecrets', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_get_vaultkeys = subparsers_get.add_parser('vaultkeys', help='print the keys associated with a vault\n')
parser_get_vaultkeys.add_argument('--vaulturl', type=str, help='vault URL (Example: https://testingvault.vault.azure.net)\n', required=True)
parser_get_vaultkeys.add_argument('--keyname', type=str, help='extract key by name\n', required=False)
parser_get_vaultkeys.add_argument('--all', action='store_true', help='extract all keys from vault\n', required=False)
parser_get_vaultkeys.add_argument('--getvaultkeys', type=bool, default=True, help=argparse.SUPPRESS, required=False)

#################################
########### ADD PARSE ###########
#################################
parser_add = subparsers.add_parser('add', help='[appsecret, serviceprincipalsecret, application, serviceprincipal, rolemember, groupmember, approleassigment, user, guest, group, newpassword, message, chatmessage, identity, mfaphone, excludeuserpolicy, vmcommand]\n')
subparsers_add = parser_add.add_subparsers(dest='option',required=True)

parser_add_appsecret = subparsers_add.add_parser('appsecret', help='add a password to an existing application\n')
parser_add_appsecret.add_argument('--appid', type=str, help='app id\n', required=True)
parser_add_appsecret.add_argument('--name', type=str, help='name for the key\n', required=True)
parser_add_appsecret.add_argument('--addappsecret', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_serviceprincipalsecret = subparsers_add.add_parser('serviceprincipalsecret', help='add a password to an existing service service\n')
parser_add_serviceprincipalsecret.add_argument('--serviceprincipalid', type=str, help='service principal id\n', required=True)
parser_add_serviceprincipalsecret.add_argument('--name', type=str, help='name for the key\n', required=True)
parser_add_serviceprincipalsecret.add_argument('--addserviceprincipalsecret', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_application = subparsers_add.add_parser('application', help='creates a new application\n')
parser_add_application.add_argument('--name', type=str, help='application name\n', required=True)
parser_add_application.add_argument('--addapplication', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_serviceprincipal = subparsers_add.add_parser('serviceprincipal', help='creates a new service principal associated with an application\n')
parser_add_serviceprincipal.add_argument('--appid', type=str, help='application id\n', required=True)
parser_add_serviceprincipal.add_argument('--addserviceprincipal', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_rolemember = subparsers_add.add_parser('rolemember', help='assigns a user to a role\n')
parser_add_rolemember.add_argument('--roleid', type=str, help='role id\n', required=True)
parser_add_rolemember.add_argument('--objectid', type=str, help='user id\n', required=True)
parser_add_rolemember.add_argument('--addrolemember', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_groupmember = subparsers_add.add_parser('groupmember', help='assigns a user to a group\n')
parser_add_groupmember.add_argument('--groupid', type=str, help='group id\n', required=True)
parser_add_groupmember.add_argument('--userid', type=str, help='user id\n', required=True)
parser_add_groupmember.add_argument('--addgroupmember', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_approleassigment = subparsers_add.add_parser('approleassigment', help='add and grant permissions to an application\n')
parser_add_approleassigment.add_argument('--serviceprincipalid', type=str, help='service principal object id to which the permission is to be added\n', required=True)
parser_add_approleassigment.add_argument('--resourceid', type=str, help='service principal object id (Microsoft Graph object id or other application)\n', required=True)
parser_add_approleassigment.add_argument('--permissionid', type=str, help='permission id\n', required=True)
parser_add_approleassigment.add_argument('--addapproleassigment', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_user = subparsers_add.add_parser('user', help='add a user\n')
parser_add_user.add_argument('--displayname', type=str, help='display name (Example: Cirilla Fiona)\n', required=True)
parser_add_user.add_argument('--mailnickname', type=str, help='mail nickname (Example: CirillaF)\n', required=True)
parser_add_user.add_argument('--userprincipalname', type=str, help='user principal name (Example: cirilla.fiona@contoso.com)\n', required=True)
parser_add_user.add_argument('--password', type=str, help='user password\n', required=True)
parser_add_user.add_argument('--adduser', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_group = subparsers_add.add_parser('group', help='add a group\n')
parser_add_group.add_argument('--displayname', type=str, help='display name (Example: Cat School)\n', required=True)
parser_add_group.add_argument('--description', type=str, help='description\n', required=False)
parser_add_group.add_argument('--mailnickname', type=str, help='mail nickname (Example: CatSchool)\n', required=True)
parser_add_group.add_argument('--addgroup', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_guest = subparsers_add.add_parser('guest', help='add a invited user\n')
parser_add_guest.add_argument('--tenantid', type=str, help='id of the current tenant to which the user will be invited\n', required=True)
parser_add_guest.add_argument('--inviteduseremail', type=str, help='invited user email address\n', required=True)
parser_add_guest.add_argument('--sendinvitationmessage', action='store_true', help='send an invitation email\n', required=False)
parser_add_guest.add_argument('--addguest', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_newpassword = subparsers_add.add_parser('newpassword', help='resets a user\'s password to a new one\n')
parser_add_newpassword.add_argument('--userid', type=str, help='user id\n', required=True)
parser_add_newpassword.add_argument('--newpassword', type=str, help='new password\n', required=True)
parser_add_newpassword.add_argument('--addnewpassword', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_identity = subparsers_add.add_parser('identity', help='add a new identity to a user\n')
parser_add_identity.add_argument('--userid', type=str, help='user id\n', required=True)
parser_add_identity.add_argument('--email', type=str, help='attacker email (External email account)\n', required=True)
parser_add_identity.add_argument('--addidentity', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_message = subparsers_add.add_parser('message', help='send a new message\n')
parser_add_message.add_argument('--userid', type=str, help='user id or upn\n', required=True)
parser_add_message.add_argument('--subject', type=str, help='subject of the message\n', required=False)
parser_add_message.add_argument('--content', type=str, help='message content\n', required=False)
parser_add_message.add_argument('--contentfile', type=str, help='file with the content of the message\n', required=False)
parser_add_message.add_argument('--contenttype', type=str, help='message content type [text,html]\n', default='text', required=False)
parser_add_message.add_argument('--recipients', type=str, help='mail recipients (Separated by commas)\n', required=True)
parser_add_message.add_argument('--ccrecipients', type=str, help='CC mail recipients (Separated by commas)\n', required=False)
parser_add_message.add_argument('--addmessage', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_chatmessage = subparsers_add.add_parser('chatmessage', help='send a new chat message\n')
parser_add_chatmessage.add_argument('--userid', type=str, help='user id or upn\n', required=True)
parser_add_chatmessage.add_argument('--chatid', type=str, help='chat id\n', required=True)
parser_add_chatmessage.add_argument('--content', type=str, help='chat message contentd\n', required=True)
parser_add_chatmessage.add_argument('--addchatmessage', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_mfa_phone = subparsers_add.add_parser('mfaphone', help='add phone authentication method to a user\n')
parser_add_mfa_phone.add_argument('--userid', type=str, help='user id\n', required=True)
parser_add_mfa_phone.add_argument('--phonenumber', type=str, help='phone number\n', required=True)
parser_add_mfa_phone.add_argument('--phonetype', type=str, help='phone type [mobile, alternateMobile, office]\n', default="alternateMobile", required=False)
parser_add_mfa_phone.add_argument('--addmfaphone', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_excludeuserpolicy = subparsers_add.add_parser('excludeuserpolicy', help='exclude a user from a policy \n')
parser_add_excludeuserpolicy.add_argument('--policyid', type=str, help='policy id\n', required=True)
parser_add_excludeuserpolicy.add_argument('--userid', type=str, help='user id\n', required=True)
parser_add_excludeuserpolicy.add_argument('--addexcludeuserpolicy', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_add_vmCommand = subparsers_add.add_parser('vmcommand', help='executes commands on virtual machine\n')
parser_add_vmCommand.add_argument('--subscriptionid', type=str, help='subscription id\n', required=True)
parser_add_vmCommand.add_argument('--resourcegroup', type=str, help='resource group\n', required=True)
parser_add_vmCommand.add_argument('--vmname', type=str, help='virtual machine name\n', required=True)
parser_add_vmCommand.add_argument('--system', type=str, help='target OS system (Windows/Linux)\n', required=True)
parser_add_vmCommand.add_argument('--payloadfile', type=str, help='file with payload (Shell or PowerShell script)\n', required=True)
parser_add_vmCommand.add_argument('--addvmcommand', type=bool, default=True, help=argparse.SUPPRESS, required=False)

#################################
########### DEL PARSE ###########
#################################
parser_del = subparsers.add_parser('del', help='[user, group, application, serviceprincipal, appsecret, serviceprincipalsecret, message, chatmessage, rolemember, groupmember, mfaphone, approleassigment, identity, excludeuserpolicy]\n')
subparsers_del = parser_del.add_subparsers(dest='option',required=True)

parser_del_user = subparsers_del.add_parser('user', help='remove a user\n')
parser_del_user.add_argument('--userid', type=str, help='user id\n', required=True)
parser_del_user.add_argument('--deluser', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_group = subparsers_del.add_parser('group', help='remove a group\n')
parser_del_group.add_argument('--groupid', type=str, help='group id\n', required=True)
parser_del_group.add_argument('--delgroup', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_application = subparsers_del.add_parser('application', help='remove an application\n')
parser_del_application.add_argument('--objectid', type=str, help='application id\n', required=True)
parser_del_application.add_argument('--delapplication', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_serviceprincipal = subparsers_del.add_parser('serviceprincipal', help='remove a service principal associated with an application\n')
parser_del_serviceprincipal.add_argument('--serviceprincipalid', type=str, help='service principal id\n', required=True)
parser_del_serviceprincipal.add_argument('--delserviceprincipal', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_appsecret = subparsers_del.add_parser('appsecret', help='remove a password from an existing app\n')
parser_del_appsecret.add_argument('--appid', type=str, help='app id\n', required=True)
parser_del_appsecret.add_argument('--keyid', type=str, help='key id\n', required=True)
parser_del_appsecret.add_argument('--delappsecret', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_serviceprincipalsecret = subparsers_del.add_parser('serviceprincipalsecret', help='remove a password from an existing service principal\n')
parser_del_serviceprincipalsecret.add_argument('--serviceprincipalid', type=str, help='service principal id\n', required=True)
parser_del_serviceprincipalsecret.add_argument('--keyid', type=str, help='key id\n', required=True)
parser_del_serviceprincipalsecret.add_argument('--delserviceprincipalsecret', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_identity = subparsers_del.add_parser('identity', help='remove an identity from a user\n')
parser_del_identity.add_argument('--userid', type=str, help='user id\n', required=True)
parser_del_identity.add_argument('--email', type=str, help='attacker email (External email account)\n', required=True)
parser_del_identity.add_argument('--delidentity', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_message = subparsers_del.add_parser('message', help='delete a message\n')
parser_del_message.add_argument('--messageid', type=str, help='message id\n', required=True)
parser_del_message.add_argument('--userid', type=str, help='user id\n', required=True)
parser_del_message.add_argument('--delmessage', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_chatmessage = subparsers_del.add_parser('chatmessage', help='delete a chat message\n')
parser_del_chatmessage.add_argument('--userid', type=str, help='user id\n', required=True)
parser_del_chatmessage.add_argument('--chatid', type=str, help='chat id\n', required=True)
parser_del_chatmessage.add_argument('--chatmessageid', type=str, help='chat message id\n', required=True)
parser_del_chatmessage.add_argument('--delchatmessage', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_rolemember = subparsers_del.add_parser('rolemember', help='remove a user from a role\n')
parser_del_rolemember.add_argument('--roleid', type=str, help='role id\n', required=True)
parser_del_rolemember.add_argument('--objectid', type=str, help='object id of user\n', required=True)
parser_del_rolemember.add_argument('--delrolemember', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_groupmember = subparsers_del.add_parser('groupmember', help='remove a user from a group\n')
parser_del_groupmember.add_argument('--groupid', type=str, help='group id\n', required=True)
parser_del_groupmember.add_argument('--objectid', type=str, help='object id of user\n', required=True)
parser_del_groupmember.add_argument('--delgroupmember', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_approleassigment = subparsers_del.add_parser('approleassigment', help='remove permissions from an application\n')
parser_del_approleassigment.add_argument('--serviceprincipalid', type=str, help='service principal object id to which the permission is to be removed\n', required=True)
parser_del_approleassigment.add_argument('--approleassignmentid', type=str, help='application role assignment id\n', required=True)
parser_del_approleassigment.add_argument('--delapproleassigment', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_mfa_phone = subparsers_del.add_parser('mfaphone', help='remove phone authentication method from a user\n')
parser_del_mfa_phone.add_argument('--userid', type=str, help='user id\n', required=True)
parser_del_mfa_phone.add_argument('--phoneid', type=str, help='phone id\n', required=True)
parser_del_mfa_phone.add_argument('--delmfaphone', type=bool, default=True, help=argparse.SUPPRESS, required=False)

parser_del_excludeuserpolicy = subparsers_del.add_parser('excludeuserpolicy', help='removes the excluded user from a policy \n')
parser_del_excludeuserpolicy.add_argument('--policyid', type=str, help='policy id\n', required=True)
parser_del_excludeuserpolicy.add_argument('--userid', type=str, help='user id\n', required=True)
parser_del_excludeuserpolicy.add_argument('--delexcludeuserpolicy', type=bool, default=True, help=argparse.SUPPRESS, required=False)

####################################################################################################################################
####################################################################################################################################

class Commands(Cmd):
    def __init__(self, args_auth):
        try:
            history_file = os.path.join(os.environ['HOME'],'.azshell_history.dat')
        except:
            history_file = '.azshell_history.dat'
        super().__init__(persistent_history_file=history_file)
        self.prompt = "\n" + style("(AzShell)", fg=Fg.WHITE, bg=Bg.BLUE, bold=True) + "> "
        self.hidden_commands += ['alias', 'edit', 'history', 'macro', 'py', 'run_pyscript', 'run_script', 'set', 'shell', 'shortcuts']
        ################################
        ######## AUTHENTICATION ########
        ################################
        if args_auth.clientid is None and args_auth.accesstoken is None and args_auth.upn is None and args_auth.refreshtoken is None:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] At least --upn, --clientid, --accesstoken or --refreshtoken have to be defined"  + Format.END)
            exit()
        elif args_auth.clientid is not None and args_auth.password is None and args_auth.upn is None:
            print(Format.BOLD_START + Format.YELLOW + "\n[!] Password is required with clientid authentication" + Format.END)
            exit()
        else:
            ######## AUTHENTICATION ########
            self.request = Request(args_auth.delay, args_auth.useragent, args_auth.proxy)
            self.auth = Auth(self.request, args_auth.tenantid, args_auth.upn, args_auth.clientid, args_auth.password, args_auth.accesstoken, args_auth.refreshtoken)
            if args_auth.accesstoken is not None:
                self.auth.graph_access_token = args_auth.accesstoken
                check = self.auth.get_msgraph_data()
                if check != "Success":
                    print(Format.BOLD_START + Format.RED + "\n[!] Error: [" + check + "]" + Format.END)
                    exit()
                else:
                    self.auth.create_context()
            else:
                self.auth.cache_tokendata()
                if self.auth.graph_access_token is None:
                    self.auth.request_token("graph")
                else:
                    print(Format.BOLD_START + Format.GREEN + "\n[+] Using cached Graph access token" + Format.END)
                if not args_auth.onlygraph:
                    if self.auth.arm_access_token is None:
                        self.auth.request_token("arm")
                    else:
                        print(Format.BOLD_START + Format.GREEN + "\n[+] Using cached ARM access token" + Format.END)
                self.auth.create_context()
                self.auth.check_context()
                
    ######## get ########
    @with_argparser(parser_get)
    def do_get(self,opts):
        """get module [privesc, users, groups, ...]"""
        self.auth.cache_tokendata()
        if self.auth.graph_access_token is None:
            print(Format.BOLD_START + Format.RED + "\n[!] Error: [it has not been possible to update the access token]" + Format.END)
            exit()
        if "getprivesc" in opts:
            if not opts.onlyroles and not opts.onlyapps:
                roles = Roles(self.auth, self.request)
                roles.get_roles(privesc=True)
                applications = Applications(self.auth, self.request, None, None)
                applications.get_apps_privesc()
            if opts.onlyroles:
                roles = Roles(self.auth, self.request)
                roles.get_roles(privesc=True)
            if opts.onlyapps:
                applications = Applications(self.auth, self.request, None, None)
                applications.get_apps_privesc()
        elif "getcontext" in opts:
            self.auth.create_context()
        elif "gettokens" in opts:
            self.auth.get_tokens(opts.renew)
        elif "getusers" in opts:
            users = Users(self.auth, self.request, opts.search, opts.all)
            users.get_users()
        elif "getgroups" in opts:
            groups = Groups(self.auth, self.request, opts.search, opts.all)
            groups.get_groups()
        elif "getdevices" in opts:
            devices = Devices(self.auth, self.request, opts.search, opts.all)
            devices.get_devices()
        elif "getroles" in opts:
            roles = Roles(self.auth, self.request)
            roles.get_roles()
        elif "getapplications" in opts:
            applications = Applications(self.auth, self.request, opts.search, opts.all)
            applications.get_apps()
        elif "getserviceprincipals" in opts:
            applications = Applications(self.auth, self.request, opts.search, opts.all)
            applications.get_serviceprincipals()
        elif "getpolicies" in opts:
            policies = Policies(self.auth, self.request, opts.search, opts.all)
            policies.get_policies(opts.userid)
        elif "getdomains" in opts:
            domains = Domains(self.auth, self.request)
            domains.get_domains()
        elif "getfiles" in opts:
            files = Files(self.auth, self.request, opts.search)
            files.get_files(opts.userid, opts.folderid, opts.fileid, opts.siteid, opts.top)
        elif "getsites" in opts:
            files = Files(self.auth, self.request, opts.search)
            files.get_sites(opts.top)
        elif "getmessages" in opts:
            messages = Messages(self.auth, self.request, opts.search)
            messages.get_messages(opts.userid, opts.messageid, opts.top)
        elif "getchats" in opts:
            chats = Chats(self.auth, self.request, opts.search)
            chats.get_chats(opts.userid, opts.chatid, opts.top)
        elif "getmfa" in opts:
            authMethods = AuthMethods(self.auth, self.request)
            authMethods.get_mfa(opts.userid)
        elif "getsubscriptions" in opts:
            subscriptions = Subscriptions(self.auth, self.request)
            subscriptions.get_subscriptions()
        elif "getvms" in opts:
            vms = VMs(self.auth, self.request, None)
            vms.get_vms(opts.subscriptionid, opts.resourcegroup)
        elif "getvmperms" in opts:
            vms = VMs(self.auth, self.request, None)
            vms.get_vm_perms(opts.subscriptionid, opts.resourcegroup, opts.vmname)
        elif "getrbac" in opts:
            roles = Roles(self.auth, self.request)
            roles.get_rbac(opts.subscriptionid)
        elif "getvaults" in opts:
            vaults = Vaults(self.auth, self.request, None)
            vaults.get_vaults(opts.subscriptionid)
        elif "getvaultsecrets" in opts:
            vaults = Vaults(self.auth, self.request, None)
            vaults.get_vaultsecrets(opts.vaulturl, opts.secretname, opts.all)
        elif "getvaultkeys" in opts:
            vaults = Vaults(self.auth, self.request, None)
            vaults.get_vaultkeys(opts.vaulturl, opts.keyname, opts.all)

    ######## ADD ########
    @with_argparser(parser_add)
    def do_add(self,opts):
        """add module [appsecret, application, serviceprincipal, ...]"""
        self.auth.cache_tokendata()
        if self.auth.graph_access_token is None:
            print(Format.BOLD_START + Format.RED + "\n[!] Error: [it has not been possible to update the access token]" + Format.END)
            exit()
        if "addappsecret" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.add_appsecret(opts.appid, opts.name)
        elif "addserviceprincipalsecret" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.add_serviceprincipalsecret(opts.serviceprincipalid, opts.name)
        elif "addapplication" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.add_application(opts.name)
        elif "addserviceprincipal" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.add_serviceprincipal(opts.appid)
        elif "addrolemember" in opts:
            roles = Roles(self.auth, self.request)
            roles.add_rolemember(opts.objectid,opts.roleid)
        elif "addapproleassigment" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.add_approleassignment(opts.serviceprincipalid,opts.resourceid,opts.permissionid)
        elif "addgroupmember" in opts:
            groups = Groups(self.auth, self.request, None, None)
            groups.add_groupmember(opts.userid,opts.groupid)
        elif "addmfaphone" in opts:
            authMethods = AuthMethods(self.auth, self.request)
            authMethods.add_mfaphone(opts.userid,opts.phonenumber,opts.phonetype)
        elif "adduser" in opts:
            users = Users(self.auth, self.request, None, None)
            users.add_user(opts.displayname, opts.mailnickname, opts.userprincipalname, opts.password)
        elif "addguest" in opts:
            users = Users(self.auth, self.request, None, None)
            users.add_guest(opts.inviteduseremail, opts.sendinvitationmessage, opts.tenantid)
        elif "addnewpassword" in opts:
            users = Users(self.auth, self.request, None, None)
            users.add_newpassword(opts.userid, opts.newpassword)
        elif "addidentity" in opts:
            users = Users(self.auth, self.request, None, None)
            users.add_identity(opts.userid,opts.email)
        elif "addgroup" in opts:
            groups = Groups(self.auth, self.request, None, None)
            groups.add_group(opts.description, opts.displayname, opts.mailnickname)
        elif "addmessage" in opts:
            messages = Messages(self.auth, self.request, None)
            messages.add_message(opts.userid, opts.subject, opts.content, opts.contentfile, opts.contenttype, opts.recipients, opts.ccrecipients)
        elif "addchatmessage" in opts:
            chats = Chats(self.auth, self.request, None)
            chats.add_chatmessage(opts.userid, opts.chatid, opts.content)
        elif "addexcludeuserpolicy" in opts:
            policies = Policies(self.auth, self.request, None, None)
            policies.add_excludeuserpolicy(opts.policyid,opts.userid)
        elif "addvmcommand" in opts:
            vms = VMs(self.auth, self.request, None)
            vms.add_vmcommand(opts.subscriptionid, opts.resourcegroup, opts.vmname, opts.system, opts.payloadfile)

    ######## DEL ########
    @with_argparser(parser_del)
    def do_del(self,opts):
        """del module [appsecret, message, rolemember, ...]"""
        self.auth.cache_tokendata()
        if self.auth.graph_access_token is None:
            print(Format.BOLD_START + Format.RED + "\n[!] Error: [it has not been possible to update the access token]" + Format.END)
            exit()
        if "delappsecret" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.del_appsecret(opts.appid, opts.keyid)
        elif "delserviceprincipalsecret" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.del_serviceprincipalsecret(opts.serviceprincipalid, opts.keyid)
        elif "delrolemember" in opts:
            roles = Roles(self.auth, self.request)
            roles.del_rolemember(opts.objectid,opts.roleid)
        elif "delapproleassigment" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.del_approleassignment(opts.serviceprincipalid,opts.approleassignmentid)
        elif "delgroupmember" in opts:
            groups = Groups(self.auth, self.request, None, None)
            groups.del_groupmember(opts.objectid,opts.groupid)
        elif "delmfaphone" in opts:
            authMethods = AuthMethods(self.auth, self.request)
            authMethods.del_mfaphone(opts.userid,opts.phoneid)
        elif "delmessage" in opts:
            messages = Messages(self.auth, self.request, None)
            messages.del_message(opts.userid, opts.messageid)
        elif "delchatmessage" in opts:
            chats = Chats(self.auth, self.request, None)
            chats.del_chatmessage(opts.userid, opts.chat, opts.chatmessageid)
        elif "deluser" in opts:
            users = Users(self.auth, self.request, None, None) 
            users.del_user(opts.userid)
        elif "delidentity" in opts:
            users = Users(self.auth, self.request, None, None) 
            users.del_identity(opts.userid,opts.email)
        elif "delgroup" in opts:
            groups = Groups(self.auth, self.request, None, None)
            groups.del_group(opts.groupid)
        elif "delapplication" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.del_application(opts.objectid)
        elif "delserviceprincipal" in opts:
            applications = Applications(self.auth, self.request, None, None)
            applications.del_serviceprincipal(opts.serviceprincipalid)
        elif "delexcludeuserpolicy" in opts:
            policies = Policies(self.auth, self.request, None, None)
            policies.del_excludeuserpolicy(opts.policyid,opts.userid)

def main():
    args_auth = parser_auth.parse_args()
    sys.argv = [sys.argv[0]]
    app = Commands(args_auth)
    sys.exit(app.cmdloop())
