import logging
import azure.functions as func
import requests
import adal
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url="https://kv-aadlookup-socdev.vault.azure.net/", credential=credential)
# Authenticate to Tenant and Get Information
class GraphApiAuthentication:
    resource_URL ='https://graph.microsoft.com'
    def __init__(self, tenant):
        self.tenant = tenant

    def Authenticate(self, appid, appsecret):
        try:
            self.app_id = secret_client.get_secret(appid).value
            self.app_password = secret_client.get_secret(appsecret).value
            try:
                self.authority_url = f'https://login.microsoftonline.com/{self.tenant}'
                self.context = adal.AuthenticationContext(self.authority_url)
                self.token = self.context.acquire_token_with_client_credentials(self.resource_URL,self.app_id,self.app_password)
                self.request_headers = {'Authorization': 'bearer {}'.format(self.token['accessToken'])}
                logging.info(f"Authenticated to {self.tenant}")
                return True
            except Exception as e:
                logging.info(f"Authentication to {self.tenant} failed")
                logging.info(str(e))
                return False
        except Exception as e:
            logging.info('Retrieving KeyVault Secret Failed')
            logging.info(str(e))
            return False
        

    def GetAllUsers(self):
        print (f"Checking Tenant: {self.tenant}...")
        self.users = self.resource_URL + '/v1.0/users/'
        self.result = requests.get(self.users,headers = self.request_headers)
        if self.result:
            logging.info("Users exist in tenant..")
            logging.info(self.result.text)
            return self.result.text
        else:
            logging.info("User Not Found")
            return

    def GetUser(self,data): 
        logging.info(f"Checking Tenant: {self.tenant} for {data}")
        self.user = self.resource_URL + '/v1.0/users/' + data
        self.result = requests.get(self.user,headers = self.request_headers)
        if self.result:
            logging.info("User exist in tenant..")
            return self.result.text
        else:
            return False
            

def FindUser(Tenant,data):
    Users = ""
    for T in Tenant:
        Tenant_Tenant_Name = T + '.onmicrosoft.com'
        TenantAuthenticate = GraphApiAuthentication(Tenant_Tenant_Name)
        if TenantAuthenticate.Authenticate(T + "-appid", T + "-appsecret"):
            User = TenantAuthenticate.GetUser(data)
            if User:
                Users +=  User + ',' 
        else:
            continue
    if Users:
        return Users
    else:
        return False

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    def DataParameters():
        if req.params.get('UserPrincipalName'):
            return req.params.get('UserPrincipalName')
        elif req.params.get('Email'):
            return req.params.get('Email')
        elif req.params.get('Id'):
            return req.params.get('Id')
        elif req.params.get('DisplayName'):
            DisplayName = req.params.get('DisplayName')
            urlFilter = f"?$filter=startsWith(displayName,'{DisplayName}')"
            return urlFilter
        elif req.params.get('FirstName'):
            FirstName = req.params.get('FirstName')
            urlFilter = f"?$filter=startsWith(givenName,'{FirstName}')"
            return urlFilter
        elif req.params.get('LastName'):
            LastName = req.params.get('LastName')
            urlFilter = f"?$filter=startsWith(Surname,'{LastName}')"
            return urlFilter
        elif req.params.get('JobTitle'):
            JobTitle = req.params.get('JobTitle')
            urlFilter = f"?$filter=startsWith(jobTitle,'{JobTitle}')"
            return urlFilter
        else:
            return False
    
    def TenantParameters():
        if req.params.get('Tenant') == "All":
            Tenant = ["osagsocdev","kay07949yahooco"]
            return Tenant
        else:
            return req.params.get('Tenant').split(',')


    Data = DataParameters()
    Tenant = TenantParameters()

    
    if not Data:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            data = req_body.get('Data')

    if Data and Tenant:
        #For Testing
        #Tenant = ["osagsocdev","kay07949yahooco"]
        FindUserInfo = FindUser(Tenant,Data)
        if FindUserInfo:
            return func.HttpResponse(FindUserInfo)
        else:
            return func.HttpResponse(
                
                f"{Data} Not Found in Tenant: {Tenant}",
                status_code=404
                
                )
    else:
        return func.HttpResponse(
             "Please Provide User Data to Search",
             status_code=204

                )


