import os
from dotenv import load_dotenv
import requests
from pprint import pprint
from datetime import datetime, timezone
import base64


load_dotenv()
EMAIL = os.getenv("EMAIL")
SENHA = os.getenv("PASSWORD")

# -------------------------------------------------------------------------------------------------
# METODO DE AUTENTICAÇÃO 1 (USANDO EMAIL E SENHA)
def query_incidents(email, password, start_time=None, end_time=None, actor_ids=None, 
                   service_names=None, incident_criteria=None, limit=500):
  
    url = f"https://www.myshn.net/shnapi/rest/external/api/v1/queryIncidents?limit={limit}"
    
   
    payload = {}
    if start_time:
        payload["startTime"] = start_time
    if end_time:
        payload["endTime"] = end_time
    if actor_ids:
        payload["actorIds"] = actor_ids
    if service_names:
        payload["serviceNames"] = service_names
    if incident_criteria:
        payload["incidentCriteria"] = incident_criteria
    
    try:
        response = requests.post(
            url,
            auth=(email, password),
            json=payload
        )
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        print(f"Error querying incidents: {e}")
        return None

# incidents = query_incidents(EMAIL, SENHA, 10)
# pprint(incidents)


# -------------------------------------------------------------------------------------------------
# METODO DE AUTENTICAÇÃO 2 (USANDO TOKEN) -> Token JWT
def get_auth_token(email, password):
    
    url = "https://www.myshn.net/neo/neo-auth-service/oauth/token"
    
    params = {
        "grant_type": "password"
    }
    
    headers = {
        "x-auth-username": email,
        "x-auth-password": password
    }
    
    try:
        response = requests.post(
            url,
            params=params,
            headers=headers
        )
        response.raise_for_status()
        return response.json().get("access_token")
        
    except requests.exceptions.RequestException as e:
        print(f"Error getting auth token: {e}")
        return None

# token = get_auth_token(EMAIL, SENHA)
# pprint(token)


# -------------------------------------------------------------------------------------------------
# USANDO O TOKEN PARA FAZER A CHAMADA
def query_incidents_token(token, actor_ids=None, service_names=None, incident_criteria=None, limit=500):
    
    # do inicio do ano até data atual
    now = datetime.now(timezone.utc)
    start_time = f"{now.year}-01-01T00:00:00Z"
    end_time = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    url = f"https://www.myshn.net/shnapi/rest/external/api/v1/queryIncidents?limit={limit}"

    payload = {
        "startTime": start_time,
        "endTime": end_time
    }

    if actor_ids:
        payload["actorIds"] = actor_ids
    if service_names:
        payload["serviceNames"] = service_names
    if incident_criteria:
        payload["incidentCriteria"] = incident_criteria

    headers = {
        "x-access-token": token,
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            url,
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Erro ao consultar incidentes: {e}")
        return None

# incidents = query_incidents_token(token)
# pprint(incidents)

# -------------------------------------------------------------------------------------------------
# METODO DE AUTENTICAÇÃO 3 (USANDO OAUTH2)
def get_oauth2_token(client_id, client_secret, scopes=None):
    
    # url = "https://auth.trellix.com/auth/realms/IAM/protocol/openid-connect/token"
    # url = "https://dashboard-us.ui.skyhigh.cloud/neo/neo-auth-service/oauth/token?grant_type=iam_token&skip_audit=true"
    url = " https://www.myshn.net/neo/neo-auth-service/oauth/token?grant_type=password"


    credentials = f"{client_id}:{client_secret}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    
    headers = {
        "Authorization": f"Basic {encoded_credentials}"
    }
    
    params = {
        "grant_type": "client_credentials"
    }
    
    if scopes:
        params["scope"] = scopes
        
    try:
        response = requests.post(
            url,
            headers=headers,
            params=params
        )
        response.raise_for_status()
        return response.json().get("access_token")
        
    except requests.exceptions.RequestException as e:
        print(f"Error getting OAuth2 token: {e}")
        return None

# token = get_oauth2_token("d692d2d0bb1f772b715afa0298e072e8", "51QYGV2b9GrqlhkZmukHcbvm7YzTsHD4")
# print(token)

# https://www.myshn.net/shnapi/rest/external/api/v1/modifyIncidents


def modify_incidents(email, password):
    url = "https://www.myshn.net/shnapi/rest/external/api/v1/modifyIncidents"
    
    payload = [{
        "incidentId": "EPO-4458",
        "changeRequests": {
            "WORKFLOW_STATUS": "VIEWED",
        }
    }]
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    try:
        response = requests.post(
            url,
            auth=(email, password),
            headers=headers,
            json=payload
        )
        response.raise_for_status()  # Lança exceção para erros HTTP (4xx/5xx)
        
        try:
            data = response.json()
            print(data)
            return data
        except ValueError:
            print("Resposta não é JSON.")
            return response.text  # Retorna conteúdo bruto se não for JSON
            
    except requests.exceptions.RequestException as e:
        print(response.json())
        return None

    
modify_incidents(EMAIL, SENHA)
