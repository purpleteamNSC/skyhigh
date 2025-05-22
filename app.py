# Execução
import os
from dotenv import load_dotenv
from pprint import pprint
load_dotenv()

from skyhigh_api.webclient import WebClient

# WebClient = WebClient('email', 'password', 'tenantId', 'environment')
# print(os.getenv('EMAIL'))

client = WebClient(
    os.getenv('EMAIL'),
    os.getenv('PASSWORD'),
    os.getenv('TENANT_ID'),
)

# pprint(client.GetListCollection('VECTOR<STRING>'))
l = client.GetList(id='Global_Blocked_User_Names')
# l = l['entries']

l['entries'].append({'value': 'xurupita2', 'comment': 'xurupita coment2'})
client.UpdateList(l)

print(l)

# l['entries'].pop({'value': 'xurupita', 'comment': 'xurupita coment'})
# print(l['entries'][0])



# if l['entries'][0]['value'] == 'xurupita':
#     l['entries'].pop(0)
   


# client.UpdateList(mylist)
