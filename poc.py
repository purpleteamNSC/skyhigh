# Execução
import os
from dotenv import load_dotenv
from pprint import pprint
load_dotenv()

from skyhigh_api.webclient import WebClient


client = WebClient(
    os.getenv('EMAIL'),
    os.getenv('PASSWORD'),
    os.getenv('TENANT_ID'),
)



# _______________________________________________________________

# PEGANDO A LISTA
l = client.GetList(id='Global_Blocked_User_Names')

# ADICIONAR
# l['entries'].append({'value': 'apolo'})
# client.UpdateList(l)

# pegar o input
value_k = input('Valor a ser excluido: ')

# LISTAR TODOS
for entrie in l['entries']:
    if entrie['value'] == f'{value_k}':
        l['entries'].remove(entrie)
        client.UpdateList(l)

for entrie in l['entries']:
    print(entrie)