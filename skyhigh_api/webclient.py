from skyhigh_api._baseclient import _baseClient, allScopes, fabrics
import json
import requests
import re
from datetime import datetime
from warnings import warn
from skyhigh_api.validation import schemas

web_urls = {
    'gov': {
        'policyBackup': 'https://webpolicy.govshn.net/api/policy/v2/PolicyMigrator/backup_customer_policy',
        'policyUpdate': 'https://webpolicy.govshn.net/api/policy/v1/commit',
        'rootPolicy': 'https://webpolicy.govshn.net/api/policy/v1/gps/content/product/Web/Policy'
    },
    'na': {
        'policyBackup': 'https://webpolicy.cloud.mvision.skyhigh.cloud/api/policy/v2/PolicyMigrator/backup_customer_policy',
        'policyUpdate': 'https://webpolicy.cloud.mvision.skyhigh.cloud/api/policy/v1/commit',
        'rootPolicy': 'https://webpolicy.cloud.mvision.skyhigh.cloud/api/policy/v1/gps/content/product/Web/Policy'
    },
    'eu': {
        'policyBackup': 'https://webpolicy.cloud.mvision.skyhigh.cloud/api/policy/v2/PolicyMigrator/backup_customer_policy',
        'policyUpdate': 'https://webpolicy.cloud.mvision.skyhigh.cloud/api/policy/v1/commit',
        'rootPolicy': 'https://webpolicy.cloud.mvision.skyhigh.cloud/api/policy/v1/gps/content/product/Web/Policy'
    }
}

class WebClient(_baseClient):
    
    def __init__(self, email, password, tenantId='', environment='na', **kwargs):
        """
        __init__(self, email, password, tenantId='', environment='na', **kwargs)

        Initialize self.
            REQUIRED PARAMETERS
            email = (str) Skyhigh Security account user email address
            password = (str) Skyhigh Security account password
            tenantId (str): Skyhigh Security tenant ID (formatted as 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX')

            OPTIONAL KEYWORD ARGUMENTS
            environment = (str) Dictates which Skyhigh environment (or fabric) to use.  Options include 'na' (North America), 'eu' (Europe), and 'gov' (GovCloud). Defaults to 'na'.
            timeout = (int) Sets the default request timeout value (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts).  Can be overridden in individual method calls.
            proxies = (dict) Sets the default proxy list (see https://docs.python-requests.org/en/latest/user/advanced/#proxies).  Can be overridden in individual method calls.
            verify = (bool or str) Sets the default SSL/TLS verification options (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification).  Can be overridden in individual method calls.
        """

        if not isinstance(environment, str) and not environment in fabrics.keys():
            raise Exception('Invalid \'environment\' argument.  Expected \'na\', \'eu\', or \'gov\'.')
        
        if not self._fabric:
            self._fabric = {}
        self._fabric.update(web_urls[environment])
        self._policyUpdateURL = web_urls[environment]['policyUpdate']
        self._skyhighPolicyURL = web_urls[environment]['rootPolicy']
        self._customerPolicyURL = ''

        super().__init__(email, password, tenantId, environment, **kwargs)

        self._customerPolicyURL = self._skyhighPolicyURL + '/customer_' + self._tenantId['tenantId'].replace('-', '_').lower() + '/Policy'
        

    # Adds object declaration (e.g. list, feature config) to root of policy
    def _addRef(self, ref, **kwargs):
        if not isinstance(ref, str):
            raise Exception('Argument \'ref\' must be of type str.')

        # Create change for root policy node
        rootPolicy = self._getObject('', ['web.adm.r'], 'policy ruleset', **kwargs)
        valueSplit = rootPolicy['object']['value'].split('\n')
        valueSplit.insert(1, '\t' + ref)
        newValue = '\n'.join(valueSplit)
        return {
            "content": {
                "name": "Policy",
                "value": newValue
            },
            "hash": rootPolicy['etag'],
            "name": "customer policy root node",
            "op": "policy.node.update",
            "path": ""
        }


    # Commits supplied list of changes to tenant
    def _commit(self, changes, scopes, **kwargs):
        h = self._getAuthHeaders(scopes)
        h['TENANT_ID'] = self._tenantId['tenantId'].upper()

        if changes:
            commitReq = requests.post(self._policyUpdateURL,
                headers=h,
                json=changes,
                timeout=kwargs.get('timeout', self._timeout),
                proxies=self._proxies,
                verify=self._verify)

            if commitReq.status_code == 200:
                return json.loads(commitReq.text)
            else:
                raise Exception('Failed to commit changes with error: {}'.format(commitReq.text))
        else:
            raise Exception("No changes ready to commit.")


    # Searches for references to an object in the policy
    def _findRef(self, ref, recur=False, path=None, **kwargs):
        # If not a recursive call, start with root of policy
        if not path:
            path = self.GetRuleSet(**kwargs)['name']

        ruleSet = self.GetRuleSet(path=path, **kwargs)
        
        # Check contents of current ruleset
        if re.search('^(?:(?!\/\/).)*\\b' + ref + '.*$', ruleSet['value'], re.MULTILINE):
            return path

        # Find child rulesets
        children = re.findall(r'^\s*INCLUDE\s+"([^"]*)"', ruleSet['value'], re.MULTILINE)

        # Recursively call function for all child nodes
        if recur and children:
            for child in children:
                referenced = self._findRef(ref, recur, path=path + '/' + child, **kwargs)
                if referenced:
                    return referenced
            
        return False
    

    def _getRev(self, **kwargs):
        """
        Returns the revision number of the current policy version.
        
        GetLatestRevisionNumber()
        """
        try:
            h = self._getAuthHeaders(['web.adm.x'])
            h['X-Gps-Revision'] = 'latest'
            policyReq = requests.get(self._customerPolicyURL + '/settings',
                headers=h,
                timeout=kwargs.get('timeout', self._timeout),
                proxies=self._proxies,
                verify=self._verify)
        except Exception as e:
            raise Exception('Failed to get the latest revision with error: {}'.format(e))
        
        return policyReq.headers['X-Revision']


    def _getObject(self, url, scopes, desc, **kwargs):
        rev = kwargs.get('rev', 'latest')
        timeout = kwargs.get('timeout', self._timeout)
        proxies = kwargs.get('proxies', self._proxies)
        verify = kwargs.get('verify', self._verify)
        url = self._customerPolicyURL + url
        h = {"authorization": self._getAuthHeaders(scopes)['authorization']}
        h['X-GPS-Revision'] = str(rev)

        objectResp = self._session.get(url,
            headers=h,
            timeout=timeout,
            proxies=proxies,
            verify=verify)
        
        if objectResp.status_code == 200:
            retval = {}
            retval['object'] = json.loads(objectResp.text)
            if 'X-Revision' in objectResp.headers.keys():
                retval['revision'] = objectResp.headers['X-Revision']
            if 'ETag' in objectResp.headers.keys():
                retval['etag'] = objectResp.headers['ETag']
            return retval
        else:
            raise Exception('Failed to get ' + desc + ' with error: {}'.format(objectResp.text))
    

    def _removeRef(self, ref, **kwargs):
        scopes = ['web.adm.r', 'web.adm.x']
        if not isinstance(ref, str):
            raise Exception('Trying to remove an invalid reference.')

        # Get root node of policy
        r = self._getObject('', scopes, 'root policy node', **kwargs)

        # Remove one reference in root node
        #newValue = re.sub('^(?:(?!\/\/).)*\\b' + ref + '.*$', '', r['value'], count=1, flags=re.MULTILINE)
        lines = r['object']['value'].split('\n')
        delete = [i for i, x in enumerate(lines) if re.match(r'^(?:(?!\/\/).)*\b' + ref + r'.*$', x)]
        if len(delete) < 1:
            raise Exception('Failed to find a reference to the object in the root of the policy.')
        if len(delete) > 1:
            raise Exception('Found multiple references to the object in the root of the policy.')
        lines.pop(delete[0])
        newValue = '\n'.join(lines)
        
        return {
            "content": {
                "name": "Policy",
                "value": newValue
            },
            "hash": r['etag'],
            "name": "customer policy root node",
            "op": "policy.node.update",
            "path": ""
        }


    def CreateList(self, newList, **kwargs):
        """
        Creates a new list object in the web policy.

        CreateList(newList)

        Arguments:
            newList (dict): New list object.  Must be validated by schemas['listObject'].

        Optional Keyword Arguments:
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        scopes = ['web.lst.r', 'web.lst.x']

        # Validation of newList
        assert 'type' in newList.keys(), 'List object must contain a \'type\'.'
        assert schemas['listType'].validate(newList['type']), 'Invalid list type provided.  See schemas[\'listType\'] for valid types.'
        assert schemas['listObjects'][newList['type']].validate(newList), 'Invalid list provided.  Please see schemas[\'listObject\'] for validation info.'

        lc = self.GetListCollection(fullObject=True, **kwargs)
        if newList['id'] in [l['id'] for l in lc['object']]:
            raise Exception('A list with id \'' + newList['id'] + '\' already exists in the latest policy revision (' + lc['revision'] + ').')
        
        if newList['name'] in [l['name'] for l in lc['object']]:
            raise Exception('A list with name \'' + newList['name'] + '\' already exists in the latest policy revision (' + lc['revision'] + ').')
        
        if not 'variable' in newList.keys():
            newList['variable'] = newList['id']
        newList['listFeature'] = 'User defined'

        # Remove 'etag' or 'revision' if present
        if 'etag' in newList.keys():
            del newList['etag']
        if 'revision' in newList.keys():
            del newList['revision']

        # Check for a reference in the policy
        ref = newList['type'] + ' ' + newList['variable']
        if self._findRef(ref, **kwargs):
            raise Exception('List with name \'' + newList['id'] + '\' is already referenced in the root of the latest policy revision (' + lc['revision'] + ').')
        ref = ref + ' = ["' + newList['id'] + '"]'

        # Collect changes to be committed
        changes = []
        changes.append(self._addRef(ref))
        changes.append({"absolute": False,
            "content": newList,
            "hash": "0",
            "name": newList['name'],
            "op": "lists.single.create",
            "path": '/' + newList['id']})
        lc['object'].append({"id": newList['id'],
            "name": newList['name'],
            "type": newList['type'],
            "comment": newList['comment']})
        changes.append({"content": lc['object'],
            "hash": lc['etag'],
            "op": "lists.collection.update",
            "path": "/lists"})
        self._commit(changes, scopes)


    def CreateLocation(self, newLoc, **kwargs):
        """
        Creates a new location object in Web Gateway Setup.
        
        CreateLocation(newLoc)
        
        Arguments:
            newLoc (dict): New location object.  Must be validated by schemas['newLocationObject'].
        
        Optional Keyword Arguments:
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
            """
        # Validate new location
        assert schemas['newLocationObject'].validate(newLoc), 'Invalid location object provided.  Please refer to location examples in the documentation.'

        # Pull existing list of locations
        scopes = ['web.plc.r', 'web.plc.x']
        url = '/locations'
        locResp = self._getObject(url, scopes, 'locations', **kwargs)
        etag = locResp['etag']
        locResp = locResp['object']

        # Check for existing location with same name or id
        if len([x for x in locResp['entries'].keys() if locResp['entries'][x]['name'] == newLoc['name']]) > 0:
            raise Exception('A location with name \'' + newLoc['name'] + '\' already exists.')
        if 'id' in newLoc.keys():
            if len([x for x in locResp['entries'].keys() if x == newLoc['id']]) > 0:
                raise Exception('A location with id \'' + newLoc['id'] + '\' already exists.')
        else:
            # Select new id for location
            newLoc['id'] = 'custom_location_' + str(round(datetime.now().timestamp()))

        # Check for existing location with same client address
        if 'clientAddress' in newLoc['ipSecMappingDetails'].keys():
            if len([x for x in locResp['entries'].keys() if newLoc['ipSecMappingDetails']['clientAddress'] == locResp['entries'][x]['ipSecMappingDetails'].get('clientAddress', '')]) > 0:
                raise Exception('A location with client address \'' + newLoc['ipSecMappingDetails']['clientAddress'] + '\' already exists.')
        
        # Check if SAML config exists
        if 'samlAuthenticationId' in newLoc.keys():
            samlConfigs = self.GetSAMLConfigs()
            if not newLoc['samlAuthenticationId'] in samlConfigs.keys():
                raise Exception('SAML config with id \'' + newLoc['samlAuthenticationId'] + '\' does not exist.')

        # Queue and commit changes
        locations = locResp['entries']
        locations[newLoc['id']] = newLoc
        changes = []
        changes.append({'op': 'common_entities.single.update',
            'name': 'Locations Collection',
            'path': '/locations',
            'absolute': 'false',
            'content': {
                    'entries': locations,
                    'name': 'Locations Collection',
                    'id': 'locations'
            },
            'hash': etag})
        self._commit(changes, scopes, **kwargs)

        # Pull location and return it
        locations = self.GetLocations()
        return locations[newLoc['id']]


    def DeleteList(self, id=None, name=None, **kwargs):
        """
        Deletes a list from the policy.  If an uncommitted change to create the list exists, that will be removed.
        
        DeleteList(id=None, name=None)
        
        One of the following keyword arguments must be supplied:
            id (str): The ID of the list to be deleted.
            name (str): The name of the list to be deleted.

        Optional Keyword Arguments:
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        scopes = ['web.lst.r', 'web.lst.x']

        l = None
        # Pull and validate
        if isinstance(id, str):
            l = self.GetList(id=id)
        if isinstance(name, str):
            if l:
                if name != l['name']:
                    raise Exception('Found list with id=\'' + id + '\', but name does not match \'' + name + '\'.')
            else:
                l = self.GetList(name=name)

        # Queue change to root policy removing any references to the list
        lc = self._getObject('/lists', scopes, 'list collection', **kwargs)
        changes=[]
        changes.append(self._removeRef(ref=l['type'] + '\\s+' + (l['variable'] if 'variable' in l.keys() else l['id']) + '\\s*=\\s*\\[\\s*\\"\\s*' + l['id'] + '\\s*\\"\\s*\\]'))

        # Check for additional references in root node (_removeRef only removes one)
        ref = l['variable'] if 'variable' in l.keys() else l['id']
        regEx = '^(?:(?!\\/\\/).)*\\b' + ref + '.*$'
        if re.search(regEx, changes[0]['content']['value'], flags=re.MULTILINE):
            raise Exception('List still referenced in the root of the policy.')

        # Recursively search for references to list in all child nodes
        children = re.findall(r'^\s*INCLUDE\s+"([^"]*)"', changes[0]['content']['value'], re.MULTILINE)
        if children:
            for child in children:
                referenced = self._findRef(ref, recur=True, path='/' + child, **kwargs)
                if referenced:
                    raise Exception('List still referenced in the policy at path \'' + referenced + '\'.')

        # Queue change to list collection
        for x in lc['object']:
            if x['id'] == l['id']:
                lc['object'].remove(x)
                break
        changes.append({"content": lc['object'],
            "hash": lc['etag'],
            "op": "lists.collection.update",
            "path": "/lists"})

        # Queue change to delete list
        changes.append({'absolute': False,
            'content': None,
            'name': l['name'],
            'op': 'lists.single.delete',
            'path': '/' + l['id']})

        self._commit(changes, scopes, **kwargs)


    def DeleteLocation(self, id='', name='', **kwargs):
        if not (id or name) or not (isinstance(id, str) and isinstance(name, str)) or (id and name):
            raise Exception('Either \'id\' or \'name\' must be specified as type str.  Do not specify both.')

        scopes = ['web.plc.x']
        url = '/locations'

        # Pull current list of locations
        locResp = self._getObject(url, scopes, 'locations', **kwargs)
        locations = locResp['object']['entries']
        
        # Find location to be deleted
        matches = [key for key in locations.keys() if (id and locations[key]['id'] == id) or (name and locations[key]['name'] == name)]
        if len(matches) != 1:
            raise Exception("Failed to find location specified" if len(matches) < 1 else "Multiple matching locations found.")
        
        # Queue and commit changes
        changes = []
        del locations[matches[0]]
        changes.append({'op': 'common_entities.single.update',
            'name': 'Locations Collection',
            'path': '/locations',
            'absolute': 'false',
            'content': {
                    'entries': locations,
                    'name': 'Locations Collection',
                    'id': 'locations'
            },
            'hash': locResp['etag']})
        
        self._commit(changes, scopes, **kwargs)   


    def DownloadPolicyBackup(self, password, **kwargs):
        """
        Downloads a backup of the current policy as a `bytes` object.

        DownloadPolicyBackup(password)

        Arguments:
            password (str): Password to decrypt the policy backup.
        
        Optional Keyword Arguments:
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        assert(isinstance(password, str) and password), 'Argument \'password\' must be a non-empty string.'

        scopes = ['web.adm.r', 'web.adm.x']
        url = self._fabric['policyBackup']
        h = {"authorization": self._getAuthHeaders(scopes)['authorization']}
        h['x-auth'] = password
        h['tenant_id'] = self._tenantId['tenantId'].upper()

        resp = self._session.get(url,
            headers=h,
            timeout=kwargs.get('timeout', self._timeout),
            proxies=self._proxies,
            verify=self._verify)
        
        if resp.status_code == 200:
            return resp.content
        else:
            raise Exception('Failed to get policy backup with error: {}'.format(resp.text))


    def GetList(self, id=None, name=None, **kwargs):
        """
        Returns a Skyghigh SSE Web policy list object (including list contents) as a 'dict' object.

        getList(id=None, name=None)

        One of the following keyword arguments must be supplied:
            id (str):  Contains the id of the list to return
            name (str): Contains the name of the list to return

        Optional Keyword Arguments:
            fullObject (bool): If True, returns the full object including metadata.  If False, returns only the object itself.
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        rev = kwargs.get('rev', 'latest')
        full = kwargs.get('fullObject', False)
        scopes = ['web.lst.r']
        if (not id and not name) or (id and name):
            raise Exception('You must specificy, exclusively, either listID or listName argument.')
        
        collection = self.GetListCollection(rev=rev)
        
        if name:
            try:
                listIndex = [i for i, l in enumerate(collection) if l['name'] == name][0]
                id = collection[listIndex]['id']
            except:
                raise Exception('Failed to find list name \'' + name + '\' in policy revision ' + rev + '.')

        retval = self._getObject('/' + id, scopes, 'list ' + id, **kwargs)
        if not full:
            retval = retval['object']

        if not 'id' in retval.keys():
            retval['id'] = id
        if not 'variable' in retval.keys():
            retval['variable'] = id

        return retval


    def GetListCollection(self, listType='', **kwargs):
        """
        Returns a collection of all lists details (excluding list contents) as a list of dicts.

        getAllLists(listType='')

        Arguments:
            listType (str): Optional str argument to specify a feature config type.  If specified, returns only feature configs of that type.
        
        Optional Keyword Arguments:
            fullObject (bool): If True, returns the full object including metadata.  If False, returns only the object itself.
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        full = kwargs.get('fullObject', False)
        scopes = ['web.lst.r', 'web.lst.x']

        retval = self._getObject('/lists', scopes, 'list collection', **kwargs)

        if listType:
            assert schemas['listType'].is_valid(listType), 'Invalid list type specified.  See schemas[\'listType\'] for valid types.'
            retval['object'] = [x for x in retval['object'] if x['type'] == listType]

        if full:
            return retval
        else:
            return retval['object']


    def GetLocations(self, **kwargs):
        """
        Returns a collection of all locations as a `dict`.
        
        GetLocations()
        
        Optional Keyword Arguments:
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        full = kwargs.get('fullObject', False)
        scopes = ['web.plc.r', 'web.plc.x', 'web.adm.r', 'web.adm.x']

        locResp = self._getObject('/locations', scopes, 'locations', **kwargs)
        
        try:
            if full:
                return locResp
            else:
                return locResp['object']['entries']
        except:
            raise Exception('Failed to parse location data.')


    def GetRuleSet(self, path='/', includeUI=False, **kwargs):
        """
        Returns a single ruleset, optionally including the UI JSON.

        GetRuleSet(path='/', includeUI=False)

        Arguments:
            path (str): Relative URL path to the ruleset in question.  '/' is the root of the customer policy.
            includeUI (bool): Indicates whether to include the contents of the UI JSON.
        
        Optional Keyword Arguments:
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        rev = kwargs.get('rev', 'latest')
        full = kwargs.get('fullObject', False)
        scopes = ['web.adm.r', 'web.adm.x']

        if not isinstance(path, str):
            raise Exception('Argument \'path\' must be of type str.')
        if not isinstance(includeUI, bool):
            raise Exception('Argument \'includeUI\' must be of type bool.')
        path = '/' if not path else path
        path = ('/' + path) if path[0] != '/' else path
        path = path[:-1] if path[-1] == '/' else path
    
        retval = self._getObject(path, scopes, 'policy ruleset', **kwargs)
        if not full:
            retval = retval['object']

        # Insert JSON UI info if requested
        if includeUI and 'ui' in retval.keys():
            uiURL = self._customerPolicyURL + re.search('(.*\/)[^\/]*', path).groups()[0] + retval['ui']

            h = self._getAuthHeaders(scopes)
            h['X-GPS-Revision'] = str(rev)

            uiResp = self._session.get(uiURL,
            headers=h,
            timeout=kwargs.get('timeout', self._timeout),
            proxies=self._proxies,
            verify=self._verify)
            if uiResp.status_code == 200:
                if full:
                    retval['ui']['object'] = uiResp.text
                    retval['ui']['path'] = uiURL.replace(self._customerPolicyURL, '')
                    if 'etag' in uiResp.headers.keys():
                        retval['ui']['etag'] = uiResp.headers['etag']
                    if 'X-Revision' in uiResp.headers.keys():
                        retval['revision'] = uiResp.headers['X-Revision']
                else:
                    retval['ui'] = uiResp.text
            else:
                raise Exception('Failed to get UI JSON with error [' + str(uiResp.status_code) + ']: ' + uiResp.text)
        
        return retval
    

    def GetSAMLConfigs(self, **kwargs):
        """
        Returns all SAML configuration objects as a `dict`.
        
        GetSAMLConfigs()
        
        Optional Keyword Arguments:
            fullObject (bool): If True, returns the full object including metadata.  If False, returns only the object itself.
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """
        full = kwargs.get('fullObject', False)
        scopes = ['web.cnf.r', 'web.cnf.x', 'web.adm.r', 'web.adm.x']
        url = '/saml'

        samlResp = self._getObject(url, scopes, 'SAML configurations', **kwargs)

        try:
            if full:
                return samlResp
            else:
                return samlResp['object']['entries']
        except:
            raise Exception('Failed to parse SAML configuration data.')


    def UpdateList(self, updatedList=None, id=None, name=None, entries=None, comment=None, **kwargs):
        """
        Updates an existing list object.  This can only update the entries in the list or the comment.  It will not change the type, name, id, or variable.

        UpdateList(updatedList: dict=None, id: str=None, name: str=None, entries: list=None, comment: str=None)

        Arguments:
            updatedList (dict): A list object in JSON format.  This is not required and can be built using keyword argument.  If listObject is provided with keyword arguments, they will overwrite listObject attributes.  For details on the format of this object, see schemas['listObject'].
            id (str): List ID
            name (str): Display name of list (visible in the List Catalog)
            entries (list of dict): A list of entries in the list.  See schemas['listObjectEntries'] for format details.
            comment (str): Optional description.
        
        Optional Keyword Arguments:
            timeout = (int) Overrides default request timeout value set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts)
            proxies = (dict) Overrides proxy list set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) Overrides SSL/TLS verification options set when WebClient object was initialized. (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)        
        
        Requirements:
            To identify the list to be updated, you must either provide an 'updatedList' object or 'id'.  Then, to update the contents of the identified list, you must provide 'entries', 'comment', and/or 'name' either as arguments or as members of 'updatedList'.
        """
        scopes = ['web.lst.x']
        # Validate updatedList or start with empty JSON
        if updatedList:
            if id:
                raise Exception('You must specify \'updatedList\' or \'id\' arguments exclusively.  You cannot specify both.')
            #if not schemas['updateListObject'].is_valid(updatedList):
            #    raise Exception('updatedList is not a valid list object.  See schemas[\'updatedListObject\'] for format info.')
            l = self.GetList(updatedList['id'], fullObject=True)
            updatedList['etag'] = l['etag']
        else:
            if not id:
                raise Exception('Parameters must include either \'listObject\' or \'id\' to identify the list to be updated.')
            if not (entries or comment or name):
                raise Exception('Parameters must include either \'listObject\' or one of the following to make changes to the list: \'entries\', \'name\', \'comment\'')
            updatedList = self.GetList(id=id)
        
        for x in [(name, 'name'), (entries, 'entries'), (comment, 'comment')]:
            if x[0]:
                updatedList[x[1]] = x[0]
        
        tag = updatedList['etag']
        del updatedList['etag']
        updatedList['listFeature'] = 'User defined'

        # Update
        # Create change
        change = {
            "absolute": False,
            "content": updatedList,
            "hash": tag,
            "op": "lists.single.update",
            "path": '/' + updatedList['id']
        }

        self._commit([change], scopes, **kwargs)

