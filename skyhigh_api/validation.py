from schema import Schema, And, Or, Optional, Regex
import re


schemas = {}
schemas['bpsTenantId'] = Schema(Regex(r'\w{8}-\w{4}-\w{4}-\w{4}-\w{12}'))
schemas['shnTenantId'] = Schema(Regex(r'\d{1,7}'))


#--------------------------
# General Schemas
#--------------------------
schemas['ipv4'] = Schema(Regex(r'^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$'))
schemas['cidr'] = Schema(Regex(r'^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:3[0-2]|[1-2]?\d)$'))
schemas['booleanString'] = Schema(Regex(r'(?:true|false)', re.IGNORECASE))
schemas['mimeType'] = Schema(Regex(r'^[a-zA-Z0-9\-\+\.]+\/[a-zA-Z0-9\-\+\.]+$'))
schemas['MWG.ApplicationType'] = Schema(Regex(r'^\d+(?:\-[a-zA-Z-]+)?$'))
schemas['MWG.ApplicationServiceGroupType'] = Schema(Regex(r'^ServiceGroup_\d+$'))
schemas['MWG.UrlCategory'] = Schema(Regex(r'^\d+$'))
schemas['PEMCertificate'] = Schema(Regex(r'^-----BEGIN CERTIFICATE-----.+-----END CERTIFICATE-----\n?$', re.DOTALL))
schemas['HostAndCertificate'] = Schema({'host': str, 'certificate': schemas['PEMCertificate'], 'name': str})

#--------------------------
# List Schemas
#--------------------------

# Each type of list and a schema for entries in that list
# This is reused later to build schemas for list objects of each type
schemas['listObjectEntries'] = {
    'MWG.SmartMatchList': Schema([{'value': str, 'comment': str}]),
    'RegExJSi.List': Schema([{'value': str, 'comment': str}]),
    'VECTOR<STRING>': Schema([{'value': str, 'comment': str}]),
    'VECTOR<NUMBER>': Schema([{'value': Or(int, float), 'comment': str}]),
    'VECTOR<MWG.ApplicationType>': Schema([{'value': schemas['MWG.ApplicationType'], Optional('comment'): str}]),
    'VECTOR<MWG.ApplicationServiceGroupType>': Schema([{'value': schemas['MWG.ApplicationServiceGroupType'], 'comment': str}]),
    'VECTOR<MWG.UrlCategory>': Schema([{'value': Or(schemas['MWG.UrlCategory'], int), 'comment': str}]),
    'VECTOR<MWG.HostAndCertificate>': Schema([{'value': schemas['HostAndCertificate'], 'comment': str}]),
    'VECTOR<MediaType>': Schema([{'value': schemas['mimeType'], 'comment': str}]),
    'VECTOR<Net.IPRange>': Schema([{'value': {'begin': schemas['ipv4'], 'end': schemas['ipv4']}, 'comment': str}]),
    'VECTOR<Net.IP>': Schema([{'value': schemas['ipv4'], 'comment': str}]),
    'VECTOR<YouTubeVideoCategory>': Schema([{'value': str, 'comment': str}]),
    'RBI.ClipboardControlList': Schema([{'value': dict, 'comment': str}]),
    'UCE.FileTransferControlList': Schema([{'value': dict, 'comment': str}]),
    'VECTOR<MWG.ServiceSubCategoryAndActivityType>': Schema([{'value': dict, 'comment': str}]),
    'VECTOR<MWG.ServiceGroupAndActivityType>': Schema([{'value': dict, 'comment': str}]),
    'MAP<STRING, STRING>': Schema({And(str, lambda s : len(s) > 0): {'value': str, 'comment': str}}),
}
schemas['listType'] = Schema(lambda n : n in schemas['listObjectEntries'].keys())
schemas['listCollectionEntry'] = Schema({'id': str,
    'name': str,
    'comment': str,
    'type': lambda n : schemas['listType'].is_valid(n),
    Optional('catalogName'): str})
schemas['listCollection'] = Schema({'revision': str,
    'etag': str,
    'entries': [lambda n : schemas['listCollectionEntry'].is_valid(n)],
    str: object})

# Create schemas for each list type using the listObjectEntries schemas defined above
schemas['listObjects'] = {}
for key in schemas['listObjectEntries'].keys():
    schemas['listObjects'][key] = Schema({'entries': schemas['listObjectEntries'][key],
        'type': key,
        'name': str,
        'id': str,
        Optional('comment'): str,
        Optional('variable'): str,
        Optional('listFeature'): str,
        Optional('catalogName'): str,
        Optional('approvals'): bool,
        Optional('createdBy'): str,
        Optional('automaticAssignment'): bool,
        Optional('notifications'): bool,
        Optional('created'): int,
        Optional('lastUpdated'): int,
        Optional('tenantId'): int,
        Optional('etag'): str,
        Optional('revision'): str})

schemas['updateListObject'] = Schema({'entries': [lambda n : schemas['listObjectEntry'].is_valid(n)],
    'type': lambda n : schemas['listType'].is_valid(n),
    'id': str,
    'comment': str,
    'name': str,
    'variable': str,
    'listFeature': str})


#--------------------------
# Location Schemas
#--------------------------

schemas['clientIdType'] = Schema(lambda n : n in ['userFqdn', 'ipv4', 'fqdn', 'clientAddress'])
schemas['logStorageRegion'] = Schema(lambda n : n in ['default', 'na', 'eu', 'uk', 'sg', 'uae', 'in', 'au', 'sa'])
schemas['newLocationObject'] = Schema({'name': str,
    'ipRangeMappingEntries': [{
        'ipRangeValue': schemas['cidr'],
        'comment': str}],
    'ipSecMappingDetails': Or({
        'clientIdType': schemas['clientIdType'],
        'clientId': str,
        'clientAddress': str,
        'sharedSecret': str,
        'subnets': [{
            'value': schemas['cidr'],
            'comment': str
        }],
        'defineSubnets': bool,
    }, {}),
    'samlAuthenticationId': str,
    'logStorageRegion': schemas['logStorageRegion'],
    'greTunnelMappingDetails': {
        'provisionedTunnels': [{
            'externalIp': schemas['ipv4'],
            'status': bool,
            'comment': str,
            'index': int,
            'tunnelDetails': list
        }],
        'excludedIpRanges': [{
            'value': schemas['cidr'],
            'comment': str
        }]
    },
    Optional('id'): str})