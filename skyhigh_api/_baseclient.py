import requests
import re
from datetime import datetime
import json
from skyhigh_api.validation import schemas

allScopes = ['api.pr.r', 'apollo.admin', 'dhub.app.r', 'dhub.app.w', 'dhub.cmn.res.r', 'dhub.sp.r', 'dhub.sp.u', 'dhub.w', 'dhub.xo.cus.r', 'dhub.xo.et.r', 'dhub.xot.sub.r', 'dp.im.r', 'ens.am.a', 'ens.am.r', 'ens.am.ta', 'ens.am.tr', 'ens.am.ve', 'ens.am.vs', 'ens.atp.a', 'ens.atp.r', 'ens.atp.vs', 'ens.comn.a', 'ens.comn.r', 'ens.comn.ta', 'ens.comn.tr', 'ens.comn.vs', 'ens.fw.a', 'ens.fw.r', 'ens.fw.vc', 'ens.fw.vp', 'ens.fw.vr', 'ens.fw.vs', 'ens.vrs.a', 'ens.vrs.r', 'ens.vrs.ta', 'ens.vrs.tr', 'ens.wp.a', 'ens.wp.r', 'ens.wp.ta', 'ens.wp.tr', 'ens.wp.vs', 'ens20.endp.a', 'ens20.endp.r', 'epo.adit.a', 'epo.adit.r', 'epo.admin', 'epo.agnt.d', 'epo.agnt.w', 'epo.cds.r', 'epo.dash.p', 'epo.dash.r', 'epo.dir.a', 'epo.dxlc.a', 'epo.dxlc.r', 'epo.eagt.a', 'epo.eagt.r', 'epo.eagt.ta', 'epo.eagt.tr', 'epo.evt.r', 'epo.evt.rp', 'epo.ldap.r', 'epo.ops.admin', 'epo.pevt.r', 'epo.pevt.rp', 'epo.qery.g', 'epo.qery.u', 'epo.reg_token', 'epo.repo.mv', 'epo.resp.ra', 'epo.resp.ru', 'epo.sdlr.e', 'epo.sdlr.r', 'epo.tag.a', 'epo.tagc.a', 'epo.tagc.u', 'epo.task.ap', 'epo.tree.m', 'epo.ubp.ae', 'epo.ubp.ap', 'epo.ubp.r', 'frp.act.r', 'frp.po.r', 'frp.po.x', 'frp.prop.v', 'hyb.plc.r', 'hyb.plc.x', 'ins.noti.r', 'ins.suser', 'ins.user', 'mcp.hd.xx', 'mcp.pc.xx', 'mde.po.r', 'mde.po.x', 'mde.usr.x', 'mi.sys.baseline.retrieve', 'mi.sys.baseline.upload', 'mi.sys.bundle.promote', 'mi.sys.bundle.upload', 'mi.sys.support', 'mi.sys.tenant.provision', 'mi.sys.tenant.wipe', 'mi.sys.wh', 'mi.user.config', 'mi.user.investigate', 'mne.act.r', 'mne.po.a', 'mne.po.r', 'mne.prop.v', 'mp.cmn.res.r', 'mp.cus.r', 'mp.sub.r', 'mp.sub.w', 'mp.xo.app.r', 'mp.xo.et.r', 'mpa.adm.r', 'mpa.adm.x', 'mpa.cnf.r', 'mpa.cnf.x', 'mpa.plc.r', 'mpa.plc.x', 'mpa.rpt.r', 'mpa.rpt.x', 'mv:m:admin', 'mvs.endp.a', 'mvs.endp.r', 'ndlp.cpo.a', 'ndlp.cpo.r', 'ndlp.dash.r', 'ndlp.po.a', 'ndlp.po.r', 'openid', 'pbc:sso', 'shn.con.r', 'soc.act.gl', 'soc.act.tg', 'soc.epy.w', 'soc.evt.vi', 'soc.hts.c', 'soc.hts.r', 'soc.rts.c', 'soc.rts.r', 'syn.perm.1', 'syn.perm.2', 'tie.admin', 'tie.view', 'tks.ck.r', 'tks.ck.x', 'uam.srt', 'uam:admin', 'uam:system:admin', 'udlp.cl.f', 'udlp.cl.m', 'udlp.cl.rd', 'udlp.cl.u', 'udlp.cl.v', 'udlp.dfn.f', 'udlp.dfn.u', 'udlp.dfn.v', 'udlp.dis.f', 'udlp.ds.a', 'udlp.ds.br', 'udlp.ds.g', 'udlp.hd.amrk', 'udlp.hd.aok', 'udlp.hd.arqk', 'udlp.hd.auk', 'udlp.im.f', 'udlp.im.vf', 'udlp.im.vm', 'udlp.imdrl.f', 'udlp.imdrs.f', 'udlp.imdum.f', 'udlp.oe.f', 'udlp.pc.v', 'udlp.pm.f', 'udlp.pm.tdscvr', 'udlp.pm.tdt', 'udlp.pm.tdvc', 'udlp.pm.u', 'udlp.pm.v', 'vnxt.api.r', 'vnxt.api.w', 'web.adm.r', 'web.adm.x', 'web.cnf.r', 'web.cnf.x', 'web.lst.r', 'web.lst.x', 'web.plc.r', 'web.plc.x', 'web.rpt.r', 'web.rpt.x', 'web.usr.r', 'web.usr.x', 'web.xprt.r', 'web.xprt.x', 'xdr.inc.w']
fabrics = {
    'gov': {
        'client': 'UI',
        'domain': 'govshn.net',
        'iam_token': 'https://iam.govshn.net/iam/v1.1/token',
        'iam_authorize': 'https://www.govshn.net/neo/neo-auth-service/oauth/token',
        'key': 'gov',
        'name': 'GovCloud'
    },
    'na': {
        'client': '0oae8q9q2y0IZOYUm0h7',
        'domain': 'myshn.net',
        'iam_token': 'https://iam.skyhigh.cloud/iam/v1.1/token',
        'iam_authorize': 'https://www.myshn.net/neo/neo-auth-service/oauth/token',
        'key': 'na',
        'name': 'North America Production'
    },
    'eu': {
        'client': '0oae8q9q2y0IZOYUm0h7',
        'domain': 'myshn.eu',
        'iam_token': 'https://iam.skyhigh.cloud/iam/v1.1/token',
        'iam_authorize': 'https://www.myshn.eu/neo/neo-auth-service/oauth/token',
        'key': 'eu',
        'name': 'Europe Production'
    }
}

class _baseClient:

    _fabric = {}
    _iamToken = None
    _authToken = None
    _refreshToken = None
    _tokenExpiration = -1
    _authScopes = []
    _userId = ''
    _userEmail = ''
    _userName = ''
    _tenantId = ''
    _shntenantId = ''
    _tenantName = ''

    def __init__(self, email, password, tenantId, environment='na', **kwargs):
        """
        __init__(self, email, password, tenantId, environment='na', **kwargs)

        Initialize self.
            REQUIRED PARAMETERS
            email = (str) Skyhigh Security account user email address
            password = (str) Skyhigh Security account password

            OPTIONAL KEYWORD ARGUMENTS
            tenantId (str): Skyhigh Security tenant ID (formatted as 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX')
            environment = (str) Dictates which Skyhigh environment (or fabric) to use.  Options include 'na' (North America), 'eu' (Europe), and 'gov' (GovCloud). Defaults to 'na'.
            timeout = (int) Default request timeout value. (see https://docs.python-requests.org/en/latest/user/advanced/#timeouts) Can be overridden in class methods.
            proxies = (dict) Local proxy list (see https://docs.python-requests.org/en/latest/user/advanced/#proxies)
            verify = (bool or str) SSL/TLS verification options (see https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification)
        """

        # ------------------------------
        # Verify and assign input values
        # ------------------------------
        assert (email and isinstance(email, str)), 'username argument must be a non-empty string.'
        self._userName = email
        
        assert (password and isinstance(password, str)), 'password argument must be a non-empty string.'
        self._password = password

        assert (tenantId and isinstance(tenantId, str) and schemas['bpsTenantId'].is_valid(tenantId)), 'tenantId argument must be a str formatted as \'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX\'.'
        self._tenantId = {'tenantId': tenantId}


        assert (isinstance(environment, str) and environment in fabrics.keys()), 'Invalid \'environment\' argument.  Expected \'na\', \'eu\', or \'gov\'.'
        if not self._fabric:
            self._fabric = {}
        self._fabric.update(fabrics[environment])

        if 'timeout' in kwargs.keys():
            assert (isinstance(kwargs['timeout'], int) and kwargs['timeout'] > 0), 'timeout argument must be an int greater than 0.'
            self._timeout = kwargs['timeout']
        else:
            self._timeout = 30
        
        if 'proxies' in kwargs.keys():
            assert (isinstance(kwargs['proxies'], dict)), 'proxies argument must be of type dict.'
            self._proxies = kwargs['proxies']
        else:
            self._proxies = {}
        
        if 'verify' in kwargs.keys():
            assert (isinstance(kwargs['verify'], bool) or isinstance(kwargs['verify'], str)), 'verify argument must be of type bool or str.  If str, it must contain a path to certificates for verification.\nSee https://docs.python-requests.org/en/latest/user/advanced/#ssl-cert-verification for more info.'
            self._verify = kwargs['verify']
        else:
            self._verify = True
        
        self._session = requests.Session()
        self._session.proxies=self._proxies
        self._session.verify=self._verify

        self._authScopes = ['shn.con.r']
        self._iamToken = ''
        self._authToken = ''
        self._refreshToken = ''
        self._tokenExpiration = ''

    
    def _getAuthHeaders(self, scopes, **kwargs):
        """
        Returns an authentication token for Skyhigh Security APIs.
        
        gettoken(scopes)
        
        scopes (list of str): A list of scopes (permissions) for requested token.
        """
        if not isinstance(scopes, list) or set([type(e) for e in scopes]) != {str}:
            raise Exception('Argument \'scopes\' must be a list of strings.')

        # Return cached token if still valid and requested scopes are subset of current scopes
        if self._iamToken and (datetime.now().timestamp() < self._tokenExpiration - 30) and set(scopes).issubset(self._authScopes):
            return {'authorization': 'Bearer ' + self._iamToken,
                    'x-access-token': self._authToken,
                    'x-refresh-token': self._refreshToken}
        
        # Add requested scopes to token scopes if they're not already present
        if not set(scopes).issubset(self._authScopes):
            self._authScopes = list(set(scopes + self._authScopes))

        # Get new authentication token
        iamReq = requests.Request('POST', self._fabric['iam_token'],
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"client_id": self._fabric['client'],
                "grant_type": "password",
                "username": self._userName,
                "password": self._password,
                "scope": ' '.join(self._authScopes),
                "tenant_id": self._tenantId['tenantId']})

        iamReq = iamReq.prepare()
        iamResp = self._session.send(iamReq, timeout=kwargs.get('timeout', self._timeout))
        
        assert (iamResp.status_code == 200), 'IAM authentication failed with error: [{}] {}'.format(iamResp.status_code, iamResp.text)
        try:
            # Parse response and store IAM token
            j = json.loads(iamResp.text)
            self._iamToken = j['access_token']
            self._tokenExpiration = datetime.now().timestamp() + int(j['expires_in'])
        except:
            raise Exception('Failed to parse response to IAM authentication attempt.')

        # Exchange IAM token for authorization token
        authReq = requests.Request('POST', self._fabric['iam_authorize'],
            headers={"x-iam-token": j['access_token'],
                "content-type": "application/json"},
            params={"grant_type":"iam_token"},
            data={})

        authReq = authReq.prepare()
        authResp = self._session.send(authReq, timeout=self._timeout)
        
        if authResp.status_code == 200:
            try:
                # Parse response, store authorization token, and return headers
                j = json.loads(authResp.text)
                self._tenantId['legacyTenantId'] = j['tenantID']
                self._authToken = j['access_token']
                self._refreshToken = j['refresh_token']
                self._tokenExpiration = datetime.now().timestamp() + int(j['expires_in'])
                return {'authorization': 'Bearer ' + self._iamToken,
                    'x-access-token': self._authToken,
                    'x-refresh-token': self._refreshToken}
            except:
                raise Exception('Failed to parse response to authorization attempt.')
        else:
            raise Exception('Authorization failed with error: [{}] {}'.format(authReq.status_code, authReq.text))

    
    def GetCurrentTenant(self):
        return self._tenantId