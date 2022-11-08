'use strict'
const fs = require('fs')
const axios = require('axios')
const forge = require('node-forge')
const pki = require('node-forge').pki
const asn1 = require('node-forge').asn1
const pkcs12 = require('node-forge').pkcs12
const njwt = require('njwt')
const querystring = require('querystring')


class UdapClient {

    constructor(certFileName, certFilePassword, scopes, serverBaseUrl, clientId, redirectUri, organization_id, organization_name, purpose_of_use, upstream_idp_url)
    {
        this.certFileName = certFileName
        this.certFilePassword = certFilePassword
        this.scopes = scopes
        this.serverBaseUrl = serverBaseUrl
        this.clientId = clientId
        this.udapWellknownUrl = serverBaseUrl + '/.well-known/udap'
        this.redirectUri = redirectUri
        this.organization_id = organization_id
        this.organization_name = organization_name
        this.purpose_of_use = purpose_of_use
        this.upstream_idp_url = upstream_idp_url
    }

    static async udapDynamicClientRegistartion(serverBaseUrl, certFileName, certPassword, registrationObject)
    {
        //Full UDAP Client Flow
        // 1. Check for support in metadata
        // 2. UDAP Trusted DCR
        //
        const udapWellknownUrl = serverBaseUrl + '/.well-known/udap'
        console.log("Looking up additional server info from:" + udapWellknownUrl)
        try {
            var httpResponse = await this.getUdapMetaDataResposne(udapWellknownUrl)
            console.log("Return from meta")
            console.log(httpResponse)
            //Check for valid http response
            if (httpResponse.status == 200)
            {
                // check for udap support
                var data = httpResponse.data
                if (data.udap_versions_supported.length > 0)
                {
                    //TODO: We should get this from the signed_metadata, after validating the x5c.
                    var registerUrl = data.registration_endpoint
                    var signedJwt = this.createUdapSignedSoftwareStatement(registerUrl, certFileName, certPassword, registrationObject)
                    console.log(signedJwt)
                    var softwareStatement = {
                        "software_statement": signedJwt,
                        "udap":"1"
                    }
                    var dcrResponse = await this.postUdapRequest(softwareStatement,registerUrl)
                    console.log(dcrResponse)
                    return dcrResponse
                }
                else
                {
                    //TODO: Return response with no udap support
                    //Is this really a usecase?  Wrong version of UDAP in the future maybe?
                }
            } else
            {
                return data
            }
        }
        catch(error)
        {
            console.log("Error getting meta data")
            if(error.isAxiosError) { //Error from UDAP Server, or while calling UDAP Server.
                return {
                    statusCode: error.response.status,
                    body: error.response.data
                }
            }
            else {
                throw error

            }
        }
    }

    async udapAuthorizeRequest() {
      const udapWellknownUrl = this.serverBaseUrl + '/.well-known/udap'
      const state = UdapClient.randomString(24)
      var authorizeParameters = {
        "client_id": this.clientId,
        "response_type": "code",
        "state": state,
        "scope": this.scopes,
        "redirect_uri": this.redirectUri
      }

      //Tiered-Oauth if appropriate.
      if(this.upstream_idp_url) {
        authorizeParameters.idp = this.upstream_idp_url
      }
      console.log("Looking up additional server info from:" + udapWellknownUrl)
      var httpResponse = await UdapClient.getUdapMetaDataResposne(udapWellknownUrl)
      const authorizeUrl = httpResponse.data.authorization_endpoint

      const output = {
        "authorizeUrl": authorizeUrl + "?" + querystring.stringify(authorizeParameters),
        "state": state
      }

      return output
    }

    async udapTokenRequestClientCredentials()
    {
        try {
            var httpResponse = await UdapClient.getUdapMetaDataResposne(this.udapWellknownUrl)
            console.log("Return from meta")
            console.log(httpResponse)
            //Check for valid http response
            if (httpResponse.status == 200)
            {
                var tokenUrl = httpResponse.data.token_endpoint
                var signedJwt = this.createUdapSignedAuthenticationToken(tokenUrl)
                var tokenRequest = {
                    'grant_type': 'client_credentials',
                    'scope': this.scopes,
                    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion': signedJwt,
                    'udap':1
                }
                //var tokenResponse = await UdapClient.postUdapSignedJwt(tokenRequest,tokenUrl)

                //We can put this back into a method later- this needs to be NOT JSON- but url encoded.
                console.log("Ready to get token from the authz server at endpoint: " + tokenUrl)
                console.log(querystring.stringify(tokenRequest))
                try {
                  const tokenResponse = await axios.request({
                    'url': tokenUrl,
                    'method': 'post',
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'data': querystring.stringify(tokenRequest)
                  })
                  console.log(tokenResponse)
                  return tokenResponse
                }
                catch(e) {
                  console.log(e)
                  throw e
                }
            }
        }
        catch (e)
        {
            console.log(e)
            throw e
        }
    }

    async udapTokenRequestAuthCode(authCode)
    {
        var httpResponse = await UdapClient.getUdapMetaDataResposne(this.udapWellknownUrl)
        console.log("Return from meta")
        console.log(httpResponse)
        //Check for valid http response
        if (httpResponse.status == 200)
        {
            // check for udap support
            var data = httpResponse.data
            if (data.udap_versions_supported.length > 0)
            {
                var tokenUrl = data.token_endpoint
                var signedJwt = this.createUdapSignedAuthenticationToken(tokenUrl)
                var tokenRequest = {
                    'grant_type': 'authorization_code',
                    'redirect_uri': this.redirectUri,
                    'code': authCode,
                    'scope': this.scopes,
                    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                    'client_assertion': signedJwt,
                    'udap':1
                }
                //We can put this back into a method later- this needs to be NOT JSON- but url encoded.
                console.log("Ready to get token from the authz server at endpoint: " + tokenUrl)
                console.log(querystring.stringify(tokenRequest))
                try {
                  const tokenResponse = await axios.request({
                    'url': tokenUrl,
                    'method': 'post',
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                    'data': querystring.stringify(tokenRequest)
                  })
                  console.log(tokenResponse)
                  return tokenResponse
                }
                catch(e) {
                  console.log(e)
                  throw e
                }
            }
        }
    }

    static async getUdapMetaDataResposne(url)
    {
        const udapMetaResponse = await axios.request({
            'url': url,
            'method': 'get',
            'headers': {'Content-Type': 'application/fhir+json'},
        })
        return udapMetaResponse
    }

    static createUdapSignedSoftwareStatement(registerUrl, certFileName, certPassword, registrationClaims) {
        //Creates a signed software statement for UDAP Trusted Dynamic Client Registration
        //These to lines should be updated with client's/communities certificate
        var x509File = fs.readFileSync(certFileName, 'binary')
        var certAndPrivateKey = this.parseX509CertFile(x509File, certPassword, 'binary')
        var privateKeyPem = pki.privateKeyToPem(certAndPrivateKey.privateKey)
        var cert = certAndPrivateKey.certChain[0]
        var subjectAltName = cert.getExtension('subjectAltName')
        var uriIndex = subjectAltName.value.indexOf("http");
        var subjectAltNameUri = subjectAltName.value.substring(uriIndex);
        var claims = {
            iss: subjectAltNameUri, sub: subjectAltNameUri,
            aud: registerUrl, jti: UdapClient.randomString(24),
            client_name: registrationClaims.client_name,
            token_endpoint_auth_method: 'private_key_jwt',
            grant_types: registrationClaims.grant_types,
            response_types: registrationClaims.response_types,
            redirect_uris: registrationClaims.redirect_uris,
            contacts: registrationClaims.contacts,
            logouri: registrationClaims.logouri,
            scope: registrationClaims.scopes

        }
        var token =  njwt.create(claims,privateKeyPem,'RS256')
        //Asssuming only 1 entry
        var cert = certAndPrivateKey.certChain[0];
        var derCert = pki.pemToDer(pki.certificateToPem(cert))
        //var buff = forge.util.createBuffer(derCert)
        //var buff = Buffer.from(derCert,'binary')
        var string64 = forge.util.encode64(derCert.getBytes())
        token.setHeader('x5c',[string64])
        token.setHeader('alg','RS256')
        var now = new Date().getTime()
        var exp = now+(5*60 * 1000)
        token.setExpiration(exp)
        token = token.compact()
        return token
    }

    static randomString(length) {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for(var i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }

    createUdapSignedAuthenticationToken(tokenUrl) {
        //Creates a signed software statement for UDAP Trusted Dynamic Client Registration
        //These to lines should be updated with client's/communities certificate
        var x509File = fs.readFileSync(this.certFileName, 'binary')
        var certAndPrivateKey = UdapClient.parseX509CertFile(x509File, this.certFilePassword,'binary')
        var privateKeyPem = pki.privateKeyToPem(certAndPrivateKey.privateKey)
        var cert = certAndPrivateKey.certChain[0]
        var subjectAltName = cert.getExtension('subjectAltName')
        var uriIndex = subjectAltName.value.indexOf("http");
        var subjectAltNameUri = subjectAltName.value.substring(uriIndex);
        const claims = {
            iss: this.clientId, sub: this.clientId,
            aud: tokenUrl, jti: UdapClient.randomString(24),
            'extensions': {
              'hl7-b2b': {
                  version:'1',
                  organization_id: this.organization_id,
                  organization_name: this.organization_name,
                  purpose_of_use: [this.purpose_of_use]
              }
            }
        }
        var token = njwt.create(claims, privateKeyPem, 'RS256')
        //Asssuming only 1 entry
        var derCert = pki.pemToDer(pki.certificateToPem(cert))
        //var buff = forge.util.createBuffer(derCert)
        //var buff = Buffer.from(derCert,'binary')
        var string64 = forge.util.encode64(derCert.getBytes())
        token.setHeader('x5c',[string64])
        token.setHeader('alg','RS256')
        var now = new Date().getTime()
        var exp = now+(5*60 * 1000)
        token.setExpiration(exp)
        token = token.compact()
        return token
    }

    static async postUdapRequest(request, postUrl)
    {
        const oktaResponse = await axios.request({
            'url': postUrl,
            'method': 'post',
            'headers': {'Content-Type': 'application/json'},
            'data': request
        })
        return oktaResponse
    }

    static async postUdapTokenRequest(request, postUrl)
    {
        const oktaResponse = await axios.request({
            'url': postUrl,
            'method': 'post',
            //'headers': {'Content-Type': 'application/x-www-form-urlencoded','Host': this.serverBaseUrl},
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'data': request
        })
        return oktaResponse
    }

    static parseX509CertFile(x509File, password,encoding) {

        //Deal with DER encoding
        //We don't need to validate cert chain on client last arg false
        var map = this.loadPkcs12(x509File, password,encoding,false)
        //Assuming only 1 entry comes back which is true for our self signed dev certs.
        var keys = Object.keys(map);
        var entry = map[keys[0]];
        return entry
    }


    static loadPkcs12(certString, password,encoding,validateCertChain) {
        var certPkcs12
        var p12Asn1
        if (encoding =='base64')
        {
            //Not sure we need this usecase anymore?
            var certPem = Buffer.from(certString, 'base64').toString()
            var cert = pki.certificateFromPem(certPem)
            p12Asn1 = pki.certificateToAsn1(cert)
            certString = forge.asn1.toDer(p12Asn1).getBytes()
        }
        else if (encoding == 'binary')
        {
            p12Asn1 = asn1.fromDer(certString)
        }
        console.log("Cert String:")
        console.log(certString)
        console.log(forge.asn1.prettyPrint(p12Asn1))
        certPkcs12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password)

        var map = {}
        for (var sci = 0; sci < certPkcs12.safeContents.length; ++sci) {
            var safeContents = certPkcs12.safeContents[sci]
            console.log('safeContents ' + (sci + 1))

            for (var sbi = 0; sbi < safeContents.safeBags.length; ++sbi) {
                var safeBag = safeContents.safeBags[sbi]
                console.log('safeBag.type: ' + safeBag.type)

                var localKeyId = null
                if (safeBag.attributes.localKeyId) {
                    localKeyId = forge.util.bytesToHex(safeBag.attributes.localKeyId[0])
                    console.log('localKeyId: ' + localKeyId)
                    if (!(localKeyId in map)) {
                        map[localKeyId] = {
                            privateKey: null,
                            certChain: []
                        }
                    }
                } else {
                    // no local key ID, skip bag
                    continue
                }
                // this bag has a private key
                if (safeBag.type === forge.pki.oids.pkcs8ShroudedKeyBag) {
                    console.log('found private key')
                    map[localKeyId].privateKey = safeBag.key
                } else if (safeBag.type === forge.pki.oids.certBag) {
                    // this bag has a certificate
                    console.log('found certificate')
                    map[localKeyId].certChain.push(safeBag.cert)
                }
            }
        }
        console.log('\nPKCS#12 Info:')

        for (var localKeyId in map) {
            var entry = map[localKeyId]
            console.log('\nLocal Key ID: ' + localKeyId)
            if (entry.privateKey) {
                var privateKeyP12Pem = forge.pki.privateKeyToPem(entry.privateKey)
                var encryptedPrivateKeyP12Pem = forge.pki.encryptRsaPrivateKey(entry.privateKey, password)
                var publicKey = pki.setRsaPublicKey(entry.privateKey.n, entry.privateKey.e)
                var publicKeyPem = pki.publicKeyToPem(publicKey)

                console.log('\nPrivate Key:')
                console.log(privateKeyP12Pem)
                console.log('Encrypted Private Key (password: "' + password + '"):')
                console.log(encryptedPrivateKeyP12Pem)
                console.log("Public Key: ")
                console.log(publicKeyPem)
            } else {
                console.log('')
            }
            var caStore
            if (entry.certChain.length > 0) {
                console.log('Certificate chain:')
                var certChain = entry.certChain
                for (var i = 0; i < certChain.length; ++i) {
                    var certP12Pem = forge.pki.certificateToPem(certChain[i])
                    console.log(certP12Pem)
                    if (!caStore) {
                        caStore = pki.createCaStore([certP12Pem])
                    } else {
                        caStore.addCertificate(certP12Pem)
                    }
                }
                if (validateCertChain)
                {
                    var chainVerified = false
                    try {
                        chainVerified = forge.pki.verifyCertificateChain(caStore, certChain)
                        console.log('Certificate chain verified: ', chainVerified)
                    } catch (ex) {
                        chainVerified = ex
                        console.log('Certificate chain verification error: ', chainVerified)
                    }
                }
            }
        }
        return map;
    }
}

module.exports = UdapClient
