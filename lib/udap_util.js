'use script'
const axios = require('axios')
const fs = require('fs')
const forge = require('node-forge')
const pki = require('node-forge').pki
const asn1 = require('node-forge').asn1

//For CRL only
const asn1js = require('asn1js')
const pkijs = require('pkijs')
const pvutils = require('pvutils')

const njwt = require('njwt');
const pem2jwk = require('pem-jwk').pem2jwk
const jwk2pem = require('pem-jwk').jwk2pem

module.exports.validateJwtWithCertChain = async (udapJwt) => {

  var ssVerifiedJwt = null
  var cert = null
  try
  {
    //Need to parse first to get cert from header for public key
    var ssJwtParts = udapJwt.split(".")
    var ssJwtHead = Buffer.from(ssJwtParts[0], 'base64').toString('utf-8')
    console.log('Token Header')
    console.log(ssJwtHead)
    var objJwtHead = JSON.parse(ssJwtHead)

    //get x5c value
    var x5c64 = objJwtHead.x5c
    if(!x5c64) {
      throw new Error("x5c header is missing.")
    }
    //decode base64
    //TODO:  Do we need to deal with more then one array element?
    var x5c = forge.util.decode64(x5c64[0])
    //Deal with DER encoding
    var certAsn1 = asn1.fromDer(x5c)
    cert = pki.certificateFromAsn1(certAsn1)

    //Get public key to verify JWT
    var certPublicKey = cert.publicKey
    var certPublicKeyPEM = pki.publicKeyToPem(certPublicKey)

    //This validates the JWT and signature
    //if JWT isn't valid bail
    ssVerifiedJwt = njwt.verify(udapJwt, certPublicKeyPEM, objJwtHead.alg)

    //We also need to ensure the iss value equals the subjectalternativename in the cert.
    console.log("Certificate loaded:")
    console.log(cert.getExtension('subjectAltName').altNames[0].value)

    console.log("ISS of JWT:")
    console.log(ssVerifiedJwt.body.iss)

    //Revisit this- We'll eventually want to do this for registration only.
    /*if(ssVerifiedJwt.body.iss != cert.getExtension('subjectAltName').altNames[0].value) {
      throw new Error('The iss value must match the subject alternative name in the certificate.')
    }*/

    console.log("Verified UDAP jwt Ant: " + ssVerifiedJwt)
	}
	catch (e) {
    console.error("njwt Verify Exception:")
		console.error(e)
		var error = new Error(e.message)
    error.code = 'invalid_software_statement'

    //Uncomment this when pushing to AWS
    throw error
	}
  // Validate cert is not on CRL
  try {
    await validateCrl(cert)
  }
  catch (e)
  {
    console.error("cert Expiration/Revocation Exception:")
    console.error(e)
    var error = new Error('certificate expired or revoked')
    error.code = 'unapproved_software_statement'
    console.error('unapproved_software_statement')
    console.log(error)
    throw error
  }

  //Validate cert is part of our trust community.
  try {
    await validateCertChain(cert)
  }
  catch(e) {
    console.error("validateCertChain Exception:")
    console.error(e)
    var error = new Error('Unable to validate certificate')
    error.code = 'unapproved_software_statement'
    throw error
  }


  console.log("UDAP verified JWT Body: " + JSON.stringify(ssVerifiedJwt.body))
	return ssVerifiedJwt
}

module.exports.getPublicKeyJWKS = (softwareStatementJWTObject) => {


  var x5c = forge.util.decode64(softwareStatementJWTObject.header.x5c[0])
  var certAsn1 = asn1.fromDer(x5c)
  certPublicKey = pki.certificateFromAsn1(certAsn1).publicKey
  var certPublicKeyPEM = pki.publicKeyToPem(certPublicKey)
  var jwkPublic = pem2jwk(certPublicKeyPEM)

  return { keys: [jwkPublic] }

}

module.exports.getOktaAPIToken = async (tokenEndpoint, clientId, privateKeyFile) => {
	const now = Math.floor( new Date().getTime() / 1000 );
	const plus5Minutes = new Date( ( now + (5*60) ) * 1000);
	var signingKeyJwk = JSON.parse(fs.readFileSync(privateKeyFile, 'utf8'))
  console.log(signingKeyJwk)
  var signingKeyPem = jwk2pem(signingKeyJwk)


	const claims = {
		aud: tokenEndpoint, // audience, which is the authz server.
	};

	const jwt = njwt.create(claims, signingKeyPem, "RS256")
		.setIssuedAt(now)
		.setExpiration(plus5Minutes)
		.setIssuer(clientId)
		.setSubject(clientId)
		.compact();

	console.log ('Generated JWT used for Okta API Access')
	console.log(jwt)

  const formData = 'client_assertion=' + jwt +
			             '&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' +
			             '&grant_type=client_credentials&scope=okta.apps.manage%20okta.apps.read'

  const oktaResponse = await axios.request({
    'url': tokenEndpoint,
    'method': 'post',
    'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
    'data': formData
  })
  return oktaResponse.data.access_token

}

async function validateCrl(cert) {
    const distributionPoints = []

    const getDistributionPoints = (node) => {
      if (typeof node === 'string') {
        distributionPoints.push(node)
        return
      }
      if (Array.isArray(node)) {
        node.forEach(getDistributionPoints);
        return
      }
      if (node && typeof node === 'object') {
        getDistributionPoints(node.value)
      }
    }

    const ext = cert.getExtension('cRLDistributionPoints')
    getDistributionPoints(asn1.fromDer(ext.value))
    console.log("Distribution Points: ")
    console.log(distributionPoints)
    if (distributionPoints.length > 0)
    {
        var crlUrl = distributionPoints[0]
        console.log("CRL URL: " + crlUrl)
        try {
           const httpResponse = await axios.request({
               'url': crlUrl,
               'responseType':'arraybuffer',
               'method': 'get',
               'headers': {'Accept':'application/x-x509-ca-cert'}
           })
           console.log("CRL Response: ", httpResponse.data.toString())

           const buffer = new Uint8Array(httpResponse.data).buffer
           const asn1crl = asn1js.fromBER(buffer);
           const crl = new pkijs.CertificateRevocationList({
             schema: asn1crl.result
           })

          for (let index in crl.revokedCertificates) {
              var revokedCertificate = crl.revokedCertificates[index]
              var revCertSerial = pvutils.bufferToHexCodes(revokedCertificate.userCertificate.valueBlock.valueHex)
              console.log("Cert Serial number: " + revCertSerial)
              if (cert.serialNumber.toLowerCase() == revCertSerial.toLowerCase())
              {
                  console.log("Cert on CRL:")
                  throw new Error("certificate revoked")
              }
          }
        }
        catch(e)
        {
            console.error('Error validatating CRL:')
            console.error(e)
            throw e;
        }
    }
    else {
      throw new Error("No CRL Found.")
    }
}

//This works for validating cert, but does throw an error for self signed certs.
async function validateCertChain(cert) {
    console.log("Cert: ")
    console.log(cert)

    try {
        var caTrustAnchor = fs.readFileSync(process.env.COMMUNITY_CERT)
        var caTrustAnchor = pki.certificateFromPem(caTrustAnchor)
        var chainVerified = false
        var certStore
        var certChain = []
        certStore = pki.createCaStore()
        certChain = await getCertChain(cert)
        var childCert = null
        var parentCert = null

         certChain.forEach(cert =>
            {
                certStore.addCertificate(cert)
            })
         certStore.addCertificate(caTrustAnchor) //DO WE NEED TO DO THIS? SEEMS LIKE THIS SHOULD BE THERE ALREADY?
         chainVerified = pki.verifyCertificateChain(certStore,certChain)
         console.log('Certificate chain verified: ', chainVerified)
    }
    catch(ex)
    {
        console.error("pki verifyCertificateCHain Exception:")
        console.error(ex)
        console.error('Certificate chain verification error: ', chainVerified)
        throw ex
    }
}

async function getCertChain(cert)
{
    const certChain = []
    var currentCert = cert
    var parent = null
    do
    {
        certChain.push(currentCert)
        parent = currentCert.getExtension('authorityInfoAccess')
        if (parent != null)
        {
            //TODO:  Try to parse this like CRL sample .fromDer
            var parentUrl = parent.value.toString().split('\u0002')
            var parsePos = parentUrl[1].indexOf('http')
            var aiaUrl = parentUrl[1].substring(parsePos)
            console.log("AIA Cert URI: " + aiaUrl)

            const httpResponse = await axios.request({
                'url': aiaUrl,
                'responseType':'arraybuffer',
                'method': 'get',
                'headers': {'Accept':'application/x-x509-ca-cert'}
            })
            console.log("1. HttpResponse  Data:")
            console.log(httpResponse.data)
            if (httpResponse.data != null)
            {
                var cerDer = forge.util.createBuffer(httpResponse.data,'raw')
                var asn1Cert = asn1.fromDer(cerDer)
                console.log("AIA Cert: " + asn1.prettyPrint(asn1Cert))
                currentCert = pki.certificateFromAsn1(asn1Cert)
            }
            else{
                throw new Error('Could not retrieve cert: ' + httpResponse.statusCode)
            }

        }
        else
        {
            currentCert = parent
        }
    }
    while (currentCert != null)
    console.log("2. Finished with chain")
    return certChain
}
