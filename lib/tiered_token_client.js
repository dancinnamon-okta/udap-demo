'use strict';
const axios = require('axios')
const querystring = require('querystring')
const udap = require('./udap_util.js')

const njwt = require('njwt');
const jwk2pem = require('pem-jwk').jwk2pem

const UdapClient = require('./UdapClient')

//Step 6- Token Proxy will take out the patient_id value in the token, and return it alongside the token instead.
//This is also where we handle public applications that need tokens.
module.exports.tieredTokenClientHandler = async (tokenRequestBody, internalIdpData) => {
	console.log('UDAP Tiered OAuth token client called.')

	console.log('Validating the inbound Okta token...')
	const inboundRequestData= querystring.parse(tokenRequestBody)
	const inboundToken = inboundRequestData.client_assertion
	const verifiedJWT = njwt.verify(inboundToken, jwk2pem(internalIdpData.public_key), "RS256")
	console.log("Inbound Okta token verified! Making UDAP token request to the real endpoint...")
	const udapClient = new UdapClient(process.env.SERVER_KEY, process.env.SERVER_KEY_PWD, inboundRequestData.scope, internalIdpData.idp_base_url, verifiedJWT.body.sub, inboundRequestData.redirect_uri, "testing123", "testing123", "testing123", null)

	const tokenResponse = await udapClient.udapTokenRequestAuthCode(inboundRequestData.code)
	console.log('Response from IDP:')
	console.log(tokenResponse.data)
		return {
			statusCode: tokenResponse.status,
			body: tokenResponse.data
		}
}
