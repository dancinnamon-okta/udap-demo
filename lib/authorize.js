'use strict';
const axios = require('axios')
const querystring = require('querystring')
const udap = require('./udap_util')

//CSR ID FOR CONNECTATHON! oiah2ZoSgnuZUCKuKwzBAdmCms9kL8xnnQ-gMGoQ60M

//Look up IDP by URL from Okta in the IDP list (maybe a cache or something too)

//If found, simply forward the request on to Okta, replacing the URL with the IDP ID.

//If NOT found, retrieve the UDAP metadata from the IDP, and validate.  If valid, then create a new IDP in Okta, and then forward the request on to Okta.

module.exports.authorizeHandler = async (requestQuerystring, requestHeaders) => {
	const idpUri = querystring.parse(requestQuerystring.idp)
	const backendAuthorizeUrl = process.env.OKTA_ORG_VANITY_URL_AUTHORIZE_ENDPOINT

	//First, validate if the IDP is in our trust community
	if(idpUri){
		console.log("Tiered-OAuth request found.")
		if(validateIDPUri(idpUri)) {
			console.log("URI is valid and belongs to our trust community.")
			var oktaIDPId = await getOktaIDPId(idpUri)

			//If Okta doesn't know this IDP yet, we need to register.
			if(!oktaIDPId) {
				console.log("No IDP found in Okta- registering."")
				oktaIDPId = registerOktaIDP(idpUri)
			}

			//Replace the IDP parameter with the one Okta needs before sending to Okta.
			requestQuerystring.idp = oktaIDPId
			requestHeaders.Host = process.env.AUTHZ_ISSUER_HOSTNAME
			const updatedQuerystring = querystring.stringify(requestQuerystring)

			console.log("Final /authorize parameters: " + updatedQuerystring)

			var oktaResult = await axios.request({
				'url': backendAuthorizeUrl + "?" + updatedQuerystring,
				'method': 'GET',
				'headers': requestHeaders
			})
			return {
				statusCode: oktaResult.status,
				headers: oktaResult.headers,
				body: oktaResult.data,
			}
		}
		else {
			return {
				statusCode: 400,
				body: {
					'error': 'unapproved_software_statement',
					'error_description': 'The IDP you passed in does not belong to the community.'
				}
			}
		}
	}
	else {
		console.log("Non-Tiered-OAuth request found.")
		
		//Normal OAuth2 flow stuff. No tiered oauth. At this point we're just proxying through.
		requestHeaders.Host = process.env.AUTHZ_ISSUER_HOSTNAME
		const updatedQuerystring = querystring.stringify(requestQuerystring)
		var oktaResult = await axios.request({
			'url': backendAuthorizeUrl + "?" + updatedQuerystring,
			'method': 'GET',
			'headers': requestHeaders
		})
		return {
			statusCode: oktaResult.status,
			headers: oktaResult.headers,
			body: oktaResult.data,
		}
	}
}

//Takes the URI from the request, and looks up in Okta what the IDP ID would be.
function validateIDPUri(idpUri) {
	//This should be part of the UDAP Client.
	return true
}

async function getOktaIDPId(idpUri) {
	const oktaAPIToken = await udap.getOktaAPIToken(process.env.OKTA_CLIENT_TOKEN_ENDPOINT, process.env.OKTA_CLIENT_ID, process.env.OKTA_PRIVATE_KEY_FILE)
	const oktaIDPsEndpoint = 'https://' + process.env.OKTA_ORG + '/api/v1/idps?q=' + querystring.escape(idpUri)
	const oktaResponse = await axios.request({
		'url': oktaIDPsEndpoint,
		'method': 'GET',
		'headers': {
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + oktaAPIToken
		}
	})
	console.log('Response from Okta:')
	console.log(JSON.stringify(oktaResponse.data))

	return oktaResponse.data[0].id
}

function registerOktaIDP(idpUri) {
	const oktaAPIToken = await udap.getOktaAPIToken(process.env.OKTA_CLIENT_TOKEN_ENDPOINT, process.env.OKTA_CLIENT_ID, process.env.OKTA_PRIVATE_KEY_FILE)
	const oktaIDPsEndpoint = 'https://' + process.env.OKTA_ORG + '/api/v1/idps'
	//const clientId = udapClient.registerIDP()

	//Im going to get this stuff from the UDAP client.
	const clientId = 'testing123'
	const authorizeUrl = 'authurl'
	const tokenUrl = 'tokenurl'
	const keysUrl = 'jwksurl'
	const userInfo = 'userinfourl'
	const issuer = 'issueruri'

	const idpObject = {
		"type": "OIDC",
		"name": idpUri,
		"protocol": {
    	"algorithms": {
      	"request": {
	        "signature": {
	            "algorithm": "RS256",
	            "scope": "REQUEST"
	        }
        }
    	},
	    "endpoints": {
	      "acs": {
	        "binding": "HTTP-POST",
	        "type": "INSTANCE"
	      },
	      "authorization": {
	        "binding": "HTTP-REDIRECT",
	        "url": authorizeUrl
	      },
	      "token": {
	        "binding": "HTTP-POST",
	        "url": tokenUrl
	      },
	      "userInfo": {
	        "binding": "HTTP-REDIRECT",
	        "url": userInfo
	      },
	      "jwks": {
	        "binding": "HTTP-REDIRECT",
	        "url": keysUrl
	      }
	    },
		  "scopes": [
		  	"openid"
		  ],
    	"type": "OIDC",
	    "credentials": {
	      "client": {
		      "token_endpoint_auth_method": "private_key_jwt",
		      "client_id": clientId
	      },
        "signing": {
        	"algorithm": "RS256"
        }
	    },
		  "issuer": {
	    	"url": issuer
		  }
		},
		"policy": {
	    "accountLink": {
	        "action": "AUTO",
	        "filter": null
	    },
	    "provisioning": {
	      "action": "AUTO",
	      "conditions": {
	        "deprovisioned": {
	        	"action": "NONE"
	        },
	        "suspended": {
	        	"action": "NONE"
	        }
	      },
	      "groups": {
	      	"action": "NONE"
	      }
	    },
		  "maxClockSkew": 120000,
	    "subject": {
	      "userNameTemplate": {
	      	"template": "idpuser.email"
	      },
	      "matchType": "USERNAME"
	    }
		}
	}

	const createResponse = await axios.request({
		'url': oktaIDPsEndpoint,
		'method': 'POST',
		'headers': {
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + oktaAPIToken,
			'data': idpObject
		}
	})
	console.log('Response from Okta:')
	console.log(JSON.stringify(createResponse.data))
	const idpId = createResponse.data.id

	const cloneUrl = oktaIDPsEndpoint + '/' + process.env.TEMPLATE_OKTA_IDP_ID + '/credentials/keys/' + process.env.TEMPLATE_OKTA_IDP_KID + '/clone?targetIdpId=' + idpId

	//Call Okta to update the IDP.
	const cloneResponse = await axios.request({
		'url': cloneUrl,
		'method': 'POST',
		'headers': {
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + oktaAPIToken
		}
	})
	console.log('Response from Okta:')
	console.log(JSON.stringify(cloneResponse.data))

	//return IDPID
	return idpId
}
