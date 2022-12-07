'use strict';
const axios = require('axios')
const querystring = require('querystring')
const udap = require('./udap_util')
const udapClient = require('./UdapClient')
//Look up IDP by URL from Okta in the IDP list (maybe a cache or something too)

//If found, simply forward the request on to Okta, replacing the URL with the IDP ID.

//If NOT found, retrieve the UDAP metadata from the IDP, and validate.  If valid, then create a new IDP in Okta, and then forward the request on to Okta.
module.exports.authorizeHandler = async (requestQuerystring, requestHeaders) => {
	const idpUri = requestQuerystring.idp
	const scopes = requestQuerystring.scope
	const backendAuthorizeUrl = process.env.OKTA_ORG_VANITY_URL_AUTHORIZE_ENDPOINT

	//First, validate if the IDP is in our trust community
	//First let's see if this is a tiered oauth request.
	//If idp parameter is passed, and udap scope is requested, then it's tiered oauth.
	if(idpUri && scopes && scopes.split(" ").includes("udap")) {
		console.log("Tiered-OAuth request found.")
		const idpValidationResult = await validateIDPUri(idpUri)
		if(idpValidationResult.valid === 'true') {
			console.log("URI is valid and belongs to our trust community.")

			var oktaIDPId = await getOktaIDPId(idpUri)
			var newKeyInfo = null
			//If Okta doesn't know this IDP yet, we need to register.
			if(!oktaIDPId) {
				console.log("No IDP found in Okta- registering.")
				console.log("Getting additional OIDC metadata.")
				const oidcMetadata = await readOIDCConfiguration(idpUri)

				const oktaIDPInfo = await registerOktaIDP(idpUri, idpValidationResult.validatedMetadataBody, oidcMetadata)
				newKeyInfo = oktaIDPInfo.newKeyMapping
				requestQuerystring.idp = oktaIDPInfo.idpId
			}
			else {
				requestQuerystring.idp = oktaIDPId
			}

			//Replace the IDP parameter with the one Okta needs before sending to Okta.
			requestHeaders.Host = process.env.BASE_DOMAIN
			requestQuerystring.prompt = "login"
			const updatedQuerystring = querystring.stringify(requestQuerystring)

			console.log("Final /authorize parameters: " + updatedQuerystring)

			var oktaResult = await axios.request({
				'url': backendAuthorizeUrl + "?" + updatedQuerystring,
				'method': 'GET',
				'headers': requestHeaders,
				'maxRedirects': 0,
				'validateStatus': function (status) {
	  			return true //We want to report on exactly what Okta reports back, good or bad.
				}
			})
			return {
				statusCode: oktaResult.status,
				headers: oktaResult.headers,
				body: oktaResult.data,
				newKeyMapping: newKeyInfo
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
		requestHeaders.Host = process.env.BASE_DOMAIN
		const updatedQuerystring = querystring.stringify(requestQuerystring)
		console.log("URL to send to Okta: " + backendAuthorizeUrl + "?" + updatedQuerystring)
		var oktaResult = await axios.request({
			'url': backendAuthorizeUrl + "?" + updatedQuerystring,
			'method': 'GET',
			'headers': requestHeaders,
			'maxRedirects': 0,
			'validateStatus': function (status) {
  			return true
			}
		})
		return {
			statusCode: oktaResult.status,
			headers: oktaResult.headers,
			body: oktaResult.data,
		}
	}
}

//Takes the URI from the request, and looks up in Okta what the IDP ID would be.
async function validateIDPUri(idpUri) {
	//Steps:
	//1- attempt to get the /.well-known/udap from the idpUri
	//2- validate the metadata coming back.
	//3- return true/false if the metadata is valid.

	const metadataUrl = idpUri + '/.well-known/udap'
	console.log('Getting metadata for idp at: ' + metadataUrl)
	const metadataResponse = await axios.request({
		'url': metadataUrl,
		'method': 'GET',
		'headers': {'Content-Type': 'application/fhir+json'}
	})
	console.log("Metadata response from IDP:")
	console.log(metadataResponse.data)

	if(!metadataResponse.data.signed_metadata) {
		//TODO: Throw an error here so we can surface this better.
		return {
			'valid': 'false',
			'code': 'missing_signed_metadata',
			'message': 'The UDAP metadata file did not contain signed metadata.'
		}
	}
	try {
		const validated = await udap.validateJwtWithCertChain(metadataResponse.data.signed_metadata)
		console.log('UDAP IDP validated. Detail:')
		console.log(validated)
		return {
			'valid': 'true',
			'code': 'Success',
			'message': 'Metadata validated.',
			'validatedMetadataBody': validated.body
		}
	}
	catch(e) {
		return {
			'valid': 'false',
			'code': 'invalid_metadata',
			'message': e.message
		}
	}
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
	if(oktaResponse.data.length > 0){
		return oktaResponse.data[0].id
	}
	else {
		return null
	}
}

async function readOIDCConfiguration(idpBaseUrl) {
	const oidcWellKnownEndpoint = idpBaseUrl + '/.well-known/openid-configuration'
	console.log("Looking for OIDC metadata at: " + oidcWellKnownEndpoint)
	const idpResponse = await axios.request({
		'url': oidcWellKnownEndpoint,
		'method': 'GET',
		'headers': {
			'Accept': 'application/json',
			'Content-Type': 'application/json'
		}
	})

	console.log('OIDC metadata found!')
	console.log(JSON.stringify(idpResponse.data))
	return idpResponse.data
}

async function registerOktaIDP(idpUri, validatedIDPMetadata, oidcMetadata) {
	const oktaAPIToken = await udap.getOktaAPIToken(process.env.OKTA_CLIENT_TOKEN_ENDPOINT, process.env.OKTA_CLIENT_ID, process.env.OKTA_PRIVATE_KEY_FILE)
	const oktaIDPsEndpoint = 'https://' + process.env.OKTA_ORG + '/api/v1/idps'
	const authzCodeRegistrationObject = {
	  client_name: "Tiered OAuth Test Data Holder",
	  contacts: ["dan.cinnamon@okta.com"],
	  grant_types: ['authorization_code'],
	  response_types: ['code'],
	  redirect_uris: ["https://" + process.env.BASE_DOMAIN + "/oauth2/v1/authorize/callback"],
	  scope: "fhirUser udap openid"
	}

	console.log("Performing dynamic client registration!")
	const idpData = await udapClient.udapDynamicClientRegistartion(idpUri, process.env.SERVER_KEY, process.env.SERVER_KEY_PWD, authzCodeRegistrationObject)

	console.log("Registration result:")
	console.log(idpData)

	const clientId = idpData.data.client_id
	const authorizeUrl = validatedIDPMetadata.authorization_endpoint
	const tokenUrl = validatedIDPMetadata.token_endpoint

	const keysUrl = oidcMetadata.jwks_uri
	const userInfo = oidcMetadata.userinfo_endpoint
	const issuer = oidcMetadata.issuer

	console.log("Using the following OIDC metadata:")
	console.log(JSON.stringify(oidcMetadata))

	const idpObject = {
		"type": "OIDC",
		"name": idpUri,
		"protocol": {
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
	        "url": "https://localhost" //tokenUrl
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
		  	"openid", "udap", "email", "profile"
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

	console.log("Invoking the Okta idps endpoint to create the IDP endpoint.")
	var createResponse = await axios.request({
		'url': oktaIDPsEndpoint,
		'method': 'POST',
		'headers': {
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + oktaAPIToken
		},
		'data': idpObject
	})
	console.log('Response from Okta:')
	console.log(JSON.stringify(createResponse.data))
	const idpId = createResponse.data.id
	const publicKeyId = createResponse.data.protocol.credentials.signing.kid

	//Getting the public key generated by Okta...
	console.log("Invoking the Okta idp credential endpoint to get the public key generated by Okta.")
	const oktaIdpKeysEndpoint = 'https://' + process.env.OKTA_ORG + '/api/v1/idps/' + idpId + '/credentials/keys/' + publicKeyId
	const keysResponse = await axios.request({
		'url': oktaIdpKeysEndpoint,
		'method': 'GET',
		'headers': {
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + oktaAPIToken
		}
	})
	console.log('Response from Okta:')
	console.log(JSON.stringify(keysResponse.data))
	const publicKey = keysResponse.data

	console.log("Updating the token endpoint on the IDP to the proper outbound proxy URL.")
	createResponse.data.protocol.endpoints.token.url = "https://" + process.env.BASE_DOMAIN + "/" + idpId + "/tiered_client/token"
	const updateResponse = await axios.request({
		'url': oktaIDPsEndpoint + "/" + idpId,
		'method': 'PUT',
		'headers': {
			'Accept': 'application/json',
			'Content-Type': 'application/json',
			'Authorization': 'Bearer ' + oktaAPIToken
		},
		'data': createResponse.data
	})
	console.log('Response from Okta:')
	console.log(JSON.stringify(updateResponse.data))

	return {
		idpId: idpId,
		newKeyMapping: {
			idp_id: idpId,
			idp_base_url: idpUri,
			public_key: publicKey
		}
	}
}
