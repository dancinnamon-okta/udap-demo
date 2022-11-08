'use strict';
const authorizeLib = require('../lib/authorize')
const AWS = require('aws-sdk');
AWS.config.update({
	region: process.env.AWS_REGION
})
const dynamoDB = new AWS.DynamoDB.DocumentClient()

//Authorize endpoint - AWS implementation.
//See the authorize library for full details.
module.exports.authorizeHandler = async (event, context) => {
	const authorizeResult = await authorizeLib.authorizeHandler(event.queryStringParameters, event.headers)

	const outputHeaders = createHeaders(authorizeResult.headers)

	//If we registered a new IDP, we need to store a mapping between the
	//Okta public key and the intended /token endpoint, and the community private key.
	//We're doing this here to abstract out the data storage from the business logic.
	console.log("Authorize Result:")
	console.log(authorizeResult)
	if(authorizeResult.newKeyMapping) {
		await storeKeyMapping(authorizeResult.newKeyMapping)
	}

	return {
		statusCode: authorizeResult.statusCode,
		headers: outputHeaders.headers,
		multiValueHeaders: outputHeaders.multiValueHeaders,
		body: authorizeResult.body
	}
}

//Stores the Okta key<->Community key in a dynamoDB for future retrieval
//During tiered oauth.
async function storeKeyMapping(mapping) {
	console.log('New IDP Registered- storing Okta Public key in the database.')
	console.log('Item to put in the DB:')
	console.log(mapping)
	const result = await dynamoDB.put({
		TableName: process.env.KEY_MAPPING_TABLE_NAME,
		Item: {
			idp_id: mapping.idp_id,
			idp_base_url: mapping.idp_base_url,
			public_key: mapping.public_key
		}
	}).promise()
	console.log(result)
}

function createHeaders(headers) {
  const singleValueHeaders = {}
  const multiValueHeaders = {}
  Object.entries(headers).forEach(([key, value]) => {
    const targetHeaders = Array.isArray(value) ? multiValueHeaders : singleValueHeaders
    Object.assign(targetHeaders, { [key]: value })
  })

  return {
    headers: singleValueHeaders,
    multiValueHeaders: multiValueHeaders,
  }
}
