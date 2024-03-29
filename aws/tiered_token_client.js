'use strict';
const tokenClientLib = require('../lib/tiered_token_client')
const AWS = require('aws-sdk');
AWS.config.update({
	region: process.env.AWS_REGION
})
const dynamoDB = new AWS.DynamoDB.DocumentClient()

//Authorize endpoint - AWS implementation.
//See the authorize library for full details.
module.exports.tieredTokenClientHandler = async (event, context) => {
	console.log("Tiered OAuth token request inbound for idpID: " + event.pathParameters.idpId)
	const internalIdpData = await getIdpData(event.pathParameters.idpId)
	console.log("Inbound request")
	console.log(event.body)
	const handlerResponse = await tokenClientLib.tieredTokenClientHandler(event.body, internalIdpData)

	return {
		statusCode: handlerResponse.statusCode,
		headers: {"Cache-Control": "no-store", "Pragma": "no-cache"},
		body: JSON.stringify(handlerResponse.body)
	}
}

//Retrieves the IDP data from our cache.
//During tiered oauth.
async function getIdpData(idpId) {
	console.log('Getting IDP data from the database...')
	const result = await dynamoDB.get({
		TableName: process.env.KEY_MAPPING_TABLE_NAME,
		Key: {
			idp_id: idpId,
		}
	}).promise()
	console.log("IDP Data:")
	console.log(result.Item)
	if(result.Item) {
		return result.Item
	}
	else {
		return null
	}
}
