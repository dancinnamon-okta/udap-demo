'use strict';
const metadataLib = require('../lib/metadata_endpoints')

//Metadata endpoints - AWS Lambda Interface
module.exports.udapMetadataHandler = async (event, context) => {
	var udapMetadataResult = await metadataLib.udapMetadataHandler()
	return {
		statusCode: 200,
		body: JSON.stringify(udapMetadataResult)
	}
}
