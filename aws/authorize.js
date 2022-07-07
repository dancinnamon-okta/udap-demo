'use strict';
const authorizeLib = require('../lib/authorize')

//Authorize endpoint - AWS implementation.
//See the authorize library for full details.
module.exports.authorizeHandler = async (event, context) => {
	var authorizeResult = await authorizeLib.authorizeHandler(event.queryStringParameters)
	return {
		statusCode: authorizeResult.statusCode,
		body: JSON.stringify(authorizeResult.body)
	}
}
