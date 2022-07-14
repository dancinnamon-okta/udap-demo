'use strict';
const axios = require('axios')
const querystring = require('querystring')
const { v4: uuidv4 } = require('uuid')

module.exports.matchHandler = async (requestBody) => {
  const matchedPatients = new Map()
  const matchParameters = getMatchParameters(JSON.parse(requestBody))
  console.log("Match Parameters: " + JSON.stringify(matchParameters))

  try {
    validateMatchParameters(matchParameters.resource)
  }
  catch(e) {
    return {
      "statusCode": 400,
      "body": {"Error": e.message}
    }
  }

  //Get date of birth
  if(matchParameters.resource.birthDate) {
    const entries = await executeFhirSearch(querystring.stringify({"birthdate":matchParameters.resource.birthDate}))
    for(var i=0; i<entries.length; i++) {
      const resultEntry = {
        "resource": entries[i].resource,
        "score": 2
      }
      console.log("Matched patient " + entries[i].resource.id + " on birthdate.")
      matchedPatients.set(entries[i].resource.id, resultEntry)
    }
  }

  //ADDRESS, EMAIL, PHONE ALL COUNT AS ONE THING!
  //THEY DONT PILE ON IN THE CALCULATION.
  //We want to track these a bit seperately, and then merge them in when we're done.
  const matchedContactInfoPatients = new Map()

  //Get telephone and email (both are in the telecom fields.)
  if(matchParameters.resource.telecom) {
    //Loop through and match on any telephone number or email address.
    for(var i=0; i<matchParameters.resource.telecom.length; i++) {
      const entries = await executeFhirSearch(querystring.stringify({"telecom": matchParameters.resource.telecom[i].system + "|" + matchParameters.resource.telecom[i].value}))
      for(var j=0; j<entries.length; j++) {
        console.log("Matched patient " + entries[j].resource.id + " on telecom info.")
        if(!matchedContactInfoPatients.get(entries[j].resource.id)) {
          matchedContactInfoPatients.set(entries[j].resource.id, entries[j].resource)
        }
      }
    }
  }

  //Get street Address
  //Get city
  if(matchParameters.resource.address) {
    for(var i=0; i<matchParameters.resource.address.length; i++) {
      const entries = await executeFhirSearch(querystring.stringify({"address": matchParameters.resource.address[i].line[0], "address-city": matchParameters.resource.address[i].city}))
      for(var j=0; j<entries.length; j++) {
        console.log("Matched patient " + entries[j].resource.id + " on address info.")
        if(!matchedContactInfoPatients.get(entries[j].resource.id)) {
          matchedContactInfoPatients.set(entries[j].resource.id, entries[j].resource)
        }
      }
    }
  }

  //Merge the single 4 point score for telecom and address back into the full results.
  matchedContactInfoPatients.forEach(function(value, key) {
     const existingMatchedPatient = matchedPatients.get(key)
	   if(existingMatchedPatient) {
       existingMatchedPatient.score += 4
       matchedPatients.set(key, existingMatchedPatient)
     }
     else { //We don't have this match yet- add the 4 point result for the first time.
       const resultEntry = {
         "resource": value,
         "score": 4
       }
       matchedPatients.set(key, resultEntry)
     }
  })

  //Get First/Last name
  if(matchParameters.resource.name) {
    for(var i=0; i<matchParameters.resource.name.length; i++) {
      var givenName = ""
      if(matchParameters.resource.name[i].given.constructor === Array) {
        givenName = matchParameters.resource.name[i].given[0]
      }
      else {
        givenName = matchParameters.resource.name[i].given
      }
      const entries = await executeFhirSearch(querystring.stringify({"given": givenName, "family": matchParameters.resource.name[i].family}))
      for(var j=0; j<entries.length; j++) {
        console.log("Matched patient " + entries[j].resource.id + " on name info.")
        const existingMatchedPatient = matchedPatients.get(entries[j].resource.id)
        if(existingMatchedPatient) {
          existingMatchedPatient.score += 4
          matchedPatients.set(key, existingMatchedPatient)
        }
        else {
          const resultEntry = {
            "resource": entries[j].resource,
            "score": 4
          }
          matchedPatients.set(entries[j].resource.id, resultEntry)
        }
      }
    }
  }
  //Convert our hashtable/map into a single array, and add in the rest of the bundle stuff we need.
  var outputEntries = []
  matchedPatients.forEach(function(value, key) {
    //Only include the result if our confidence is high enough, and also stop at our requested limit.
    if((!matchParameters.onlyCertainMatches || value.score >= 8) && (outputEntries.length < matchParameters.count)){
      outputEntries.push({
        "fullUrl": (process.env.FHIR_BASE + "/Patient/" + key),
        "resource": value.resource,
        "search": {
          "extension": [{
            "url": "http://hl7.org/fhir/StructureDefinition/match-grade",
            "valueCode": value.score >= 8 ? "certain" : "possible"
          }],
          "mode": "match",
          "score": value.score / 10
        }
      })
    }
  })

  //Now our matchedPatients map has everything we need. Now we just need to format it in JSON and return it!
  const responseBundle = {
    "resourceType": "Bundle",
    "id": uuidv4(),
    "meta": {
      "lastUpdated": new Date().toISOString()
    },
    "type": "searchset",
    "total": outputEntries.length,
    "entry": outputEntries
  }

  //Output.
  return {
      //400 - Bad Request
      statusCode: 200,
      body: responseBundle
  }
}

async function executeFhirSearch(searchQueryString) {
  const requestUrl = process.env.BACKEND_FHIR_SERVER + "/Patient?" + searchQueryString
  var fhirResult = await axios.request({
    'url': requestUrl,
    'method': 'GET'
  })
  if(fhirResult.data.entry) {
    return fhirResult.data.entry
  }
  else {
    return []
  }
}

function getMatchParameters(requestBody) {
  var result = {
    "resource": "",
    "count": "",
    "onlyCertainMatches":""
  }
  for(var i=0; i<requestBody.parameter.length; i++) {
    if(requestBody.parameter[i].name == "resource") {
      result.resource = requestBody.parameter[i].resource
    }
    else if(requestBody.parameter[i].name == "count") {
      result.count = requestBody.parameter[i].valueInteger
    }
    else if(requestBody.parameter[i].name == "onlyCertainMatches") {
      result.onlyCertainMatches = (requestBody.parameter[i].valueBoolean == "true")
    }
  }
  return result
}

function validateMatchParameters(resource) {
  var overallScore = 0
  var idPPNScore = 0
  var idDLSTIDScore = 0
  var idOtherScore = 0
  var nameScore = 0
  var photoScore = 0
  var telecomScore = 0
  var addressScore = 0

  //First check the identifier
  if(resource.identifier) {
    for(var i=0; i<resource.identifier.length; i++) {
      if(resource.identifier[i].type && ["DL", "STID"].includes(resource.identifier[i].type.coding) && resource.identifier[i].value) {
        idDLSTIDScore += 1
      }
      else if(resource.identifier[i].type && resource.identifier[i].type.coding == "PPN" && resource.identifier[i].value) {
        idPPNScore += 1
      }
      else if(resource.identifier[i].value) {
        idOtherScore += 1
      }
    }
  }

  //Check for Names
  if(resource.name) {
    for(var i=0; i<resource.name.length; i++) {
      //If neither name is given, we need to throw an error.
      if(!resource.name[i].given && !resource.name[i].family) {
        throw new Error("Condition idi-2 failed. A search was attempted with an empty name field.")
      }
      else if(resource.name[i].given && resource.name[i].family) {
        nameScore += 1
      }
    }
  }

  //Check for address, email, phone, photo.
  if(resource.photo) {
    photoScore += 1
  }
  if(resource.telecom) {
    for(var i=0; i<resource.telecom.length; i++) {
      if(resource.telecom[i].system == "email" && resource.telecom[i].value) {
        telecomScore += 1
      }
      else if(resource.telecom[i].system == "phone" && resource.telecom[i].value) {
        telecomScore += 1
      }
    }
  }
  if(resource.address) {
    for(var i=0; i<resource.address.length; i++) {
      if(resource.address[i].use == "home" && resource.address[i].line && resource.address[i].city) {
        addressScore += 1
      }
    }
  }

  //Compute our final results!
  if(idPPNScore > 0) {
    overallScore += 10
  }

  if(idDLSTIDScore > 0) {
    overallScore += 10
  }

  if(addressScore > 0 || telecomScore > 0 || photoScore > 0 || idOtherScore > 0) {
    overallScore += 4
  }

  if(nameScore > 0) {
    overallScore += 4
  }

  //Check for date of birthdate
  if(resource.birthDate) {
    overallScore += 2
  }

  if(overallScore < 10) {
    throw new Error("Unauthorized Match - Input criteria doesn't meet minimum requirements")
  }
  console.log("The final input validation score is: " + overallScore)
  console.log("ID PPN Score: " + idPPNScore)
  console.log("ID DL/STID Score: " + idDLSTIDScore)
  console.log("ID Other Score: " + idOtherScore)
  console.log("Name Score: " + nameScore)
  console.log("Photo Score: " + photoScore)
  console.log("Telecom Score: " + telecomScore)
  console.log("Address Score: " + addressScore)
}
//PER IG- the logic for input validation is:
/*Combined weighted values of included elements must have a minimum value of 10 (see Patient Weighted Elements table):
(
  (
    (
      identifier.type.coding.exists(code = 'PPN') and
      identifier.value.exists()
    ).toInteger()*10
  ) +
  (
    (
      identifier.type.coding.exists(code = 'DL' or code = 'STID') and
      identifier.value.exists()
    ).toInteger()*10
  ) +

  (
    (
      (
        address.exists(use = 'home') and
        address.line.exists() and
        address.city.exists()
      ) or
      (
        identifier.type.coding.exists(code != 'PPN' and code != 'DL' and code != 'STID') //WE DONT CARE ABOUT THE VALUE??
      ) or
      (
        (
          telecom.exists(system = 'email') and
          telecom.value.exists()
        ) or
        (
          telecom.exists(system = 'phone') and
          telecom.value.exists()
        )
      ) or
      (
        photo.exists()
      )
    ).toInteger() * 4
  ) +

  (
    (
      name.family.exists() and
      name.given.exists()
    ).toInteger()*4
  ) +

  (
    birthDate.exists().toInteger()*2
  )

) >= 10
*/
