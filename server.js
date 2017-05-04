//
// Copyright (c) 2016 Cisco Systems
// Licensed under the MIT License 
//

/*
 * a Cisco Spark Integration based on nodejs, that acts on user's behalf.
 * implements the Cisco Spark OAuth flow, to retreive Cisco Spark API access tokens.
 * 
 * See documentation: https://developer.ciscospark.com/authentication.html
 * 
 */

var debug = require("debug")("oauth");
var fine = require("debug")("oauth:fine");

var request = require("request");
var express = require('express');
var app = express();


//
// Step 0: create a Spark integration from https://developer.ciscospark.com/add-integration.html
//   - then fill in your Integration properties below
//
var clientId = process.env.CLIENT_ID || "C9901101c66249d7e6b7cb174941a400e2e01f7d80d0b1f08b11665bad5cbb66d";
var clientSecret = process.env.CLIENT_SECRET || "aaa8f0304a9b49a1654b74a14faf7b939481341ab09c9e47bab9d7c1e54e62a7";
var redirectURI = process.env.REDIRECT_URI || "http://localhost:8080/oauth"; // where your integration is waiting for Cisco Spark to redirect and send the authorization code
var state = process.env.STATE || "Test"; // state can be used for security and/or correlation purposes
var scopes = "spark:people_read spark:messages_read spark:messages_write"; // extend permission with Spark OAuth scopes required by your example, supported scopes are: https://developer.ciscospark.com/add-integration.html
//var scopes = "spark:room_read"; // extend permission with Spark OAuth scopes required by your example, supported scopes are: https://developer.ciscospark.com/add-integration.html


//
// Step 1: initiate the OAuth flow
//   - serves a Web page with a link to the Cisco Spark OAuth flow initializer
//
// Initiate the OAuth flow from the 'index.ejs' template  
// ------------------------------------------------------------- 
// -- Comment this section to initiate the flow from  static html page
var initiateURL = "https://api.ciscospark.com/v1/authorize?" 
    + "client_id=" + clientId 
    + "&response_type=code"
    + "&redirect_uri=" + encodeURIComponent(redirectURI) 
    + "&scope=" + encodeURIComponent(scopes)
    + "&state=" + state;
var read = require("fs").readFileSync;
var join = require("path").join;
var str = read(join(__dirname, '/www/initiate.ejs'), 'utf8');
var ejs = require("ejs");
var compiled = ejs.compile(str)({ "link": initiateURL }); // inject the link into the template
app.get("/index.html", function (req, res) {
    debug("serving the integration home page (generated from an EJS template)");
    res.send(compiled);
});
app.get("/", function (req, res) {
     res.redirect("/index.html");
});
// -------------------------------------------------------------
// Statically serve the "/www" directory
// WARNING: Do not move the 2 lines of code below, as we need this exact precedance order for the static and dynamic HTML generation to work correctly all together
//          If the section above is commented, the static index.html page will be served instead of the EJS template.
var path = require('path');
app.use("/", express.static(path.join(__dirname, 'www')));
var myName = "none";

//
// Step 2: process OAuth Authorization codes
//
/*app.get("/receive", function (req, res) {
    // Did the user decline
    if (req.query.error) {
        debug("unknown error: " + req.query.error);
        res.send("<p>req.query.error</p>");
        return;
    }
    String json = JSON.parse(req.body);

}*/

app.get("/oauth", function (req, res) {
        debug("oauth callback hitted");

        // Did the user decline
        if (req.query.error) {
            if (req.query.error == "access_denied") {
                debug("user declined");
                res.send("<h1>OAuth Integration could not complete</h1><p>Got your NO, ciao.</p>");
                return;
            }

            if (req.query.error == "server_error") {
                debug("server error");
                res.send("<h1>OAuth Integration could not complete</h1><p>Cisco Spark send a Server Error, Auf Wiedersehen.</p>");
                return;
            }

            debug("unknown error: " + req.query.error);
            res.send("<h1>OAuth Integration could not complete</h1><p>Error case not implemented, au revoir.</p>");
            return;
        }

        // Check request parameters correspond to the spec
        if ((!req.query.code) || (!req.query.state)) {
            debug("expected code & state query parameters are not present");
            res.send("<h1>OAuth Integration could not complete</h1><p>Unexpected query parameters, ignoring...</p>");
            return;
        }

        // Check State
        // [NOTE] we implement a Security check below, but the State variable can also be leveraged for Correlation purposes
        if (state != req.query.state) {
            debug("State does not match");
            res.send("<h1>OAuth Integration could not complete</h1><p>Wrong secret, aborting...</p>");
            return;
        }

        // Retreive access token (expires in 14 days) & refresh token (expires in 90 days)
        //   {
        //      "access_token":"N2MxMmE0YzgtMjY0MS00MDIxLWFmZDItNTg0MGVkOWEyNWQ3YmMzMmFlODItYzAy",
        //      "expires_in":1209599,
        //      "refresh_token":"NjBjNDk3MjktMjUwMy00YTlkLWJkOTctM2E2MjE3YWU1NmI4Njk3Y2IzODctMjBh",
        //      "refresh_token_expires_in":7775999
        //   }
        var options = {
            method: "POST",
            url: "https://api.ciscospark.com/v1/access_token",
            headers: {
                "content-type": "application/x-www-form-urlencoded"
            },
            form: {
                grant_type: "authorization_code",
                client_id: clientId,
                client_secret: clientSecret,
                code: req.query.code,
                redirect_uri: redirectURI
            }
        };
        request(options, function (error, response, body) {
            if (error) {
                debug("could not reach Cisco Spark to retreive access & refresh tokens");
                res.send("<h1>OAuth Integration could not complete</h1><p>Sorry, could not retreive your access token. Try again...</p>");
                return;
            }

            if (response.statusCode != 200) {
                debug("access token not issued with status code: " + response.statusCode);
                switch (response.statusCode) {
                    case 401:
                        res.send("<h1>OAuth Integration could not complete</h1><p>OAuth authentication error. Ask the service contact to check the secret.</p>");
                        break;
                    default:
                        res.send("<h1>OAuth Integration could not complete</h1><p>Sorry, could not retreive your access token. Try again...</p>");
                        break;
                }
                return;
            }

            // Check payload
            var json = JSON.parse(body);
            if ((!json) || (!json.access_token) || (!json.expires_in) || (!json.refresh_token) || (!json.refresh_token_expires_in)) {
                debug("could not parse access & refresh tokens");
                res.send("<h1>OAuth Integration could not complete</h1><p>Sorry, could not retreive your access token. Try again...</p>");
                return;
            }

            // Cisco Spark OAuth flow completed
            debug("OAuth flow completed, for state: " + state, ", access token: " + json.access_token);
            oauthFlowCompleted(state, json.access_token, json.refresh_token, res);
        });
    });


//
// Step 3: this is where the integration runs its custom logic
//   - this function is called as the Cisco Spark OAuth flow has been successfully completed, 
//   - this function is expected to send back an HTML page to the end-user
//   
// some optional activities to perform here: 
//    - associate the issued Spark access token to a user through the state (acting as a Correlation ID)
//    - store the refresh token (valid 90 days) to reissue later a new access token (valid 14 days)
function oauthFlowCompleted(state, access_token, refresh_token, res) {

    //
    // Custom logic below
    //

    // Retreive user name: GET https://api.ciscospark.com/v1/people/me
    /*var options = {
        method: 'GET',
        url: 'https://api.ciscospark.com/v1/people/me',
        headers:
        {
            "authorization": "Bearer " + access_token
        }
    };i*/

    // create webhook for roomId=Y2lzY29zcGFyazovL3VzL01FU1NBR0UvM2RhNzAxZjAtMzAzMy0xMWU3LWI5OGItMWQ1ZDZmOGY1ZTVi

    var body_createWebhook = JSON.stringify({
        "name": "Message auto webhook creation",
        "targetUrl": "http://requestb.in/zfd5s6zf",
        "resource": "messages",
        "event": "created",
        "filter": "roomId=Y2lzY29zcGFyazovL3VzL1JPT00vNDMyZmJlYjAtMzAzMi0xMWU3LWIxYTgtNDcxYjQzOWM2OGM5"
    })
    var options_createWebhook = {
        method: 'POST',
        url: 'https://api.ciscospark.com/v1/webhooks',
        headers:
            {
                "authorization": "Bearer " + access_token
            }
    };

    request(options_createWebhook, function (error, response, body_createWebhook) {
        if (error) {
            debug("could not reach Cisco Spark to create webhook's details, error: " + error);
            res.send("<p>Sorry, could not create your Cisco Spark webhook details. Try again...</p>");
            return;
        }

        // Check the call is successful
        if (response.statusCode != 200) {
            debug("could not retreive your details, /webhooks returned: " + response.statusCode);
            res.send("<p>Sorry, could not create your Cisco Spark webhook. Try again...</p>");
            return;
        }

        var json= JSON.parse(body);
        if ((!json)) {
            debug("could not parse webhook creation result: bad json payload");
            res.send("<p>Sorry, could not retreive your Cisco Spark account details. Try again...</p>");
            return;
        }

        var str = read(join(__dirname, '/www/webhooks.ejs'), 'utf8');
        var compiled = ejs.compile(str)({ "webhooks": JSON.stringify(json)});
        res.send(compiled);
    });

    // Retreive webhooks: GET https://api.ciscospark.com/v1/webhooks
    /*var options_webhook = {
        method: 'GET',
        url: 'https://api.ciscospark.com/v1/webhooks',
        headers:
            {
                "authorization": "Bearer " + access_token
            }
    };

    request(options_webhook, function (error, response, body) {
        if (error) {
            debug("could not reach Cisco Spark to retreive webhook's details, error: " + error);
            res.send("<p>Sorry, could not retreive your Cisco Spark webhook details. Try again...</p>");
            return;
        }

        // Check the call is successful
        if (response.statusCode != 200) {
            debug("could not retreive your details, /webhooks returned: " + response.statusCode);
            res.send("<p>Sorry, could not retreive your Cisco Spark webhook details. Try again...</p>");
            return;
        }

        var json= JSON.parse(body);
        if ((!json)) {
            debug("could not parse webhook details: bad json payload");
            res.send("<h1>OAuth Integration could not complete</h1><p>Sorry, could not retreive your Cisco Spark account details. Try again...</p>");
            return;
        }

        debug("webhook details: " + body);

        var str = read(join(__dirname, '/www/webhooks.ejs'), 'utf8');
        var compiled = ejs.compile(str)({ "webhooks": JSON.stringify(json)});
        res.send(compiled);
    });*/

}


// Starts the Cisco Spark Integration
var port = process.env.OVERRIDE_PORT || process.env.PORT || 8080;
app.listen(port, function () {
    debug("Cisco Spark OAuth Integration started on port: " + port);
});
