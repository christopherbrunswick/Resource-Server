/*const crypto = require('crypto');                  // Core Module - Generates random strings for security (nonce/state)
const jwt = require('jsonwebtoken');               // Library for decoding/verifying JWT tokens
const request = require('request-promise');        // Makes HTTP requests (e.g., token exchange)
const express = require('express');
const querystring = require('querystring');
const dfd = require('danfojs-node'); // data structures for data analysis install danfojs -> npm install danfojs-node



module.exports = (app) => { // function will expect an argument called app when being called
    const router = express.Router();
    const nonceCookie = 'auth0rization-nonce'; // Name of cookie that stores the nonce (replay protection)
    const { getPublicUrl } = require('../server.js');
    const redirectUri = getPublicUrl();
   // const { getPublicUrlEnd } = require('../server.js');
    //const endSessionUri = getPublicUrlEnd();
    
  // ---------------------- LOGIN FLOW ----------------------
    // Authorization endpoint to start OIDC login
    router.get('/login', (req, res) => {

        // Define constraints for Auth0 authorization request
        const oidcProviderInfo = app.locals.oidcProviderInfo;
        const authorizationEndpoint = oidcProviderInfo['authorization_endpoint']; // /authorize
        const responseType = 'code';     // We want authorization_code flow
        const scope = 'openid profile email_verified created_at read:to-dos'; // Data/scopes we’re requesting
        const clientID = process.env.CLIENT_ID; // Auth0 Client ID
        //const redirectUri = redirectUri; // Redirect URI (must match Auth0 config) - should be an ngrok callback to connect to AuthO
        const responseMode = 'query';   // Auth0 sends back tokens via query string
        const nonce = crypto.randomBytes(16).toString('hex'); // Nonce to prevent replay
        const state = crypto.randomBytes(16).toString('hex'); // State to prevent CSRF
        const audience = process.env.API_IDENTIFIER;          // API audience we’re requesting access to
        

        // Cookie options (signed, expires in 15 minutes, HTTP-only)
        const options = {
            maxAge: 1000 * 60 * 15, // determines cookie lifespan
            httpOnly: true, // prevents client-side scripts from accessing the cookie preventing XSS attacks
            secure: true, // ensures cookie is only sent over https connections - protects cookie from being intercepted by man-in-the-middle (MITM) attacks
            signed: true, // server signs cookie letting Auth0 know where it came from
        };

        // Save nonce & state into cookies, then redirect user to Auth0’s hosted login
        res
            .cookie('auth0rization-state', state, options) //
            .cookie(nonceCookie, nonce, options)
            .redirect(
                authorizationEndpoint + 
                '?response_mode=' + responseMode +
                '&response_type=' + responseType +
                '&scope=' + scope +
                '&client_id=' + clientID +
                '&redirect_uri=' + redirectUri +
                '&nonce=' + nonce +
                '&state=' + state +
                '&audience=' + audience 
            );
        });

    // ---------------------- VALIDATION ID TOKEN ----------------------
    // Function to validate ID token returned from Auth0
    function validateIDToken(idToken, nonce, oidcProviderInfo) {
    const decodedToken = jwt.decode(idToken); // Decode JWT (not verifying signature yet)

    // Extract important fields
    const {
        nonce: decodedNonce,
        aud: audience,
        exp: expirationDate,
        iss: issuer
    } = decodedToken;

    const currentTime = Math.floor(Date.now() / 1000);
    const expectedAudience = process.env.CLIENT_ID;

    // Check audience, nonce, expiration, issuer
    if (
        audience !== expectedAudience ||
        decodedNonce !== nonce ||
        expirationDate < currentTime ||
        issuer !== oidcProviderInfo['issuer']
    )
        throw new Error('ID token validation failed');

    return decodedToken; // If valid, return decoded token
    }

    // ---------------------- CALLBACK ----------------------
    // Callback route (Auth0 redirects here after login)
    router.get('/callback', async (req, res) => {
        const { code, state } = req.query; // Extract code & state from query params
        const bubbleRedirectLogin = process.env.BUBBLE_REDIRECT_LOGIN;

        // debugging 
        if (!code) {
            return res.status(400).send("Missing code");
        }
        console.log("Auth code received:", code);

        // Verify state parameter matches stored cookie
        const storedState = req.signedCookies['auth0rization-state'];
        if (!storedState || storedState !== state) {
            return res.status(401).send('Invalid state parameter'); // CSRF protection
        }
        delete req.signedCookies['auth0rization-state']; // Clear cookie

        // Prepare token exchange request - sending post request to auth0
        const codeExchangeOptions = {
            grant_type: 'authorization_code',
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            code: code,
            redirect_uri: redirectUri // needs to be same callback as above - ngrok
        };

        // Send POST to Auth0 /oauth/token endpoint to exchange code for tokens
        const codeExchangeResponse = await request.post(
            `https://${process.env.OIDC_PROVIDER}/oauth/token`,
            { form: codeExchangeOptions }
        );

        // Parse tokens from response
        const tokens = JSON.parse(codeExchangeResponse);
        req.session.accessToken = tokens.access_token;

        // Extract nonce cookie & delete it
        const nonce = req.signedCookies[nonceCookie];
        delete req.signedCookies[nonceCookie];

        try {
            // Validate ID token and save in session
            req.session.decodedIdToken = validateIDToken(tokens.id_token, nonce, app.locals.oidcProviderInfo);
            req.session.idToken = tokens.id_token;
            res.redirect(bubbleRedirectLogin); // Redirect user to bubble welcome page
        } catch (error) {
            res.status(401).send(); // Invalid token
        }
    });

    /*---------------------------- HANDLING CSV UPLOADS - BUBBLE -----------------------------*/
    const { check, validationResult } = require('express-validator');
    const multer = require('multer'); // express middleware for handling mult-part form data primarily used for uploading files
    const { parse } = require('csv-parser');
    const fs = require('fs');
    const stringSimilarity = require('string-similarity'); // for fuzzy matching

    router.get('/csvSubmission', async (req, res) => {
        // Configuring Multer for file upload security
        const storage = multer.memoryStorage(); // Store file in memory
        const upload = multer({
            //dest: 'uploads/', // temporary storage folder for uploaded files
            storage: storage,
            limits: {
                fileSize: 1024 * 1024 * 1024 // limit filesize to 1GB
            },
            fileFilter: (req, file, cb) => {
                // accepting .csv .xls .xlsx
                // .csv simple plain-text cross-platform data interchange formats
                // .xls proprietary binary microsoft excel spreadsheets containing advanced formatting, formulas, and multiple sheets
                if (file.mimetype === 'text/csv' || file.mimetype === 'application/vnd.ms-excel' || file.mimetype === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') {
                    cb(null, true)
                } else {
                    cb(new Error('Only CSV files are allowed!'), false);
                }
            }
        });

        request.post('/upload-csv', 
            upload.single('csvFile'), 
            [
                check('csvFile').custom((value, { req }) => {
                    if (!req.file) {
                        throw new Error('Please upload a CSV file.');
                    }
                    return true;
                })
            ],
            async (req, res) => {
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    return res.status(400).json({ errors: errors.array() });
                }

                const results = [];
                const bufferStream = require('stream').Readable.from(req.file.buffer);
                const sexVal = ['male', 'female'];
                const raceVal = ['black', 'hispanic', 'white', 'other'];
                //const sexOrientationVal = [];
                bufferStream
                    .pipe(parse())
                    .on('data', (data) => {
                        // Perform cleansing and validation on each row (data)
                        // Example: Trim strings, convert types, validate values
                        const cleanedData = {
                            // Demographics
                            firstName: data.firstName ? data.firstName.trim() && data.firstName.toLowerCase() : '',
                            lastName: data.kastName ? data.lastName.trim() && data.lastName.toLowerCase() : '',
                            age: parseInt(data.age) || 0,
                            sex: data.sex && sexVal.includes() ? data.sex.trim() && data.sex.toLowerCase() : '',
                            nationality: data.nationality ? data.nationality.trim() : '',
                            race: data.race && raceVal.includes(data.race.trim()) ? data.race.trim() : '',
                            //sexualOrientation: data.sexualOrientation
                            ethnicity: data.ethnicity
                            employment: data.employment
                            education: data.education
                            housing: data.housing
                            victimType: data.victimType
                            childWelfareServices: data.childWelfareServices
                            genderIdentity:
                            primaryCaregiver:
                            familySupport:
                            sexualExploitationHistory:

                            // ... further cleansing and validation
                        };
                        results.push(cleanedData);
                    })
                    .on('end', () => {
                        // All rows processed
                        console.log('CSV parsing complete. Cleaned data:', results);

                        // Access the complete array 
                        console.log(results);

                    }).on('error', (err) => {
                        console.error('CSV parsing error:', err);
                        //res.redirect()
                    });
                });
    });

    // ------------------------------ FLASK SERVER ------------------------------
    router.post('/sendToFlask', async(req, res) => {
        // send data from express server to flask server
        const sendResults = results; //data from express.js app

        try {
            const response = await fetch('http://localhost:5000/flaskmc', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ data: sendResults })});
            const data = await response.json(); //flask response
            res.status(200).json({ message: 'Data sent to Flask successfully', data});
        } catch (error) {
            console.error('Error sending data to Flask Server:', error);
            res.status(500).json({ error: 'Failed to send data to Flask' });
        }
    });

    /*
    router.get('/getFromFlask', async (req, res) => {
        try{
            const response = await fetch(/* /predict, {
                method: 'POST',
                headers: {
                    'Content-Type: 'application/json'
                },

                // Send results to flask server
                body: JSON.stringify({ data: jsOutput })
                } *); // call flask api
            const data = await response.json();
            res.json(data);
        } catch (error) {
            console.error('Error fetching from flask:', error);
            res.status(500).json({ error: 'Failed to fetch data from flask' });
        }
    });*/
    

    //--------------------------- LOGOUT --------------------------------
    router.get('/logout', async (req, res) => {

        const idToken = req.session.idToken;
        const bubbleRedirectLogout = process.env.BUBBLE_REDIRECT_LOGOUT;

       // 1. clear application session
       req.session.destroy(err => {

        if (err) {
            console.error('Error destroying session:', err);
        }

        // 2. Define constraints for Auth0 RP-Initiated Logout End Session Endpoint Discovery request
        //const endSessionEndpoint = oidcProviderInfo['end_session_endpoint'];
        const logoutParams = {
            idTokenHint: idToken,
            //const logoutHint = 
            //postLogoutRedirectUri: bubbleRedirectLogout, //OIDC standard logout
            clientID: process.env.CLIENT_ID,
            returnTo: bubbleRedirectLogout // Auth0 logout
            //const federated
            //const state
            //const
        };
        
        // Encode the parameters to be included in the URL
        const query = querystring.stringify(logoutParams);

        // 3. Construct and place the redirect URL
        const auth0LogoutUrl = `https://${process.env.OIDC_PROVIDER}/v2/logout?${query}`;

        res.redirect(auth0LogoutUrl);
       });
        
    });

    app.use(router);

};