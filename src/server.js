// ===========================
// server.js
// ===========================
const express = require('express');  // web dev framwork in node.js
const cookieParser = require('cookie-parser'); //express middleware
const crypto = require('crypto'); // node core module for cryptographic functions
const session = require('express-session'); // express middleware
const helmet = require('helmet'); // express middleware that improves safeguarding HTTP requests returned by node.js app
const request = require('request-promise');
const cors = require('cors');
require('dotenv').config();
const ngrok = require('@ngrok/ngrok'); // ngrok software development kit (SDK)
const userRoutes = require('./routes/user.js');
//const todoRoutes = require('./routes/todos.js');


const NODE_ENV = process.env.NODE_ENV || 'development';
const app = express();

let ngrokUrl; // will hold the ngrok url

// ===========================
// Middleware - functions executed during the processing of HTTP requests
// ===========================
app.use(helmet()); // registering helmet in express app - adds 15 sub middlewares to app -additional security headers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(crypto.randomBytes(16).toString('hex')));
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false
}));

app.use(cors({
  origin: 'https://christopherbrunswick.bubbleapps.io', // Bubble frontend
  credentials: true
}));

// ===========================
// Test route
// ===========================
app.get('/', (req, res) => {
  res.send("✅ Server is running through ngrok tunnel!");
});

// ===========================
// OIDC Discovery (Auth0) - discovery endpoint
// ===========================
let oidcProviderInfo;

async function fetchOIDCProviderInfo() {
  const { OIDC_PROVIDER } = process.env;
  const discEnd = `https://${OIDC_PROVIDER}/.well-known/openid-configuration`; //https://dev-v5kwwhbl6vx1nj4j.us.auth0.com/.well-known/openid-configuration

  try {
    const res = await request(discEnd);
    oidcProviderInfo = JSON.parse(res);
    app.locals.oidcProviderInfo = oidcProviderInfo;
    console.log("✅ OIDC provider info fetched successfully");
  } catch (err) {
    console.error("Unable to fetch OIDC provider info:", err);
    process.exit(1);
  }
}

// ===========================
// Start server + ngrok
// ===========================
async function startServer() {
  await fetchOIDCProviderInfo();
  const PORT = process.env.PORT || 3000;

  // Import routes after OIDC info is available
  //require('./routes/user.js')(app);
  //app.use('/api', router);
  // require('./routes/todos')(app); // optional for later

  app.listen(PORT, '0.0.0.0', async () => {
    console.log(`Server running on http://localhost:${PORT}`);

    if (NODE_ENV === 'development') {
      try {
        const url = await ngrok.connect({
          addr: PORT,
          authtoken: process.env.NGROK_AUTHTOKEN
        });
        ngrokUrl = url.url();
        console.log(`ngrok tunnel established at: ${ngrokUrl}`);
        console.log(`Use this redirect_uri in Auth0 and Bubble`);
        // Only now import user routes so getPublicUrl() works
        userRoutes(app);
        
        // next get todos
        //todoRoutes(app);
      } catch (err) {
        console.error("ngrok connection error:", err);
      }
    } else {
      userRoutes(app);
    }
  });
}

startServer();

function getPublicUrl() {
  if (!ngrokUrl) throw new Error('ngrok URL not available yet');
  return ngrokUrl + '/callback'; // append your callback path
}

// ===========================
// Export url for other modules
// ===========================
//const getPublicUrl = () => ngrokUrl;
module.exports = { app, startServer, getPublicUrl };

// ===========================
// Export app for testing
// ===========================
//module.exports = {app};
