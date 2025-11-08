// routes/todos.js
const express = require('express');
const jwt = require('jsonwebtoken');
const sql = require('mssql');
const jwksClient = require('jwks-rsa');

module.exports = (app) => {
  const router = express.Router();

  /* SQL Server configuration
  const dbConfig = {
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    options: {
      encrypt: true,
      trustServerCertificate: true
    },
    pool: {
      max: 10,
      min: 0,
      idleTimeoutMillis: 30000
    }
  };

  // Create a connection pool
  const pool = new sql.ConnectionPool(dbConfig);
  const poolConnect = pool.connect();*/

  // JWKS client for Auth0
  const client = jwksClient({
    jwksUri: `https://${process.env.OIDC_PROVIDER}/.well-known/jwks.json`
  });

  // Function to retrieve the signing key
  const getKey = (header, callback) => {
    client.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      const signingKey = key.getPublicKey();
      callback(null, signingKey);
    });
  };

  // Middleware: Validate Auth0 access token
  async function validateAccessToken(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });

      const token = authHeader.split(' ')[1];
      if (!token) return res.status(401).json({ error: 'Malformed token' });

      const oidcProviderInfo = req.app.locals.oidcProviderInfo;
      const expectedAudience = process.env.API_IDENTIFIER;

      jwt.verify(token, getKey, {
        audience: expectedAudience,
        issuer: oidcProviderInfo.issuer
      }, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token', details: err.message });
        req.user = decoded;
        next();
      });
    } catch (err) {
      console.error(err);
      res.status(401).json({ error: 'Unauthorized', details: err.message });
    }
  }

  // GET /api/todos -> fetch all todos for user
  router.get('/api/todos', validateAccessToken, async (req, res) => {
    try {
      await poolConnect;
      const result = await pool.request()
        .input('userId', sql.NVarChar, req.user.sub)
        .query('SELECT * FROM Todos WHERE userId = @userId');

      res.json(result.recordset);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Database error', details: err.message });
    }
  });

  // POST /api/todos -> create a new todo
  router.post('/api/todos', validateAccessToken, async (req, res) => {
    const { title, completed } = req.body;
    if (!title) return res.status(400).json({ error: 'Missing title' });

    try {
      await poolConnect;
      const result = await pool.request()
        .input('userId', sql.NVarChar, req.user.sub)
        .input('title', sql.NVarChar, title)
        .input('completed', sql.Bit, completed ? 1 : 0)
        .query(`
          INSERT INTO Todos (userId, title, completed)
          OUTPUT INSERTED.*
          VALUES (@userId, @title, @completed)
        `);

      res.status(201).json(result.recordset[0]);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Database error', details: err.message });
    }
  });

  // DELETE /api/todos/:id -> delete a todo
  router.delete('/api/todos/:id', validateAccessToken, async (req, res) => {
    const { id } = req.params;

    try {
      await poolConnect;
      await pool.request()
        .input('id', sql.Int, id)
        .input('userId', sql.NVarChar, req.user.sub)
        .query('DELETE FROM Todos WHERE id = @id AND userId = @userId');

      res.status(204).send();
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Database error', details: err.message });
    }
  });

  // Attach router to app
  app.use(router);
};
