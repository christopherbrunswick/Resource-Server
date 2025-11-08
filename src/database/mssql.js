const express = require('express');
const sql = require('mssql');
//const connection = require('tedious').Connection;
//const request = require('tedious').Request;

// SQL Server connection pooling is a mechanism designed to enhance application 
// performance and scalability by reducing the overhead associated with establishing 
// and closing database connections. Instead of opening a new connection for every 
// database operation, connection pooling maintains a "pool" of open, reusable connections.

module.exports = (app) => {
    const router = express.Router();

    // SQL Server configuration
    const dbConfig = {
        server: process.env.DB_SERVER,
        database: process.env.DB_NAME,
        userName: process.env.DB_USER,
        passWord: process.env.DB_PASSWORD,
        options: {
            encrypt: true, // for azure
            trustServerCertificate: true // change to false for production purposes
        },
        // pooling will enhance performance of application server - maintain a "pool" of open, reusable connections
        pool: {
            max: 10,
            min: 0,
            idleTimeoutMillis: 30000
        }
    }
};

// Create a connection pool
const pool = new sql.ConnectionPool(dbConfig);
const poolConnect = pool.connect();

poolConnect
  .then(() => console.log("✅ Connected to MSSQL"))
  .catch(err => console.error("❌ Database connection failed: ", err));

module.exports = {
    sql,
    poolConnect
};



