const mysql = require('mysql2/promise'); // Use the promise version

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

pool.getConnection()
  .then(() => {
    console.log('Connected to the database.');
  })
  .catch(err => {
    console.error('Database connection failed:', err);
  });

module.exports = pool;