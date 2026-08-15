const express = require('express');
const { Client } = require('pg');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());

const client = new Client({ connectionString: "postgres://dbuser:SecretPass123!@localhost:5432/mydb" });
const db = new sqlite3.Database(':memory:');

// Vulnerable Endpoint 1: Direct String Concatenation in SQL Query
app.get('/api/users/search', (req, res) => {
    const userId = req.query.id;
    // CRITICAL SQL INJECTION: Untrusted user query param concatenated into query
    const sql = "SELECT id, username, email FROM users WHERE id = " + userId;
    
    client.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result.rows);
    });
});

// Vulnerable Endpoint 2: Template Literal String Interpolation
app.post('/api/products/filter', (req, res) => {
    const category = req.body.category;
    const minPrice = req.body.min_price;

    // HIGH SQL INJECTION: Template literal interpolation in raw SQL query
    const query = `SELECT * FROM products WHERE category = '${category}' AND price >= ${minPrice}`;
    
    client.query(query, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result.rows);
    });
});

// Vulnerable Endpoint 3: Dynamic ORDER BY Clause Construction
app.get('/api/reports', (req, res) => {
    const sortBy = req.query.sort || 'id';
    
    // MEDIUM SQL INJECTION: Dynamic ORDER BY column identifier interpolation
    const sql = "SELECT * FROM sales_reports ORDER BY " + sortBy + " DESC";
    
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// SAFE Endpoint 1: Prepared Statement Parameterized Query (False Positive Check)
app.get('/api/users/safe-search', (req, res) => {
    const userId = req.query.id;
    // SECURE: Parameterized positional binding
    const sql = "SELECT id, username, email FROM users WHERE id = $1";
    
    client.query(sql, [userId], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result.rows);
    });
});

// SAFE Endpoint 2: Sanitized Integer Casting (False Positive Check)
app.get('/api/users/sanitized-search', (req, res) => {
    const safeId = parseInt(req.query.id, 10);
    // SECURE: Input sanitized via parseInt
    const sql = "SELECT id, username, email FROM users WHERE id = " + parseInt(safeId);
    
    client.query(sql, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(result.rows);
    });
});

app.listen(3000, () => console.log('Node sample running on port 3000'));
