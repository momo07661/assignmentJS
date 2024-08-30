// Import required modules
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');

// Initialize express app
const app = express();

// Middleware for parsing JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware configuration
app.use(
    session({
        secret: 'your-secret-key', // Replace with your secret key
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }, // Set to true if using HTTPS
    })
);

// MySQL database connection configuration
const db = mysql.createConnection({
    host: 'localhost',
    user: 'test', // Replace with your MySQL username
    password: 'assignmentJS123', // Replace with your MySQL password
    database: 'myapp', // Replace with your database name
    //insecureAuth : true
});

// Connect to MySQL database
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Route for user registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Check if username and password are provided
    if (!username || !password) {
        return res.status(400).json({ error: 'Please provide username and password' });
    }

    // Check if user already exists
    db.query('SELECT username FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;
        if (results.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the new user into the database
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
            if (err) throw err;
            res.status(201).json({ message: 'User registered successfully' });
        });
    });
});

// Route for user login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check if username and password are provided
    if (!username || !password) {
        return res.status(400).json({ error: 'Please provide username and password' });
    }

    // Check if user exists
    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) throw err;
        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const user = results[0];

        // Check if password is correct
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        // Create a JWT token
        const token = jwt.sign({ id: user.id }, 'your-jwt-secret', { expiresIn: '1h' }); // Replace 'your-jwt-secret' with your secret key

        // Set the session
        req.session.userId = user.id;

        res.json({ message: 'Login successful', token });
    });
});

// Route for user logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to logout' });
        }
        res.json({ message: 'Logout successful' });
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
