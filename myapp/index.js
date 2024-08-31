// Import required modules
const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const yahooFinance = require('yahoo-finance2').default;
const cors = require('cors');

// Initialize express app
const app = express();

// MySQL database connection configuration
const db = mysql.createConnection({
    host: 'localhost',
    user: 'test', // Replace with your MySQL username
    password: 'assignmentJS123', // Replace with your MySQL password
    database: 'myapp', // Replace with your database name
});

// Connect to MySQL database
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Use the CORS middleware
app.use(cors({
    origin: 'http://localhost:3001', // Replace with frontend URL
    methods: 'GET,POST,PUT,DELETE',
    credentials: true, // dealing with cookies or sessions
}));

// Middleware for parsing JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Session middleware configuration
app.use(
    session({
        secret: 'secret-key', // secret key
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }, //TODO: Set to true if using HTTPS
    })
);

// Middleware to check authentication
const authenticateToken = (req, res, next) => {
    console.log('user authentication')

    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });

    jwt.verify(token, 'jwt_secret', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Middleware to check if user is admin
function authenticateAdmin(req, res, next) {
    if (req.user.is_admin) {
        next();
    } else {
        res.status(403).json({ message: 'Admin privileges required' });
    }
}

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

        // Insert the new user into the users table
        db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
            if (err) throw err;

            res.status(201).json({ message: 'User registered successfully and cash initialized' });
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

        // Create a JWT token including the user role
        const token = jwt.sign({
            id: user.id,
            username: user.username,
            is_admin: user.is_admin // Include user role in the token payload
        }, 'jwt_secret', { expiresIn: '1h' }); // 'jwt_secret' with secret key

        // Set the session
        req.session.userId = user.id;

        res.json({ message: 'Login successful', token, is_admin: user.is_admin });
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

// Buy route
app.post('/buy', authenticateToken, (req, res) => {
    const { symbol, shares } = req.body;
    if (!symbol || !shares || isNaN(shares) || shares <= 0) {
        return res.status(400).json({ error: 'Invalid symbol or shares' });
    }

    const userId = req.user.id;

    // Check cash balance
    db.query('SELECT cash FROM users WHERE id = ?', [userId], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        const cash = results[0]?.cash || 0;

        try {
            // Fetch stock price from Yahoo Finance
            const quote = await yahooFinance.quote(symbol);
            const price = quote.regularMarketPrice;
            const totalCost = shares * price;

            if (totalCost > cash) {
                return res.status(400).json({ error: 'Insufficient funds' });
            }

            // Update user cash balance
            db.query('UPDATE users SET cash = ? WHERE id = ?', [cash - totalCost, userId], (err) => {
                if (err) return res.status(500).json({ error: 'Database error' });

                // Insert deal into deals table
                const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
                db.query('INSERT INTO deals (user_id, symbol, shares, price, total, time) VALUES (?, ?, ?, ?, ?, ?)',
                    [userId, symbol, shares, price, totalCost, now], (err) => {
                        if (err) return res.status(500).json({ error: 'Database error' });

                        res.status(200).json({ message: 'Purchase successful' });
                    });
            });
        } catch (error) {
            return res.status(500).json({ error: 'Error fetching stock price' });
        }
    });
});

// Sell route
app.post('/sell', authenticateToken, (req, res) => {
    const { symbol, shares } = req.body;
    if (!symbol || !shares || isNaN(shares) || shares <= 0) {
        return res.status(400).json({ error: 'Invalid symbol or shares' });
    }

    const userId = req.user.id;

    // Check user shares
    db.query('SELECT SUM(shares) AS shares FROM deals WHERE user_id = ? AND symbol = ?', [userId, symbol], async (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        const userShares = results[0]?.shares || 0;
        if (userShares < shares) {
            return res.status(400).json({ error: 'Not enough shares' });
        }

        try {
            // Fetch stock price from Yahoo Finance
            const quote = await yahooFinance.quote(symbol);
            const price = quote.regularMarketPrice;
            const totalValue = shares * price;

            // Update user cash balance
            db.query('SELECT cash FROM users WHERE id = ?', [userId], (err, results) => {
                if (err) return res.status(500).json({ error: 'Database error' });

                const cash = results[0]?.cash || 0;
                db.query('UPDATE users SET cash = ? WHERE id = ?', [cash + totalValue, userId], (err) => {
                    if (err) return res.status(500).json({ error: 'Database error' });

                    // Insert deal into deals table
                    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
                    db.query('INSERT INTO deals (user_id, symbol, shares, price, total, time) VALUES (?, ?, ?, ?, ?, ?)',
                        [userId, symbol, -shares, price, -totalValue, now], (err) => {
                            if (err) return res.status(500).json({ error: 'Database error' });

                            res.status(200).json({ message: 'Sale successful' });
                        });
                });
            });
        } catch (error) {
            return res.status(500).json({ error: 'Error fetching stock price' });
        }
    });
});

// History route
app.get('/history', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT symbol, shares, price, time FROM deals WHERE user_id = ? ORDER BY time DESC', [userId], (err, results) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        res.status(200).json(results);
    });
});

// Quote route
app.post('/quote', async (req, res) => {
    const { symbol } = req.body;
    if (!symbol) {
        return res.status(400).json({ error: 'Symbol is required' });
    }

    try {
        const quote = await yahooFinance.quote(symbol);
        res.status(200).json({ symbol: quote.symbol, price: quote.regularMarketPrice });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stock quote' });
    }
});


// Delete User Route
app.delete('/admin/deleteUser', authenticateToken, authenticateAdmin, async (req, res) => {
    const {username} = req.body;

    // Check if the user ID is provided
    if (!username) {
        return res.status(400).json({ error: 'required data is needed' });
    }

    // Delete the user from the database
    try {
        // Assuming you use MySQL
        await db.query('DELETE FROM users WHERE username = ?', [username]);

        // Send success response
        res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
        console.error('Database error: delete user failed', err);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Add-money route
app.post('/add-money', authenticateToken, authenticateAdmin, (req, res) => {
    const { userId, amount } = req.body;

    // Validate input
    if (!userId || !amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ message: 'Invalid user ID or amount' });
    }

    // Add money to the user’s account
    db.query('UPDATE users SET cash = cash + ? WHERE id = ?', [amount, userId], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'Money added successfully' });
    });
});

// Get balance route
app.get('/balance', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.query('SELECT cash FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ balance: results[0].cash });
    });
});

// Get owned stocks route
app.get('/owned-stocks', authenticateToken, (req, res) => {
    const userId = req.user.id;

    const query = `
        SELECT symbol, SUM(shares) AS shares
        FROM deals
        WHERE user_id = ?
        GROUP BY symbol
    `;

    db.query(query, [userId], (err, results) => {
        if (err) return res.status(500).json({ message: 'Database error' });

        res.json({
            stocks: results // Array of stocks with symbol and total shares
        });
    });
});



// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
