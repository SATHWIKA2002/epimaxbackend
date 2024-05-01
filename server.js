const express = require('express');
const { open } = require('sqlite');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const dbPath = path.join(__dirname, 'epimax.db');

let db = null;

const initializeDb = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
        console.log('Connected to SQLite database');
        app.listen(port, () => console.log(`Server running on port ${port}`));
    } catch (error) {
        console.error('DB Error:', error.message);
        process.exit(1);
    }
};

initializeDb();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).send('Authentication required');
    }

    jwt.verify(token, 'MY_SECRET_TOKEN', (err, decodedToken) => {
        if (err) {
            return res.status(403).send('Invalid token');
        }
        req.user = decodedToken;
        next();
    });
};

// Register User
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const existingUser = await db.get('SELECT * FROM Users WHERE username = ?', username);
        if (existingUser) {
            return res.status(400).send('User already exists');
        }
        await db.run('INSERT INTO Users (username, password) VALUES (?, ?)', username, hashedPassword);
        res.status(201).send('User registered successfully');
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Internal server error');
    }
});

// Login User
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await db.get('SELECT * FROM Users WHERE username = ?', username);
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).send('Invalid username or password');
        }
        const token = jwt.sign({ id: user.id, username: user.username }, 'MY_SECRET_TOKEN');
        res.status(200).send({ token });
    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).send('Internal server error');
    }
});

// Other endpoints (tasks, etc.) go here

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
