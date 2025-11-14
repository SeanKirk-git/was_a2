const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10; // Used for password hashing

// Uses the DATABASE_URL environment variable configured in Render.
const connectionString = process.env.DATABASE_URL;

// Checks if DATABASE_URL is set in Render and enables SSL.
const sslConfig = process.env.DATABASE_URL ? { rejectUnauthorized: false } : false;

// Creates PostgreSQL connection pool
const pool = new Pool({
    connectionString: connectionString,
    ssl: sslConfig
});

// Uses the SESSION_SECRET environment variable configured in Render to connect to the db.
const sessionSecret = process.env.SESSION_SECRET;


//Middleware configuration

// CORS (Cross Origin Resource Sharing) setup
// Needed to allow frontend which is on a different domain to make API requests
app.use(cors({
    // Uses the FRONTEND_URL environment variable configured in Render
    origin: process.env.FRONTEND_URL, 
    credentials: true // Enables session cookies.
}));

// Parses incoming JSON request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// express-session used to handle user sessions.
// Uses 'connect-pg-simple' to store session data in the PostgreSQL database.
app.use(session({
    store: new PgSession({
        pool: pool, // Uses the existing database pool
        tableName: 'user_sessions' // Name of the sessions table
    }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Uses secure cookies in production.
        httpOnly: true, // Prevents client-side JS from accessing the cookie
        maxAge: 1000 * 60 * 60 * 24 // Cookie expiration = 1 day
    }
}));

// Middleware to protect routes that require login
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'You are not authenticated.' });
    }
}


// Database Creation

// Function to create database tables if they don't exist yet
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        // Creates the 'users' table
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Creates the 'user_sessions' table for express-session
        await client.query(`
            CREATE TABLE IF NOT EXISTS "user_sessions" (
                "sid" varchar NOT NULL COLLATE "default",
                "sess" json NOT NULL,
                "expire" timestamp(6) NOT NULL
            )
            WITH (OIDS=FALSE);
            
            ALTER TABLE "user_sessions" 
            ADD CONSTRAINT "user_sessions_pkey" 
            PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE;
        `);

        console.log('Database tables successfully created.');
    } catch (err) {
        console.error('Error creating database:', err);
    } finally {
        client.release();
    }
}

// API Endpoints
// Endpoint = POST /register

//Registers user account
app.post('/register', async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    // Input Validation (Server Side)
    // "Username" field validation. Only allows alphabets and numbers. Requires 8+ characters.
    const usernameRegex = /^[a-zA-Z0-9]{8,}$/;
    if (!username || !usernameRegex.test(username)) {
        return res.status(400).json({ success: false, message: 'Invalid username. Must be 8+ characters. Use only alphabets and numbers.' });
    }

    // "Email" field validation. Checks for valid email format.
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Please use a valid email address.' });
    }

    // "Password" field validation. Only allows alphabets and numbers. Requires 8+ characters.
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    if (!password || !passwordRegex.test(password)) {
        return res.status(400).json({ success: false, message: 'Invalid password. Must be 8+ characters. Use only alphabets and numbers.' });
    }

    // Checks that values in "Password" and "Confirm Password" match.
    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Does not match entered password.' });
    }

    // Creates a hash of password using bcrypt
    let hashedPassword;
    try {
        hashedPassword = await bcrypt.hash(password, saltRounds);
    } catch (hashError) {
        console.error('Password hashing failed:', hashError);
        return res.status(500).json({ success: false, message: 'Server error.' });
    }

    // Database insertion
    try {
        const queryText = `
            INSERT INTO users (username, email, password_hash)
            VALUES ($1, $2, $3)
            RETURNING id, username;
        `;

        // Uses parameterized queries to prevent SQL injection attacks.
        // pg library separately takes query text ($1, $2 used as placeholders) and values array.
        // Sanitizes values before inserting them into query.
        const values = [username, email, hashedPassword];
        
        const result = await pool.query(queryText, values);
        const user = result.rows[0];

        // Creates a session for newly registered user to immediately log them in.
        req.session.userId = user.id;
        req.session.username = user.username;

        res.status(201).json({ 
            success: true, 
            message: 'Registration successful!',
            username: user.username 
        });

    } catch (dbError) {
        // Handling of database errors
        if (dbError.code === '23505') { // Unique violation
            return res.status(409).json({ success: false, message: 'Username or email already exists.' });
        }
        console.error('Database insertion error:', dbError);
        return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});


// Endpoint = POST /login
// Logs user in if account exists in db.
app.post('/login', async (req, res) => {
    const { username, password } = req.body; 

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username/Email and password are required.' });
    }

    // Searches for user account using either "username" or "email"
    try {
        const queryText = `
            SELECT id, username, password_hash 
            FROM users 
            WHERE username = $1 OR email = $1;
        `;
        
        // Uses parameterized query to prevent SQL injection
        const values = [username];
        const result = await pool.query(queryText, values);
        
        const user = result.rows[0];

        // Error handling if account not found
        if (!user) {
            return res.status(404).json({ success: false, message: 'Account not found. Please register.' });
        }

        // Checks if inserted password matched the stored hash using bcrypt.compare .
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            // Creates a session if password matches stored hash
            req.session.userId = user.id;
            req.session.username = user.username;
            
            res.status(200).json({ 
                success: true, 
                message: 'Login successful!',
                username: user.username
            });
        } else {
            // Error handling for incorrect password
            res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }
        
    } catch (dbError) {
        console.error('Login database error:', dbError);
        return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

// Endpoint = POST /logout
// Logs out user by destroying the session.
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Error: Could not log out.' });
        }
        // Clears session cookie
        res.clearCookie('connect.sid'); // The default session cookie name
        res.status(200).json({ success: true, message: 'You have been logged out successfully.' });
    });
});

// Endpoint = POST /check-session
// Checks for active session
app.post('/check-session', isAuthenticated, (req, res) => {
    // 'isAuthenticated' middleware already checked the session.
    // User is already logged in if this point is reached.
    res.status(200).json({
        success: true,
        message: 'Session is active.',
        username: req.session.username
    });
});


// Starts the server if db is ready
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    initializeDatabase();
});
