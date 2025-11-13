const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const cors = require('cors');

// --- CONFIGURATION ---

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10; // For password hashing

// Use the DATABASE_URL environment variable provided by Render.
// Fallback to a local default (update this for your local machine).
const connectionString = process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/assignment2';

// Check if DATABASE_URL is set (like on Render) and enable SSL if so.
const sslConfig = process.env.DATABASE_URL ? { rejectUnauthorized: false } : false;

// Setup PostgreSQL connection pool
const pool = new Pool({
    connectionString: connectionString,
    ssl: sslConfig
});

// Use a long, random string for session secret in production!
// Store this in your Render environment variables.
const sessionSecret = process.env.SESSION_SECRET || 'a-very-weak-local-secret-key';

// --- MIDDLEWARE SETUP ---

// 1. CORS (Cross-Origin Resource Sharing)
// This is required to allow your frontend (on a different domain)
// to make API requests to this backend.
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5500', // Allow your frontend URL
    credentials: true // Allow cookies (for sessions)
}));

// 2. Body Parser
// This parses incoming JSON request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 3. Express Session
// This middleware handles user sessions.
// We use 'connect-pg-simple' to store sessions in our PostgreSQL database.
// This is crucial for a stateless hosting environment like Render.
app.use(session({
    store: new PgSession({
        pool: pool, // Use our existing database pool
        tableName: 'user_sessions' // Name of the session table
    }),
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
        httpOnly: true, // Prevents client-side JS from accessing the cookie
        maxAge: 1000 * 60 * 60 * 24 // Cookie expires in 1 day
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

// --- DATABASE INITIALIZATION ---

// Function to create necessary database tables if they don't exist
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        // Create 'users' table
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Create 'user_sessions' table (for express-session)
        // This schema is from the 'connect-pg-simple' documentation
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

        console.log('Database tables initialized successfully.');
    } catch (err) {
        console.error('Error initializing database:', err);
    } finally {
        client.release();
    }
}

// --- API ENDPOINTS ---

/**
 * Endpoint: POST /register
 * Registers a new user.
 */
app.post('/register', async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    // --- 1. Server-Side Input Validation (Requirement 10) ---

    // a. Username validation
    const usernameRegex = /^[a-zA-Z0-9]{9,}$/;
    if (!username || !usernameRegex.test(username)) {
        return res.status(400).json({ success: false, message: 'Invalid username. Must be 9+ characters, letters and numbers only.' });
    }

    // b. Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email address format.' });
    }

    // c. Password validation
    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{9,}$/;
    if (!password || !passwordRegex.test(password)) {
        return res.status(400).json({ success: false, message: 'Invalid password. Must be 9+ characters, with at least one letter and one number.' });
    }

    // d. Confirm password validation
    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Passwords do not match.' });
    }

    // --- 2. Password Hashing (Requirement 9) ---
    // We use bcrypt to create a secure hash of the user's password.
    // We never store the plain-text password in the database.
    let hashedPassword;
    try {
        hashedPassword = await bcrypt.hash(password, saltRounds);
    } catch (hashError) {
        console.error('Password hashing failed:', hashError);
        return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }

    // --- 3. Database Insertion (with SQL Injection Prevention) ---
    try {
        const queryText = `
            INSERT INTO users (username, email, password_hash)
            VALUES ($1, $2, $3)
            RETURNING id, username;
        `;
        
        // --- SQL Injection Prevention (Requirement 11) ---
        // We use parameterized queries. The `pg` library takes the
        // queryText (with $1, $2 placeholders) and the values array
        // separately. It sanitizes the values *before* inserting them
        // into the query, making SQL injection impossible.
        // We NEVER build a query string like: "INSERT... VALUES ('" + username + "', ...)"
        const values = [username, email, hashedPassword];
        
        const result = await pool.query(queryText, values);
        const user = result.rows[0];

        // --- 4. Auto-Login (Requirement 5) ---
        // Create a session for the new user immediately.
        req.session.userId = user.id;
        req.session.username = user.username;

        res.status(201).json({ 
            success: true, 
            message: 'Registration successful!',
            username: user.username 
        });

    } catch (dbError) {
        // Handle database errors (e.g., username or email already exists)
        if (dbError.code === '23505') { // Unique violation
            return res.status(409).json({ success: false, message: 'Username or email already exists.' });
        }
        console.error('Database insertion error:', dbError);
        return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});


/**
 * Endpoint: POST /login
 * Logs in an existing user.
 */
app.post('/login', async (req, res) => {
    const { username, password } = req.body; // 'username' can be username or email

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username/Email and password are required.' });
    }

    // --- 1. Find User (with SQL Injection Prevention) ---
    try {
        const queryText = `
            SELECT id, username, password_hash 
            FROM users 
            WHERE username = $1 OR email = $1;
        `;
        
        // --- SQL Injection Prevention (Requirement 11) ---
        // Again, we use a parameterized query.
        const values = [username];
        const result = await pool.query(queryText, values);
        
        const user = result.rows[0];

        // (Requirement 7) User not found
        if (!user) {
            return res.status(404).json({ success: false, message: 'Account not found. Please register.' });
        }

        // --- 2. Verify Password (using hashing) ---
        // We use bcrypt.compare to securely check if the provided
        // password matches the stored hash.
        const match = await bcrypt.compare(password, user.password_hash);

        if (match) {
            // Password is correct! Create a session.
            req.session.userId = user.id;
            req.session.username = user.username;
            
            res.status(200).json({ 
                success: true, 
                message: 'Login successful!',
                username: user.username
            });
        } else {
            // Password incorrect
            res.status(401).json({ success: false, message: 'Invalid username or password.' });
        }
        
    } catch (dbError) {
        console.error('Login database error:', dbError);
        return res.status(500).json({ success: false, message: 'Server error. Please try again.' });
    }
});

/**
 * Endpoint: POST /logout
 * Logs out the current user by destroying their session.
 */
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ success: false, message: 'Could not log out. Please try again.' });
        }
        // Clear the session cookie
        res.clearCookie('connect.sid'); // The default session cookie name
        res.status(200).json({ success: true, message: 'Logged out successfully.' });
    });
});

/**
 * Endpoint: POST /check-session
 * Checks if a user has an active session.
 */
app.post('/check-session', isAuthenticated, (req, res) => {
    // The 'isAuthenticated' middleware already checked the session.
    // If we get here, the user is logged in.
    res.status(200).json({
        success: true,
        message: 'Session is active.',
        username: req.session.username
    });
});

// --- START SERVER ---

// Start the server after ensuring the database is ready
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
    initializeDatabase();
});