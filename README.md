Secure Web Service with OAuth 2.0 Authentication and Security Measures

🚀 Overview

This project implements a secure web service with the following key features:

Security Enhancements:

Enforces HTTPS for secure communication.

Implements CORS restrictions to prevent unauthorized access.

Adds security headers using helmet to prevent attacks.

Uses input validation to sanitize and validate requests.

Implements rate limiting to mitigate brute-force attacks.

OAuth 2.0 Authentication:

Uses JWT tokens for secure user authentication.

Implements passport.js for handling token verification.

Protects API endpoints from unauthorized access.

📌 Features Implemented

Security Measures (Q2)

✅ Enforce HTTPS (via server configuration)
✅ Use helmet for security headers
✅ Enable CORS with allowed origins
✅ Input validation using express-validator
✅ Implement rate limiting to prevent abuse

OAuth 2.0 Authentication (Q5)

✅ Issue JWT tokens for authenticated users
✅ Protect API routes using passport.js
✅ Use token-based authentication for secure access

🛠️ Tech Stack

Backend: Node.js, Express.js

Security: Helmet, CORS, Rate Limiting, JWT

Authentication: Passport.js with JWT Strategy

🏗️ Installation & Setup

1️⃣ Clone the repository

git clone https://github.com/your-repo/secure-api.git
cd secure-api

2️⃣ Install dependencies

npm install

3️⃣ Create .env file

touch .env

Add the following environment variables:

PORT=5000
JWT_SECRET=your_super_secret_key

4️⃣ Run the server

npm start

🔒 Security Implementation

1. Using Helmet for Security Headers

Helmet helps protect against common web vulnerabilities like XSS, Clickjacking, and MIME sniffing.

const helmet = require('helmet');
app.use(helmet());

2. Enabling CORS Restrictions

Restrict API access to only allowed origins.

const cors = require('cors');
app.use(cors({
    origin: 'https://your-frontend.com',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

3. Rate Limiting to Prevent Abuse

Limits repeated API requests from a single IP.

const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

4. Input Validation to Prevent Injection Attacks

Using express-validator to validate and sanitize user input.

const { body, validationResult } = require('express-validator');
app.post('/api/submit',
    [
        body('name').isString().trim().escape().notEmpty(),
        body('email').isEmail().normalizeEmail()
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        res.json({ message: "Data submitted securely" });
    }
);

🔐 OAuth 2.0 Authentication

1. Implement JWT-Based Authentication

Use JWT (JSON Web Token) for secure authentication.

const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.JWT_SECRET || 'supersecretkey';

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (username === "admin" && password === "password123") {
        const user = { id: 1, username };
        const token = jwt.sign(user, SECRET_KEY, { expiresIn: '1h' });
        return res.json({ token });
    }
    return res.status(401).json({ message: "Invalid credentials" });
});

2. Protect API Routes Using Passport.js

const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

passport.use(new JwtStrategy(
    {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: SECRET_KEY
    },
    (jwtPayload, done) => {
        if (jwtPayload) return done(null, jwtPayload);
        return done(null, false);
    }
));
app.use(passport.initialize());

app.get('/api/data', passport.authenticate('jwt', { session: false }), (req, res) => {
    res.json({
        id: 1,
        name: "Cyber Security Service",
        description: "Secure API with OAuth 2.0",
        user: req.user
    });
});

✅ Testing the API

Test Security Features (Q2)

Try sending invalid input to /api/submit and check validation errors.

Test CORS policy by making API requests from an unauthorized domain.

Check rate limiting by making too many requests quickly.

Test OAuth 2.0 (Q5)

Login using:

{
    "username": "admin",
    "password": "password123"
}

This returns a JWT token.

Access the protected route with the token:

curl -H "Authorization: Bearer YOUR_JWT_TOKEN" http://localhost:5000/api/data

📜 License

This project is licensed under the MIT License.

📩 Contact

For queries, feel free to reach out:

Email: your.email@example.com

GitHub: your-github-profile

🎯 Conclusion

This project demonstrates secure API development using:

Security best practices (Helmet, CORS, Rate Limiting, Input Validation)

OAuth 2.0 authentication with JWT

Protected API routes with Passport.js

Ready to deploy! 🚀