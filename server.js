const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 6000;

// **1. Security Headers**
app.use(helmet());

// **2. CORS Configuration**
app.use(cors({
    origin: 'https://your-secure-frontend.com', // Allow only trusted frontend
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// **3. Rate Limiting**
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per window
});
app.use(limiter);

// **4. Input Validation Example**
app.use(express.json());
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

app.get('/', (req, res) => {
    res.json({ message: "Secure web service!" });
});

app.listen(PORT, () => {
    console.log(`Secure server running on port ${PORT}`);
});
