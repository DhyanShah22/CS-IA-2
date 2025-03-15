const express = require('express');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

app.get('/', (req, res) => {
    res.json({ message: "Welcome to the web service!" });
});

app.get('/api/data', (req, res) => {
    const sampleData = {
        id: 1,
        name: "Cyber Security Service",
        description: "A sample web service for learning."
    };
    res.json(sampleData);
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
