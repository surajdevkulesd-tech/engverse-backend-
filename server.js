const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '25mb' }));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'UP',
    application: 'EngVerse IELTS Evaluation Engine',
    version: '1.0.0'
  });
});

app.post('/api/gemini', async (req, res) => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'Server configuration error: GEMINI_API_KEY missing.' });
    }

    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const apiResponse = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });

    const data = await apiResponse.json();
    return res.status(apiResponse.status).json(data);
  } catch (error) {
    console.error('Gemini Backend Error:', error);
    return res.status(500).json({ error: 'Internal server error processing evaluation.' });
  }
});

app.listen(PORT, () => {
  console.log(`EngVerse Server is running on port ${PORT}`);
});
