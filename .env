// server.ts

import * as dotenv from 'dotenv';
// Use dotenv to load environment variables from .env file
dotenv.config();

import app from './src/app';

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`API documentation at http://localhost:${PORT}/docs`);
});

// Graceful Shutdown (Best Practice)
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: Closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed.');
  });
});
