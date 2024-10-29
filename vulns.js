// vulnerableFile.js

const mysql = require('mysql');
const express = require('express');
const app = express();
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const fetch = require('node-fetch');

// 1. SQL Injection Vulnerability
function getUserData(userId) {
  const query = 'SELECT * FROM users WHERE id = ?';
  return mysql.query(query, [userId], (err, results) => {
    if (err) throw err;
    return results;
  });
}


// 2. Cross-Site Scripting (XSS) Vulnerability
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.get('/display', (req, res) => {
  const username = escapeHtml(req.query.username);
  res.send(`<h1>Welcome, ${username}</h1>`);
});


// 3. Insecure Deserialization
function deserializeUser(serializedData) {
  let user;
  try {
    user = JSON.parse(serializedData);
    // Add validation logic here
  } catch (e) {
    throw new Error('Invalid serialized data');
  }
  return user;
}



// 4. Command Injection Vulnerability

const path = require('path');

function listFiles(directory) {
  const safeDirectory = path.resolve(directory);
  exec(`ls ${safeDirectory}`, (err, stdout, stderr) => {
    if (err) throw err;
    console.log(stdout);
  });
}




// 5. Hardcoded API Key (Sensitive Data Exposure)

const apiKey = process.env.API_KEY;
function makeApiRequest() {
  fetch('https://api.example.com/data', {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });
}

// 6. Path Traversal Vulnerability
const path = require('path');

app.get('/file', (req, res) => {
  const fileName = path.basename(req.query.file);
  fs.readFile(`/var/www/${fileName}`, 'utf8', (err, data) => {
    if (err) throw err;
    res.send(data);
  });
});


// 7. Insecure Fetch API Call (External JSON Placeholder API)
function fetchUserData(userId) {
  const safeUserId = encodeURIComponent(userId);
  fetch(`https://jsonplaceholder.typicode.com/users/${safeUserId}`)
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Fetch error:', error));
}

// 8. Insecure Random Number Generation
function generateToken() {
  // Using Math.random() which is not cryptographically secure
  const token = Math.random().toString(36).substring(2);
  console.log('Generated token:', token);
  return token;
}

// 9. Weak Hashing Algorithm
const bcrypt = require('bcrypt');

function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// 10. Insecure File Permissions

function createConfigFile() {
  fs.writeFile('/tmp/config.txt', 'configurations', { mode: 0o600 }, (err) => {
    if (err) throw err;
    console.log('Config file created with secure permissions.');
  });
}

// False Positive 1: URL Hardcoding (Not a vulnerability but flagged sometimes)
const defaultUrl = "https://example.com/home"; // Static URL, no sensitive data

// False Positive 2: Non-sensitive variable name (Can be mistaken as sensitive)
const fakeToken = 'not-a-real-token'; // Contains "token" in name but isn't sensitive data

// False Positive 3: Mock API Key (Looks like sensitive data but isn't real)
const mockApiKey = 'MOCK-KEY-1234-FAKE'; // Often flagged but not an actual key

// False Positive 4: Sample Configuration URL (Commonly flagged but not sensitive)
const configUrl = 'https://jsonplaceholder.typicode.com/config'; // Placeholder URL with no sensitive information

module.exports = {
  getUserData,
  deserializeUser,
  listFiles,
  makeApiRequest,
  fetchUserData,
  generateToken,
  hashPassword,
  createConfigFile
};
