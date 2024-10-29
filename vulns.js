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
  // Vulnerable to SQL Injection due to direct string concatenation with user input
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  return mysql.query(query, (err, results) => {
    if (err) throw err;
    return results;
  });
}

// 2. Cross-Site Scripting (XSS) Vulnerability
app.get('/display', (req, res) => {
  const username = req.query.username;
  // Outputting user input directly into HTML without escaping
  res.send(`<h1>Welcome, ${username}</h1>`);
});

// 3. Insecure Deserialization
function deserializeUser(serializedData) {
  // Directly using user-provided data in deserialization
  const user = JSON.parse(serializedData); // Untrusted deserialization
  return user;
}

// 4. Command Injection Vulnerability
function listFiles(directory) {
  // Command injection risk due to unvalidated user input
  exec(`ls ${directory}`, (err, stdout, stderr) => {
    if (err) throw err;
    console.log(stdout);
  });
}

// 5. Hardcoded API Key (Sensitive Data Exposure)
const apiKey = '12345-ABCDE-SECRET-KEY'; // Hardcoded sensitive information
function makeApiRequest() {
  // Using hardcoded API key in request headers
  fetch('https://api.example.com/data', {
    headers: { 'Authorization': `Bearer ${apiKey}` }
  });
}

// 6. Path Traversal Vulnerability
app.get('/file', (req, res) => {
  const fileName = req.query.file;
  // Allows directory traversal via unvalidated file name input
  fs.readFile(`/var/www/${fileName}`, 'utf8', (err, data) => {
    if (err) throw err;
    res.send(data);
  });
});

// 7. Insecure Fetch API Call (External JSON Placeholder API)
function fetchUserData(userId) {
  // No error handling and directly using user input in the URL, leading to potential open redirects or data exfiltration
  fetch(`https://jsonplaceholder.typicode.com/users/${userId}`)
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
function hashPassword(password) {
  // Using MD5, which is considered a weak hashing algorithm
  return crypto.createHash('md5').update(password).digest('hex');
}

// 10. Insecure File Permissions
function createConfigFile() {
  // Setting file permissions to 777, which is insecure
  fs.writeFile('/tmp/config.txt', 'configurations', { mode: 0o777 }, (err) => {
    if (err) throw err;
    console.log('Config file created with insecure permissions.');
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
