const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const dns = require('dns').promises;
const net = require('net');
const cheerio = require('cheerio');
const https = require('https');

// Initialize Express app
const app = express();

app.set('view cache', false);  // Disable EJS caching


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Function definitions
async function scanHeaders(url) {
    console.log(`Scanning headers for ${url}...`);
    try {
        const response = await axios.get(url);
        const headers = response.headers;
        const vulnerabilities = [];

        if (!headers['x-frame-options']) {
            vulnerabilities.push('Missing X-Frame-Options header (Clickjacking protection)');
        }
        if (!headers['x-content-type-options']) {
            vulnerabilities.push('Missing X-Content-Type-Options header (MIME-sniffing protection)');
        }
        if (!headers['strict-transport-security']) {
            vulnerabilities.push('Missing Strict-Transport-Security header (HSTS)');
        }
        if (!headers['content-security-policy']) {
            vulnerabilities.push('Missing Content-Security-Policy header (XSS protection)');
        }

        return vulnerabilities.length ? vulnerabilities : ['No vulnerabilities found in headers.'];
    } catch (error) {
        return [`Failed to fetch headers: ${error.message}`];
    }
}
async function scanSSL(domain) {
    console.log(`Scanning SSL configuration for ${domain}...`);
    const options = {
        host: domain,
        port: 443,
        method: 'GET',
    };

    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            const cert = res.connection.getPeerCertificate();
            if (cert) {
                resolve({
                    Issuer: cert.issuer && cert.issuer.CN ? cert.issuer.CN : 'N/A',
                    Subject: cert.subject && cert.subject.CN ? cert.subject.CN : 'N/A',
                    Expiration: cert.valid_to ? cert.valid_to : 'N/A',
                });
            } else {
                reject('SSL certificate not found');
            }
        });

        req.on('error', (error) => reject(`SSL scan failed: ${error.message}`));
        req.end();
    });
}

async function scanXSS(url) {
    console.log(`Scanning for XSS vulnerabilities on ${url}...`);
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);
        const forms = $('form');
        const vulnerabilities = [];

        forms.each((i, form) => {
            const action = $(form).attr('action');
            if (action && action.startsWith('http')) {
                vulnerabilities.push(`Potential XSS vulnerability in form with action: ${action}`);
            }
        });

        return vulnerabilities.length ? vulnerabilities : ['No XSS vulnerabilities detected.'];
    } catch (error) {
        return [`XSS scan failed: ${error.message}`];
    }
}

async function scanDirectoryTraversal(url) {
    console.log(`Checking for directory traversal vulnerability on ${url}...`);
    const payloads = ['../../../../etc/passwd', '../windows/win.ini'];
    const vulnerabilities = [];

    for (const payload of payloads) {
        try {
            const testUrl = `${url}/${payload}`;
            const response = await axios.get(testUrl);
            if (response.data.includes('root:') || response.data.includes('extensions')) {
                vulnerabilities.push(`Potential Directory Traversal vulnerability with payload: ${payload}`);
            }
        } catch (error) {
            continue;
        }
    }

    return vulnerabilities.length ? vulnerabilities : ['No Directory Traversal vulnerability detected.'];
}

async function scanSQLInjection(url) {
    console.log(`Scanning for SQL Injection vulnerabilities on ${url}...`);
    const payloads = ["'", "' OR 1=1 --", "' DROP TABLE users; --"];
    const vulnerabilities = [];

    for (const payload of payloads) {
        try {
            const testUrl = `${url}?id=${encodeURIComponent(payload)}`;
            const response = await axios.get(testUrl);
            if (response.data.includes('syntax error') || response.data.includes('mysql_fetch')) {
                vulnerabilities.push(`Potential SQL Injection vulnerability with payload: ${payload}`);
            }
        } catch (error) {
            continue;
        }
    }

    return vulnerabilities.length ? vulnerabilities : ['No SQL Injection vulnerabilities detected.'];
}

async function scanOutdatedSoftware(url) {
    console.log(`Checking for outdated software on ${url}...`);
    try {
        const response = await axios.get(url);
        const $ = cheerio.load(response.data);
        const vulnerabilities = [];

        const generator = $('meta[name="generator"]').attr('content');
        if (generator) {
            vulnerabilities.push(`Outdated software found: ${generator}`);
        }

        return vulnerabilities.length ? vulnerabilities : ['No outdated software detected.'];
    } catch (error) {
        return [`Failed to scan for outdated software: ${error.message}`];
    }
}

// Routes
app.get('/', (req, res) => {
    res.render('index');
});

app.post('/scan', async (req, res) => {
    const url = req.body.url;
    const domain = new URL(url).hostname;

    const headerVulns = await scanHeaders(url);
    const sslInfo = await scanSSL(domain);
    const xssVulns = await scanXSS(url);
    const traversalVulns = await scanDirectoryTraversal(url);
    const sqlVulns = await scanSQLInjection(url);
    const softwareVulns = await scanOutdatedSoftware(url);

    // Log the SSL Info to console
    console.log("SSL Info: ", sslInfo); // Log the sslInfo object


    const report = {
        headerVulns,
        sslInfo,
        xssVulns,
        traversalVulns,
        sqlVulns,
        softwareVulns,
    };

    res.render('report', { report, url });
});

// Start the server
app.listen(3000, () => {
    console.log("Server is running on http://localhost:3000");
});
