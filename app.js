const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Configuration
const SERVER_SECRET = crypto.randomBytes(32).toString('hex'); // Generated on startup, or load from .env
const PORT = 3000;
const submissionLogsDir = path.join(__dirname, 'submission_logs');

if (!fs.existsSync(submissionLogsDir)) {
    fs.mkdirSync(submissionLogsDir, { recursive: true });
}

// Helper to generate flags
function generateFlags(studentId) {
    const userDir = path.join(__dirname, 'userdata', studentId);
    if (!fs.existsSync(userDir)) {
        fs.mkdirSync(userDir, { recursive: true });
    }

    const flagFile = path.join(userDir, 'flags.json');
    if (fs.existsSync(flagFile)) {
        return JSON.parse(fs.readFileSync(flagFile, 'utf8'));
    }

    // Use HMAC to make flags deterministic for the Student ID + Secret
    // This makes them unique per student but impossible to guess without the SERVER_SECRET
    const generateFlag = (level) => {
        const hmac = crypto.createHmac('sha256', SERVER_SECRET);
        hmac.update(`${studentId}-level${level}`);
        const hash = hmac.digest('hex').substring(0, 10).toUpperCase();
        return `ETHICALHCK{LFI_LVL${level}_${hash}}`;
    };

    const flags = {
        flag1: generateFlag(1),
        flag2: generateFlag(2),
        flag3: generateFlag(3)
    };

    fs.writeFileSync(flagFile, JSON.stringify(flags));
    fs.writeFileSync(path.join(userDir, 'flag1.txt'), flags.flag1);
    fs.writeFileSync(path.join(userDir, 'flag2.txt'), flags.flag2);
    fs.writeFileSync(path.join(userDir, 'flag3.txt'), flags.flag3);

    return flags;
}

// UI Middleware
const head = `
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1a1a1a; color: #e0e0e0; margin: 0; padding: 20px; }
    .container { max-width: 800px; margin: auto; background: #2d2d2d; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
    h1 { color: #00ffcc; border-bottom: 2px solid #444; padding-bottom: 10px; }
    h2 { color: #ffcc00; }
    .card { background: #3d3d3d; padding: 15px; margin-bottom: 20px; border-left: 5px solid #00ffcc; border-radius: 5px; }
    a { color: #00b3ff; text-decoration: none; font-weight: bold; }
    a:hover { color: #00ffcc; }
    input[type="text"] { width: 100%; padding: 10px; margin: 10px 0; border: none; border-radius: 5px; background: #444; color: white; }
    button { background: #00ffcc; color: #1a1a1a; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; }
    button:hover { background: #00ccaa; }
    pre { background: #111; padding: 15px; border-radius: 5px; overflow-x: auto; color: #00ff00; border: 1px solid #444; }
    .nav { margin-bottom: 20px; }
    .nav a { margin-right: 20px; }
    .error { color: #ff4444; font-weight: bold; }
    .success { color: #00ff00; font-weight: bold; }
</style>
`;

app.get('/', (req, res) => {
    const studentId = req.cookies.studentId;
    if (!studentId) {
        return res.send(`
            ${head}
            <div class="container">
                <h1>Cyber Security Lab: LFI Challenge</h1>
                <p>Welcome, student. Please register with your Student ID to start the lab.</p>
                <form action="/register" method="POST">
                    <input type="text" name="studentId" placeholder="Enter Student ID (e.g., S12345)" required>
                    <button type="submit">Start Lab</button>
                </form>
            </div>
        `);
    }

    res.send(`
        ${head}
        <div class="container">
            <div class="nav">
                <a href="/">Dashboard</a> | <a href="/submit">Submit Flags</a> | <a href="/logout">Logout</a>
            </div>
            <h1>Dashboard - Welcome ${studentId}</h1>
            <p>Your flags are stored in your private directory: <code>userdata/${studentId}/</code></p>
            
            <div class="card">
                <h2>Level 1: Legacy Support Portal</h2>
                <p>Accessing old project documentation via our Internal Proxy Service.</p>
                <ul>
                    <li><a href="/api/v1/debug/view-doc?path=welcome.txt">View welcome.txt (Proxy)</a></li>
                    <li><a href="/api/v1/debug/view-doc?path=about.txt">View about.txt (Proxy)</a></li>
                </ul>
                <p><small>Note: This is a direct proxy to the internal documentation server.</small></p>
            </div>

            <div class="card">
                <h2>Level 2: High-Performance Asset Optimizer</h2>
                <p>Our CDN optimizes assets on-the-fly. We've implemented a "secure" path filter to prevent access to sensitive files.</p>
                <ul>
                    <li><a href="/cdn-cgi/image/optimizer?resource=nature.jpg">Optimize nature.jpg</a></li>
                    <li><a href="/cdn-cgi/image/optimizer?resource=city.jpg">Optimize city.jpg</a></li>
                </ul>
                <p><small>Security: Path traversal protection is enabled on this endpoint.</small></p>
            </div>

            <div class="card">
                <h2>Level 3: Cross-Platform Profile Sync</h2>
                <p>Sync your avatar from multiple sources. Currently, only <code>local_storage</code> is supported for PNG files.</p>
                <ul>
                    <li><a href="/api/sync/avatar?provider=local_storage&id=default.png">Sync default.png</a></li>
                    <li><a href="/api/sync/avatar?provider=local_storage&id=user1.png">Sync user1.png</a></li>
                </ul>
                <p><small>Constraint: Only <code>.png</code> files are accepted. Our system automatically handles extensions for your convenience.</small></p>
            </div>
        </div>
    `);
});

app.post('/register', (req, res) => {
    const { studentId } = req.body;
    if (!studentId || studentId.length < 3) {
        return res.send('Invalid Student ID');
    }
    generateFlags(studentId);
    res.cookie('studentId', studentId);
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    res.clearCookie('studentId');
    res.redirect('/');
});

// VULN 1: Simple LFI - Legacy Proxy
app.get('/api/v1/debug/view-doc', (req, res) => {
    const pathParam = req.query.path;
    if (!pathParam) return res.send('No path specified');

    // Prevent leaking all flags at once
    if (pathParam.includes('flags.json') || pathParam.includes('flag2.txt') || pathParam.includes('flag3.txt')) {
        return res.status(403).send('Access denied');
    }

    let filePath;
    // Auto-route to student's flag if they traverse to it
    if (pathParam.includes('flag1.txt')) {
        const studentId = req.cookies.studentId;
        if (!studentId) return res.status(401).send('Please register first');
        filePath = path.join(__dirname, 'userdata', studentId, 'flag1.txt');
    } else {
        filePath = path.join(__dirname, 'docs', pathParam);
    }
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Resource not found in documentation server');
        res.send(`${head}<div class="container"><div class="nav"><a href="/">Back</a></div><pre>${data}</pre></div>`);
    });
});

// VULN 2: Filter Bypass - Asset Optimizer
app.get('/cdn-cgi/image/optimizer', (req, res) => {
    let resource = req.query.resource;
    if (!resource) return res.send('No resource specified');

    // Prevent leaking all flags at once
    if (resource.includes('flags.json') || resource.includes('flag1.txt') || resource.includes('flag3.txt')) {
        return res.status(403).send('Access denied');
    }

    // VULNERABLE FILTER: only replaces once, not recursive
    let filteredResource = resource.replace(/\.\.\//g, '');
    
    let filePath;
    // Auto-route to student's flag if they bypass the filter and reach flag2.txt
    if (filteredResource.includes('flag2.txt')) {
        const studentId = req.cookies.studentId;
        if (!studentId) return res.status(401).send('Please register first');
        filePath = path.join(__dirname, 'userdata', studentId, 'flag2.txt');
    } else {
        filePath = path.join(__dirname, 'assets', filteredResource);
    }
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Optimized asset not found');
        res.send(`${head}<div class="container"><div class="nav"><a href="/">Back</a></div><pre>${data}</pre></div>`);
    });
});

// VULN 3: URL-Encoded LFI - Profile Sync
app.get('/api/sync/avatar', (req, res) => {
    let id = req.query.id;
    let provider = req.query.provider;

    if (!id || provider !== 'local_storage') {
        return res.status(400).send('Invalid provider or ID');
    }

    // Strict check: Input MUST end with .png
    if (!id.toLowerCase().endsWith('.png')) {
        return res.send('Invalid image file. Only .png is accepted for security.');
    }

    // "SECURE" FILTER: Blocks literal path traversal
    if (id.includes('../')) {
        return res.status(403).send('SECURITY ALERT: Path traversal attempt detected and blocked!');
    }

    // VULNERABILITY: The app decodes the ID AFTER the filter check
    // This allows bypass via URL encoding: ..%2f..%2f
    let decodedId = decodeURIComponent(id);

    // Prevent leaking all flags at once
    if (decodedId.includes('flags.json') || decodedId.includes('flag1.txt') || decodedId.includes('flag2.txt')) {
        return res.status(403).send('Access denied');
    }

    let resourceName = decodedId.replace('.png', '');
    
    let filePath;

    // HELPER: If they are looking for flag3.txt via traversal, we route it to their private flag
    if (resourceName.includes('flag3.txt')) {
        const studentId = req.cookies.studentId;
        if (!studentId) return res.status(401).send('Please register first');
        filePath = path.join(__dirname, 'userdata', studentId, 'flag3.txt');
    } else {
        filePath = path.join(__dirname, 'avatars', resourceName);
    }
    
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Resource not found in sync bucket');
        res.send(`${head}<div class="container"><div class="nav"><a href="/">Back</a></div><pre>${data}</pre></div>`);
    });
});

// Submit Flag Feature
app.get('/submit', (req, res) => {
    const studentId = req.cookies.studentId;
    if (!studentId) return res.redirect('/');

    res.send(`
        ${head}
        <div class="container">
            <div class="nav">
                <a href="/">Dashboard</a> | <a href="/submit">Submit Flags</a> | <a href="/logout">Logout</a>
            </div>
            <h1>Flag Submission</h1>
            <form action="/submit" method="POST">
                <p>Level:</p>
                <select name="level" style="width: 100%; padding: 10px; background: #444; color: white; border: none; border-radius: 5px;">
                    <option value="1">Level 1: Documentation Viewer</option>
                    <option value="2">Level 2: Assets Gallery</option>
                    <option value="3">Level 3: Profile Avatar Fetcher</option>
                </select>
                <p>Flag:</p>
                <input type="text" name="flag" placeholder="ETHICALHCK{...}" required>
                <button type="submit">Submit Flag</button>
            </form>
            <div id="result"></div>
        </div>
    `);
});

app.post('/submit', (req, res) => {
    const studentId = req.cookies.studentId;
    if (!studentId) return res.redirect('/');

    const { level, flag } = req.body;
    const flags = generateFlags(studentId);
    
    const correctFlag = flags[`flag${level}`];
    let message = '';
    
    if (flag === correctFlag) {
        message = `<p class="success">Correct! You solved Level ${level}.</p>`;
        fs.appendFileSync(path.join(submissionLogsDir, 'solves.log'), `${new Date().toISOString()} - ${studentId} solved Level ${level}\n`);
    } else {
        message = `<p class="error">Incorrect flag for Level ${level}. Try again!</p>`;
    }

    res.send(`
        ${head}
        <div class="container">
            <div class="nav">
                <a href="/">Dashboard</a> | <a href="/submit">Submit Flags</a> | <a href="/logout">Logout</a>
            </div>
            <h1>Submission Result</h1>
            ${message}
            <a href="/submit"><button>Back to Submission</button></a>
        </div>
    `);
});

app.listen(PORT, () => {
    console.log(`LFI Lab listening at http://localhost:${PORT}`);
});
