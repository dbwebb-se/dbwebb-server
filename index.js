import crypto from 'crypto';
import express from 'express';
// import bodyParser from 'body-parser';
import fs from 'fs';
import { exec } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import ipRangeCheck from 'ip-range-check';
import getRawBody from 'raw-body';

const app = express();
const PORT = 1337;
const SECRET = process.env.GITHUB_WEBHOOK_SECRET;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const githubCIDRs = [
  '192.30.252.0/22',
  '185.199.108.0/22',
  '140.82.112.0/20',
  '143.55.64.0/20'
];

app.set('trust proxy', true);

app.use(express.static(path.join(__dirname, '../website/dist')));

// app.use('/webhook', (req, res, next) => {
//   const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
//   console.log('Incoming IP:', ip);
//   if (!ipRangeCheck(ip, githubCIDRs)) {
//     console.log('IP not allowed');
//     return res.status(403).send('Forbidden: Invalid IP');
//   }
//   next();
// });


app.post('/webhook', async (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!ipRangeCheck(ip, githubCIDRs)) {
    return res.status(403).send('Forbidden: Invalid IP');
  }

  let rawBody;
  try {
    rawBody = await getRawBody(req);
  } catch (err) {
    return res.status(400).send('Failed to read request body');
  }

  const signature = req.headers['x-hub-signature-256'];
  const hmac = crypto.createHmac('sha256', SECRET);
  const digest = 'sha256=' + hmac.update(rawBody).digest('hex');

  const isValid = signature && crypto.timingSafeEqual(
    Buffer.from(digest),
    Buffer.from(signature)
  );

  if (!isValid) {
    console.warn('Invalid signature');
    return res.status(401).send('Unauthorized');
  }

  console.log('Verified webhook from GitHub');

  exec(`
    cd /var/www/dbwebb.bth.se/website &&
    git pull origin main &&
    npm install &&
    npm run build
  `, (err, stdout, stderr) => {
    if (err) {
      console.error(`Build error: ${stderr}`);
      return res.status(500).send('Build failed');
    }
    console.log(`Build output: ${stdout}`);
    res.status(200).send('Build successful');
  });
});

// Optional root route
app.get('/', (req, res) => {
  res.send('Dbwebb server running.');
});

app.get('/api/kmom05/:country', (req, res) => {
  // if (!["sweden", "norway", "denmark"].includes(req.params.country)) {
  //   return res.status(404).json({ error: 'File not found' });
  // }

  const filePath = path.join(__dirname, `./data/kmom05/${req.params.country}.json`);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
    if (err.code === 'ENOENT') {
      // File not found
      return res.status(404).json({ error: 'File not found' });
    }

    // Some other error
    return res.status(500).json({ error: 'Server error' });
  }

  res.json(JSON.parse(data));
  });
});

app.listen(PORT, () => {
  console.log(`dbwebb server listening on port ${PORT}`);
});
