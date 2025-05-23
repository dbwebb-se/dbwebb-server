import crypto from 'crypto';
import express from 'express';
import bodyParser from 'body-parser';
import { exec } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import ipRangeCheck from 'ip-range-check';

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

app.use(express.static(path.join(__dirname, '../website/dist')));

app.use('/webhook', (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  if (!ipRangeCheck(ip, githubCIDRs)) {
    return res.status(403).send('Forbidden: Invalid IP');
  }
  next();
});

// Parse and keep raw body for GitHub signature verification
app.use(bodyParser.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

function verifySignature(req) {
  const signature = req.headers['x-hub-signature-256'];
  if (!signature || typeof signature !== 'string') return false;

  const hmac = crypto.createHmac('sha256', SECRET);
  const digest = 'sha256=' + hmac.update(req.rawBody).digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(signature));
  } catch {
    return false;
  }
}


app.post('/webhook', (req, res) => {
  if (!verifySignature(req)) {
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
  res.send('Webhook server running.');
});

app.listen(PORT, () => {
  console.log(`dbwebb server listening on port ${PORT}`);
});
