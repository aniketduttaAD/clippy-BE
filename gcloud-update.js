const fs = require('fs');
const { execSync } = require('child_process');
require('dotenv').config();

const config = JSON.parse(fs.readFileSync('./deploy.config.json', 'utf8'));

const envVars = Object.entries(process.env)
    .map(([key, value]) => `${key}=${value}`)
    .join(',');

const command = `gcloud run deploy ${config.serviceName} --source . --region ${config.region} --platform managed --project ${config.projectId} --set-env-vars ${envVars}`;

console.log('Running:', command);
execSync(command, { stdio: 'inherit' });
