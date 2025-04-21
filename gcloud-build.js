const fs = require('fs');
const { execSync } = require('child_process');
const dotenv = require('dotenv');

const envConfig = dotenv.parse(fs.readFileSync('.env'));

const config = JSON.parse(fs.readFileSync('./deploy.config.json', 'utf8'));

const envVars = Object.entries(envConfig)
    .map(([key, value]) => `${key}="${value.replace(/"/g, '\\"')}"`)
    .join(',');

const imageTag = `gcr.io/${config.projectId}/${config.serviceName}`;

const buildCmd = `gcloud builds submit --tag ${imageTag}`;
const deployCmd = `gcloud run deploy ${config.serviceName} --image ${imageTag} --region ${config.region} --platform managed --project ${config.projectId} --set-env-vars ${envVars}`;

try {
    console.log('🏗️  Building Docker image...');
    console.log('Running:', buildCmd);
    execSync(buildCmd, { stdio: 'inherit' });

    console.log('🚀 Deploying to Cloud Run...');
    console.log('Running:', deployCmd);
    execSync(deployCmd, { stdio: 'inherit' });

    console.log('✅ Deployment complete!');
} catch (err) {
    console.error('❌ Deployment failed:', err.message);
    process.exit(1);
}
