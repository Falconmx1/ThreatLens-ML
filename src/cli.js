#!/usr/bin/env node
const { malwareDetector } = require('./modules/malware-detector');
const { networkAnomaly } = require('./modules/network-anomaly');
const { phishingClassifier } = require('./modules/phishing-classifier');
const { logAnalyzer } = require('./modules/log-analyzer');
const { threatScorer } = require('./modules/threat-scorer');

const args = process.argv.slice(2);
const moduleName = args.find(a => a.startsWith('--module'))?.split('=')[1];
const filePath = args.find(a => a.startsWith('--file'))?.split('=')[1];

const modules = {
  'malware': malwareDetector,
  'network': networkAnomaly,
  'phishing': phishingClassifier,
  'log': logAnalyzer,
  'threat': threatScorer
};

if (!moduleName || !modules[moduleName]) {
  console.log(`
👑 ThreatLens ML - Uso:
  node src/cli.js --module=<malware|network|phishing|log|threat> --file=<ruta>

Ejemplos:
  node src/cli.js --module=malware --file=muestra.bin
  node src/cli.js --module=phishing --file=urls.csv
  `);
  process.exit(1);
}

modules[moduleName](filePath).then(result => {
  console.log('✅ Resultado:', result);
}).catch(err => {
  console.error('❌ Error:', err.message);
});
