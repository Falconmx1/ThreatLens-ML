const tf = require('@tensorflow/tfjs-node');
const fs = require('fs');
const csv = require('csv-parser');

async function phishingClassifier(filePath) {
  // Simulación de clasificador de phishing
  const urls = await readURLsFromCSV(filePath);
  const results = urls.map(url => classifyURL(url));
  
  const phishingCount = results.filter(r => r.isPhishing).length;
  const total = results.length;
  
  return {
    totalURLs: total,
    phishingDetected: phishingCount,
    safeURLs: total - phishingCount,
    phishingPercentage: (phishingCount / total * 100).toFixed(2) + '%',
    results: results.slice(0, 5), // Mostrar primeros 5
    recommendation: phishingCount > total * 0.3 ? '⚠️ Alerta de phishing masivo' : '✅ Nivel de phishing normal'
  };
}

function readURLsFromCSV(filePath) {
  return new Promise((resolve) => {
    const urls = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (row) => {
        if (row.url) urls.push(row.url);
      })
      .on('end', () => {
        resolve(urls.length ? urls : ['http://ejemplo-phishing.com', 'https://google.com']);
      });
  });
}

function classifyURL(url) {
  // Simulación basada en características de la URL
  const features = extractURLFeatures(url);
  const score = features.reduce((sum, f) => sum + f, 0) / features.length;
  
  return {
    url,
    isPhishing: score > 0.6,
    confidence: score,
    features: {
      hasHTTPS: url.startsWith('https'),
      length: url.length,
      hasIP: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url),
      suspiciousWords: ['login', 'secure', 'verify', 'update'].some(w => url.includes(w))
    }
  };
}

function extractURLFeatures(url) {
  const features = [];
  features.push(url.startsWith('https') ? 1 : 0);
  features.push(Math.min(url.length / 100, 1));
  features.push(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url) ? 0.8 : 0);
  features.push(['login', 'secure', 'verify', 'update'].some(w => url.includes(w)) ? 0.7 : 0);
  features.push(url.includes('@') ? 0.9 : 0);
  return features;
}

module.exports = { phishingClassifier };
