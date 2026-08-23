const tf = require('@tensorflow/tfjs-node');
const fs = require('fs');

async function logAnalyzer(filePath) {
  // Simulación de análisis de logs
  const logs = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
  const analyzed = logs.map(line => analyzeLogLine(line));
  
  const anomalies = analyzed.filter(a => a.isAnomaly);
  const severity = calculateSeverity(anomalies);
  
  return {
    totalLines: logs.length,
    anomaliesDetected: anomalies.length,
    severityLevel: severity,
    topAnomalies: anomalies.slice(0, 5),
    recommendation: severity === 'alta' ? '🚨 Responder inmediatamente' :
                    severity === 'media' ? '⚠️ Investigar' : '✅ Monitoreo normal'
  };
}

function analyzeLogLine(line) {
  const patterns = [
    { regex: /error|fail|critical/i, weight: 0.9 },
    { regex: /warning|warn/i, weight: 0.6 },
    { regex: /unauthorized|forbidden|denied/i, weight: 0.8 },
    { regex: /timeout|connection refused/i, weight: 0.7 }
  ];
  
  let score = 0;
  patterns.forEach(p => {
    if (p.regex.test(line)) score += p.weight;
  });
  
  const isAnomaly = score > 1.2;
  return {
    line: line.substring(0, 100) + (line.length > 100 ? '...' : ''),
    isAnomaly,
    score: Math.min(score / 2, 1),
    timestamp: new Date().toISOString()
  };
}

function calculateSeverity(anomalies) {
  const count = anomalies.length;
  if (count > 20) return 'alta';
  if (count > 5) return 'media';
  return 'baja';
}

module.exports = { logAnalyzer };
