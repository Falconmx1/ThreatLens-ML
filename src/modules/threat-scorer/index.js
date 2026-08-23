const tf = require('@tensorflow/tfjs-node');
const fs = require('fs');

async function threatScorer(filePath) {
  // Simulación de cálculo de puntuación de riesgo para IoCs
  const iocs = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
  const scored = iocs.map(ioc => scoreIOC(ioc));
  
  const highRisk = scored.filter(s => s.riskScore > 0.7);
  const critical = scored.filter(s => s.riskScore > 0.9);
  
  return {
    totalIOCs: scored.length,
    highRiskCount: highRisk.length,
    criticalCount: critical.length,
    averageRisk: (scored.reduce((sum, s) => sum + s.riskScore, 0) / scored.length * 100).toFixed(2) + '%',
    topThreats: highRisk.slice(0, 5),
    recommendation: critical.length > 0 ? '🚨 Aislamiento inmediato' :
                    highRisk.length > 0 ? '⚠️ Priorizar investigación' : '✅ Riesgo controlado'
  };
}

function scoreIOC(ioc) {
  // Simulación de puntuación basada en características del IoC
  const features = extractIOCFeatures(ioc);
  const riskScore = features.reduce((sum, f) => sum + f, 0) / features.length;
  
  return {
    ioc: ioc.substring(0, 50) + (ioc.length > 50 ? '...' : ''),
    riskScore: riskScore,
    riskLevel: riskScore > 0.8 ? 'Crítico' :
               riskScore > 0.6 ? 'Alto' :
               riskScore > 0.4 ? 'Medio' : 'Bajo',
    features: {
      isIP: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(ioc),
      isDomain: /[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/.test(ioc),
      isHash: /[a-fA-F0-9]{32,64}/.test(ioc),
      length: ioc.length
    }
  };
}

function extractIOCFeatures(ioc) {
  const features = [];
  features.push(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(ioc) ? 0.8 : 0);
  features.push(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/.test(ioc) ? 0.6 : 0);
  features.push(/[a-fA-F0-9]{32,64}/.test(ioc) ? 0.7 : 0);
  features.push(Math.min(ioc.length / 100, 1));
  features.push(/malware|trojan|ransom|exploit|phish/i.test(ioc) ? 0.9 : 0);
  return features;
}

module.exports = { threatScorer };
