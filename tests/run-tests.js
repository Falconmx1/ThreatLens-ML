#!/usr/bin/env node
/**
 * Test Suite para ThreatLens ML
 * Ejecuta pruebas en todos los módulos
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  dim: '\x1b[2m'
};

const tests = [
  {
    name: 'Malware Detector',
    module: 'malware',
    file: path.join(__dirname, 'fixtures', 'sample.bin'),
    skip: false
  },
  {
    name: 'Network Anomaly',
    module: 'network',
    file: path.join(__dirname, 'fixtures', 'traffic.csv'),
    skip: false
  },
  {
    name: 'Phishing Classifier',
    module: 'phishing',
    file: path.join(__dirname, 'fixtures', 'urls.csv'),
    skip: false
  },
  {
    name: 'Log Analyzer',
    module: 'log',
    file: path.join(__dirname, 'fixtures', 'access.log'),
    skip: false
  },
  {
    name: 'Threat Scorer',
    module: 'threat',
    file: path.join(__dirname, 'fixtures', 'iocs.txt'),
    skip: false
  }
];

// Crear fixtures si no existen
function createFixtures() {
  const fixturesDir = path.join(__dirname, 'fixtures');
  if (!fs.existsSync(fixturesDir)) {
    fs.mkdirSync(fixturesDir, { recursive: true });
  }

  // sample.bin (binario simulado)
  if (!fs.existsSync(path.join(fixturesDir, 'sample.bin'))) {
    const buffer = Buffer.from('MZ' + 'x'.repeat(1000) + 'PE', 'ascii');
    fs.writeFileSync(path.join(fixturesDir, 'sample.bin'), buffer);
  }

  // urls.csv
  if (!fs.existsSync(path.join(fixturesDir, 'urls.csv'))) {
    const urls = [
      'url,label',
      'https://google.com,legitimo',
      'http://login-secure-verify.xyz,phishing',
      'https://facebook.com,legitimo',
      'http://192.168.1.1/login,phishing'
    ];
    fs.writeFileSync(path.join(fixturesDir, 'urls.csv'), urls.join('\n'));
  }

  // access.log
  if (!fs.existsSync(path.join(fixturesDir, 'access.log'))) {
    const logs = [
      '2026-08-23 10:00:00 INFO Usuario login exitoso',
      '2026-08-23 10:01:23 ERROR Conexión fallida a BD',
      '2026-08-23 10:05:45 WARNING Intento de acceso no autorizado',
      '2026-08-23 10:10:12 CRITICAL Servidor sobrecargado',
      '2026-08-23 10:15:30 INFO Operación completada'
    ];
    fs.writeFileSync(path.join(fixturesDir, 'access.log'), logs.join('\n'));
  }

  // iocs.txt
  if (!fs.existsSync(path.join(fixturesDir, 'iocs.txt'))) {
    const iocs = [
      '192.168.1.100',
      'malware-domain.xyz',
      'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
      'https://phishing-site.com/login',
      'google.com'
    ];
    fs.writeFileSync(path.join(fixturesDir, 'iocs.txt'), iocs.join('\n'));
  }

  // traffic.csv
  if (!fs.existsSync(path.join(fixturesDir, 'traffic.csv'))) {
    const traffic = [
      'srcIP,dstIP,packets,bytes,protocol',
      '192.168.1.1,10.0.0.1,100,10000,TCP',
      '192.168.1.2,10.0.0.2,50,5000,UDP',
      '192.168.1.3,10.0.0.3,1000,1000000,TCP',
      '192.168.1.4,10.0.0.4,200,20000,UDP'
    ];
    fs.writeFileSync(path.join(fixturesDir, 'traffic.csv'), traffic.join('\n'));
  }
}

// Ejecutar un test
async function runTest(test) {
  console.log(`\n${colors.blue}▶️ Ejecutando: ${test.name}${colors.reset}`);
  console.log(`${colors.dim}   Módulo: ${test.module} | Archivo: ${path.basename(test.file)}${colors.reset}`);

  try {
    const cmd = `node src/cli.js run ${test.module} --file=${test.file}`;
    const output = execSync(cmd, { 
      cwd: path.join(__dirname, '..'),
      encoding: 'utf8',
      stdio: 'pipe'
    });

    // Verificar que no haya errores en la salida
    if (output.includes('❌ Error')) {
      throw new Error('El módulo reportó un error');
    }

    console.log(`${colors.green}✅ Test pasado${colors.reset}`);
    return { passed: true, output };
  } catch (error) {
    console.log(`${colors.red}❌ Test fallido: ${error.message}${colors.reset}`);
    return { passed: false, error: error.message };
  }
}

// Función principal
async function main() {
  console.log(`
${colors.blue}${'═'.repeat(60)}
  🧪 ThreatLens ML - Suite de Tests
${'═'.repeat(60)}${colors.reset}
`);

  // Crear fixtures
  createFixtures();
  console.log(`${colors.dim}📁 Fixtures creados/verificados${colors.reset}`);

  // Ejecutar tests
  const results = [];
  for (const test of tests) {
    if (test.skip) {
      console.log(`\n⏭️  Saltando: ${test.name} (pendiente)`);
      continue;
    }
    const result = await runTest(test);
    results.push({ ...test, ...result });
  }

  // Resumen
  console.log(`\n${colors.blue}${'═'.repeat(60)}${colors.reset}`);
  console.log(`\n${colors.bright}📊 RESUMEN DE TESTS:${colors.reset}\n`);

  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  results.forEach(r => {
    const icon = r.passed ? `${colors.green}✅` : `${colors.red}❌`;
    console.log(`  ${icon} ${r.name} (${r.module})`);
  });

  console.log(`\n${colors.dim}${'─'.repeat(60)}${colors.reset}`);
  console.log(`  ${colors.green}✅ Exitosos: ${passed}${colors.reset}`);
  console.log(`  ${colors.red}❌ Fallidos: ${failed}${colors.reset}`);
  console.log(`  📦 Total: ${results.length}`);

  if (failed === 0) {
    console.log(`\n${colors.green}${colors.bright}🎉 ¡Todos los tests pasaron!${colors.reset}\n`);
  } else {
    console.log(`\n${colors.red}${colors.bright}⚠️ Algunos tests fallaron. Revisa los detalles.${colors.reset}\n`);
    process.exit(1);
  }
}

// Ejecutar
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { runTest, createFixtures };
