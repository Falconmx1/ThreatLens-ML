#!/usr/bin/env node
/**
 * ThreatLens ML - CLI Principal
 * Uso: node src/cli.js [comando] [opciones]
 */

const fs = require('fs');
const path = require('path');
const { malwareDetector } = require('./modules/malware-detector');
const { networkAnomaly } = require('./modules/network-anomaly');
const { phishingClassifier } = require('./modules/phishing-classifier');
const { logAnalyzer } = require('./modules/log-analyzer');
const { threatScorer } = require('./modules/threat-scorer');
const modelLoader = require('./core/model-loader');

// Colores para la consola
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

const args = process.argv.slice(2);
const command = args[0] || 'help';

// Módulos disponibles
const modules = {
  malware: { 
    fn: malwareDetector, 
    desc: 'Detecta patrones maliciosos en binarios',
    args: ['--file <ruta>']
  },
  network: { 
    fn: networkAnomaly, 
    desc: 'Detecta anomalías en tráfico de red',
    args: ['--file <ruta>']
  },
  phishing: { 
    fn: phishingClassifier, 
    desc: 'Clasifica URLs como phishing o legítimas',
    args: ['--file <ruta.csv>']
  },
  log: { 
    fn: logAnalyzer, 
    desc: 'Analiza logs y detecta comportamientos anómalos',
    args: ['--file <ruta.log>']
  },
  threat: { 
    fn: threatScorer, 
    desc: 'Calcula puntuación de riesgo de IoCs',
    args: ['--file <ruta.txt>']
  }
};

// Parsear argumentos
function parseArgs() {
  const options = {};
  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const [key, value] = args[i].substring(2).split('=');
      options[key] = value || args[++i];
    }
  }
  return options;
}

// Mostrar banner
function showBanner() {
  console.log(`
${colors.cyan}${colors.bright}╔═══════════════════════════════════════════════════╗
║                                                   ║
║   ${colors.magenta}👑 ThreatLens ML v1.0.0${colors.cyan}                     ║
║   ${colors.white}Detección de amenazas con Machine Learning${colors.cyan}    ║
║                                                   ║
╚═══════════════════════════════════════════════════╝${colors.reset}
`);
}

// Mostrar ayuda
function showHelp() {
  showBanner();
  console.log(`
${colors.bright}📖 COMANDOS DISPONIBLES:${colors.reset}

  ${colors.green}run${colors.reset}      Ejecuta un módulo de análisis
  ${colors.green}list${colors.reset}     Lista todos los módulos disponibles
  ${colors.green}train${colors.reset}    Entrena un modelo (experimental)
  ${colors.green}info${colors.reset}     Muestra información del sistema
  ${colors.green}help${colors.reset}     Muestra esta ayuda

${colors.bright}📦 MÓDULOS:${colors.reset}

`);
  Object.entries(modules).forEach(([name, mod]) => {
    console.log(`  ${colors.yellow}${name.padEnd(12)}${colors.reset} ${mod.desc}`);
    console.log(`  ${colors.dim}    Uso: node src/cli.js run ${name} --file=<ruta>${colors.reset}\n`);
  });

  console.log(`
${colors.bright}💡 EJEMPLOS:${colors.reset}
  node src/cli.js run malware --file=./muestra.bin
  node src/cli.js run phishing --file=./urls.csv
  node src/cli.js run log --file=./acceso.log
  node src/cli.js list
  node src/cli.js info
`);
}

// Ejecutar un módulo
async function runModule(moduleName, options) {
  if (!modules[moduleName]) {
    console.error(`❌ Módulo '${moduleName}' no encontrado. Usa 'list' para ver disponibles.`);
    process.exit(1);
  }

  if (!options.file) {
    console.error(`❌ Se requiere --file para el módulo '${moduleName}'`);
    process.exit(1);
  }

  if (!fs.existsSync(options.file)) {
    console.error(`❌ Archivo no encontrado: ${options.file}`);
    process.exit(1);
  }

  console.log(`\n${colors.blue}🔍 Analizando con ${moduleName}...${colors.reset}`);
  console.log(`${colors.dim}📁 Archivo: ${options.file}${colors.reset}\n`);

  const startTime = Date.now();
  try {
    const result = await modules[moduleName].fn(options.file);
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log(`\n${colors.green}✅ Análisis completado en ${elapsed}s${colors.reset}`);
    console.log(`\n${colors.bright}📊 RESULTADOS:${colors.reset}`);
    console.log(JSON.stringify(result, null, 2));
    
    return result;
  } catch (error) {
    console.error(`\n${colors.red}❌ Error: ${error.message}${colors.reset}`);
    throw error;
  }
}

// Listar módulos
function listModules() {
  showBanner();
  console.log(`\n${colors.bright}📦 MÓDULOS DISPONIBLES:${colors.reset}\n`);
  console.log(`${colors.dim}${'ID'.padEnd(14)} ${'DESCRIPCIÓN'.padEnd(45)} ${'ESTADO'}${colors.reset}`);
  console.log(`${colors.dim}${'-'.repeat(70)}${colors.reset}`);
  
  Object.entries(modules).forEach(([name, mod]) => {
    const status = mod.fn ? '✅ Activo' : '⏳ En desarrollo';
    console.log(`  ${colors.yellow}${name.padEnd(12)}${colors.reset} ${mod.desc.padEnd(45)} ${status}`);
  });
  console.log('');
}

// Info del sistema
function showInfo() {
  showBanner();
  console.log(`\n${colors.bright}📊 INFORMACIÓN DEL SISTEMA:${colors.reset}\n`);
  console.log(`  ${colors.cyan}🔹 Versión:${colors.reset} 1.0.0`);
  console.log(`  ${colors.cyan}🔹 Node.js:${colors.reset} ${process.version}`);
  console.log(`  ${colors.cyan}🔹 Plataforma:${colors.reset} ${process.platform} (${process.arch})`);
  console.log(`  ${colors.cyan}🔹 Memoria:${colors.reset} ${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)} MB`);
  console.log(`  ${colors.cyan}🔹 Módulos:${colors.reset} ${Object.keys(modules).length}`);
  console.log(`  ${colors.cyan}🔹 TensorFlow:${colors.reset} ${require('@tensorflow/tfjs-node').version}`);
  console.log('');
}

// Comando principal
async function main() {
  switch (command) {
    case 'run':
      const runOptions = parseArgs();
      const moduleName = args[1];
      if (!moduleName) {
        console.error('❌ Especifica un módulo: node src/cli.js run <modulo> --file=<ruta>');
        process.exit(1);
      }
      await runModule(moduleName, runOptions);
      break;

    case 'list':
      listModules();
      break;

    case 'info':
      showInfo();
      break;

    case 'train':
      console.log('🧠 Entrenamiento de modelos (próximamente...)');
      // TODO: Implementar entrenamiento
      break;

    case 'help':
    default:
      showHelp();
      break;
  }

  // Liberar recursos de TensorFlow
  if (command === 'run') {
    modelLoader.dispose();
  }
}

// Capturar errores no manejados
process.on('uncaughtException', (error) => {
  console.error(`\n${colors.red}💥 Error crítico: ${error.message}${colors.reset}`);
  process.exit(1);
});

// Ejecutar
if (require.main === module) {
  main().catch(console.error);
}

module.exports = { runModule, listModules, showHelp };
