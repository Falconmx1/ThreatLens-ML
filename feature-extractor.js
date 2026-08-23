/**
 * Feature Extractor - Extrae características de diferentes tipos de datos
 * Normaliza y prepara los datos para los modelos de ML
 */

const tf = require('@tensorflow/tfjs-node');
const crypto = require('crypto');

class FeatureExtractor {
  constructor() {
    this.featureCache = new Map();
    this.normalizationParams = {
      malware: { mean: 0.5, std: 0.2 },
      network: { mean: 0.3, std: 0.15 },
      phishing: { mean: 0.4, std: 0.25 },
      log: { mean: 0.2, std: 0.1 },
      threat: { mean: 0.3, std: 0.2 }
    };
  }

  /**
   * Extrae características de un archivo binario para detección de malware
   * @param {Buffer} buffer - Datos del archivo
   * @returns {object} Características extraídas
   */
  extractBinaryFeatures(buffer) {
    const bytes = new Uint8Array(buffer);
    const totalBytes = bytes.length;
    
    // Entropía (0-1)
    const freq = new Array(256).fill(0);
    bytes.forEach(b => freq[b]++);
    let entropy = 0;
    freq.forEach(f => {
      if (f > 0) {
        const p = f / totalBytes;
        entropy -= p * Math.log2(p);
      }
    });
    entropy = entropy / 8; // Normalizar a 0-1

    // Densidad de bytes nulos
    const nullBytes = freq[0] / totalBytes;

    // Patrones de secciones PE/ELF
    const peHeader = this.detectPEHeader(bytes);
    const elfHeader = this.detectELFHeader(bytes);

    // Frecuencia de caracteres imprimibles
    let printable = 0;
    for (let i = 0; i < Math.min(bytes.length, 1000); i++) {
      if (bytes[i] >= 32 && bytes[i] <= 126) printable++;
    }
    const printableRatio = printable / Math.min(bytes.length, 1000);

    // Detectar ofuscación (alta entropía + pocos imprimibles)
    const isObfuscated = entropy > 0.8 && printableRatio < 0.3;

    return {
      entropy,
      nullBytesRatio: nullBytes,
      hasPEHeader: peHeader,
      hasELFHeader: elfHeader,
      printableRatio,
      isObfuscated,
      fileSize: totalBytes,
      // Vector de características para ML
      features: [
        entropy,
        nullBytes,
        peHeader ? 1 : 0,
        elfHeader ? 1 : 0,
        printableRatio,
        isObfuscated ? 1 : 0,
        Math.min(totalBytes / 1000000, 1) // Tamaño normalizado
      ]
    };
  }

  /**
   * Extrae características de tráfico de red
   * @param {Array} packets - Array de paquetes
   * @returns {object} Características extraídas
   */
  extractNetworkFeatures(packets) {
    if (!packets || packets.length === 0) {
      return { features: Array(10).fill(0) };
    }

    const totalPackets = packets.length;
    const sizes = packets.map(p => p.size || p.bytes || 0);
    const times = packets.map(p => p.time || 0);
    
    // Estadísticas básicas
    const avgSize = sizes.reduce((a, b) => a + b, 0) / totalPackets;
    const maxSize = Math.max(...sizes);
    const minSize = Math.min(...sizes);
    const stdSize = this.standardDeviation(sizes);

    // Ratio de protocolos (simulado)
    const tcpCount = packets.filter(p => p.protocol === 'TCP' || p.tcp).length;
    const udpCount = packets.filter(p => p.protocol === 'UDP' || p.udp).length;

    // Detectar patrones anómalos
    const sizeAnomaly = avgSize > 1000 || stdSize > 500;
    const protocolRatio = tcpCount / totalPackets;

    return {
      avgSize,
      maxSize,
      minSize,
      stdSize,
      tcpRatio: tcpCount / totalPackets,
      udpRatio: udpCount / totalPackets,
      sizeAnomaly,
      packetCount: totalPackets,
      // Vector de características para ML
      features: [
        Math.min(avgSize / 1500, 1),
        Math.min(maxSize / 1500, 1),
        Math.min(stdSize / 500, 1),
        tcpCount / totalPackets,
        udpCount / totalPackets,
        sizeAnomaly ? 1 : 0,
        Math.min(totalPackets / 1000, 1),
        Math.random() * 0.5, // Ruido para simulación
        Math.random() * 0.5,
        Math.random() * 0.5
      ]
    };
  }

  /**
   * Extrae características de una URL para detección de phishing
   * @param {string} url - URL a analizar
   * @returns {object} Características extraídas
   */
  extractURLFeatures(url) {
    if (!url) {
      return { features: Array(8).fill(0) };
    }

    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname;
      const path = parsed.pathname;
      const query = parsed.search;

      // Características
      const hasHTTPS = parsed.protocol === 'https:';
      const urlLength = url.length;
      const hostLength = hostname.length;
      const numDots = (hostname.match(/\./g) || []).length;
      const numHyphens = (hostname.match(/-/g) || []).length;
      const hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname);
      const suspiciousWords = ['login', 'secure', 'verify', 'update', 'bank', 'account'];
      const hasSuspicious = suspiciousWords.some(w => url.toLowerCase().includes(w));
      const specialChars = (url.match(/[^a-zA-Z0-9.:/-]/g) || []).length;

      // Longitud del dominio relativa
      const domainLengthRatio = hostLength / urlLength;

      return {
        hasHTTPS,
        urlLength,
        hostLength,
        numDots,
        numHyphens,
        hasIP,
        hasSuspicious,
        specialChars,
        domainLengthRatio,
        // Vector de características para ML
        features: [
          hasHTTPS ? 1 : 0,
          Math.min(urlLength / 100, 1),
          Math.min(hostLength / 50, 1),
          Math.min(numDots / 5, 1),
          Math.min(numHyphens / 5, 1),
          hasIP ? 1 : 0,
          hasSuspicious ? 1 : 0,
          Math.min(specialChars / 10, 1)
        ]
      };
    } catch (e) {
      // URL inválida
      return { features: Array(8).fill(0), error: 'URL inválida' };
    }
  }

  /**
   * Extrae características de una línea de log
   * @param {string} logLine - Línea de log
   * @returns {object} Características extraídas
   */
  extractLogFeatures(logLine) {
    if (!logLine) {
      return { features: Array(6).fill(0) };
    }

    const line = logLine.toLowerCase();
    
    // Patrones de seguridad
    const errorPatterns = ['error', 'fail', 'critical', 'fatal'];
    const warningPatterns = ['warn', 'warning', 'attention'];
    const accessPatterns = ['unauthorized', 'forbidden', 'denied', 'rejected'];
    const networkPatterns = ['timeout', 'connection', 'refused', 'reset'];
    
    const hasError = errorPatterns.some(p => line.includes(p));
    const hasWarning = warningPatterns.some(p => line.includes(p));
    const hasAccess = accessPatterns.some(p => line.includes(p));
    const hasNetwork = networkPatterns.some(p => line.includes(p));

    // Nivel de severidad (0-1)
    let severity = 0;
    if (hasError) severity += 0.4;
    if (hasAccess) severity += 0.3;
    if (hasNetwork) severity += 0.2;
    if (hasWarning) severity += 0.1;
    severity = Math.min(severity, 1);

    // Detectar números (IPs, puertos, etc.)
    const numbers = line.match(/\d+/g) || [];
    const numCount = Math.min(numbers.length / 10, 1);

    // Longitud de la línea
    const length = Math.min(line.length / 500, 1);

    // Timestamp (simulado)
    const hasTimestamp = /\d{4}[-/]\d{2}[-/]\d{2}/.test(line) || 
                         /\d{2}:\d{2}:\d{2}/.test(line);

    return {
      hasError,
      hasWarning,
      hasAccess,
      hasNetwork,
      severity,
      numCount,
      length,
      hasTimestamp,
      // Vector de características para ML
      features: [
        hasError ? 1 : 0,
        hasWarning ? 1 : 0,
        hasAccess ? 1 : 0,
        hasNetwork ? 1 : 0,
        severity,
        numCount
      ]
    };
  }

  /**
   * Extrae características de un IoC para puntuación de riesgo
   * @param {string} ioc - Indicador de compromiso
   * @returns {object} Características extraídas
   */
  extractIOCFeatures(ioc) {
    if (!ioc) {
      return { features: Array(7).fill(0) };
    }

    const iocStr = ioc.trim();
    
    // Detectar tipo de IoC
    const isIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(iocStr);
    const isDomain = /^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$/.test(iocStr);
    const isHash = /^[a-fA-F0-9]{32,64}$/.test(iocStr);
    const isURL = /^https?:\/\//.test(iocStr);

    // Palabras de riesgo
    const riskWords = ['malware', 'trojan', 'ransom', 'exploit', 'phish', 
                       'c2', 'botnet', 'dropper', 'payload'];
    const hasRiskWord = riskWords.some(w => iocStr.toLowerCase().includes(w));

    // Longitud
    const length = Math.min(iocStr.length / 100, 1);

    // Cantidad de caracteres especiales
    const specialChars = (iocStr.match(/[^a-zA-Z0-9.]/g) || []).length;
    const specialRatio = Math.min(specialChars / 10, 1);

    // Reputación (simulado con hash)
    const hash = crypto.createHash('md5').update(iocStr).digest('hex');
    const reputation = parseInt(hash.substring(0, 4), 16) / 65535; // 0-1

    return {
      type: isIP ? 'IP' : isDomain ? 'Domain' : isHash ? 'Hash' : isURL ? 'URL' : 'Unknown',
      isIP,
      isDomain,
      isHash,
      isURL,
      hasRiskWord,
      length,
      specialRatio,
      reputation,
      // Vector de características para ML
      features: [
        isIP ? 1 : 0,
        isDomain ? 1 : 0,
        isHash ? 1 : 0,
        isURL ? 1 : 0,
        hasRiskWord ? 1 : 0,
        length,
        specialRatio,
        reputation
      ]
    };
  }

  /**
   * Normaliza características usando z-score
   * @param {Array} features - Vector de características
   * @param {string} type - Tipo de características
   * @returns {Float32Array} Características normalizadas
   */
  normalizeFeatures(features, type = 'generic') {
    const params = this.normalizationParams[type] || { mean: 0.5, std: 0.2 };
    
    return new Float32Array(
      features.map(f => (f - params.mean) / (params.std + 0.001))
    );
  }

  /**
   * Convierte características a tensor para TensorFlow
   * @param {Array} features - Vector de características
   * @param {string} type - Tipo de características
   * @returns {tf.Tensor} Tensor listo para el modelo
   */
  featuresToTensor(features, type = 'generic') {
    const normalized = this.normalizeFeatures(features, type);
    return tf.tensor2d([Array.from(normalized)]);
  }

  /**
   * Helper: detecta cabecera PE en binarios
   */
  detectPEHeader(bytes) {
    // MZ al inicio y PE en el offset 0x3C
    if (bytes.length < 64) return false;
    return bytes[0] === 0x4D && bytes[1] === 0x5A;
  }

  /**
   * Helper: detecta cabecera ELF en binarios
   */
  detectELFHeader(bytes) {
    if (bytes.length < 16) return false;
    return bytes[0] === 0x7F && bytes[1] === 0x45 && 
           bytes[2] === 0x4C && bytes[3] === 0x46;
  }

  /**
   * Helper: calcula desviación estándar
   */
  standardDeviation(values) {
    if (values.length === 0) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
    return Math.sqrt(squaredDiffs.reduce((a, b) => a + b, 0) / values.length);
  }

  /**
   * Limpia la caché de características
   */
  clearCache() {
    this.featureCache.clear();
    console.log('🧹 Caché de características limpiada');
  }
}

// Exportar instancia única (singleton)
module.exports = new FeatureExtractor();
