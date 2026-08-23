# 👑 ThreatLens ML

> **Herramienta ligera de detección de amenazas basada en Machine Learning**  
> *Sin Docker, 100% open source, listo para producción*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow.js-4.15+-orange)](https://www.tensorflow.org/js)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

---

## 📋 Tabla de Contenidos
- [Descripción General](#-descripción-general)
- [Módulos Incluidos](#-módulos-incluidos)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso Rápido](#-uso-rápido)
- [Comandos del CLI](#-comandos-del-cli)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Entrenamiento de Modelos](#-entrenamiento-de-modelos)
- [Tests](#-tests)
- [Contribución](#-contribución)
- [Licencia](#-licencia)

---

## 🎯 Descripción General

**ThreatLens ML** es una suite de herramientas de ciberseguridad que utiliza Machine Learning para detectar amenazas en tiempo real. Diseñada para ser **ligera**, **modular** y **fácil de usar**, sin necesidad de contenedores Docker ni infraestructura compleja.

### Características Principales
- 🚀 **Ligero**: Sin Docker, solo Node.js y TensorFlow.js
- 🔍 **5 Módulos ML**: Cobertura completa de amenazas
- 📊 **Resultados claros**: JSON estructurado y colores en consola
- 🧠 **Simulación inteligente**: Funciona incluso sin modelos pre-entrenados
- 🔄 **Extensible**: Fácil agregar nuevos módulos
- 📦 **Zero-config**: Listo para usar después de `npm install`

---

## 📦 Módulos Incluidos

| ID | Módulo | Descripción | Estado |
|----|--------|-------------|--------|
| 81 | **Malware Pattern Detector** | Detecta patrones maliciosos en binarios usando ML | ✅ Activo |
| 82 | **Network Anomaly Detector** | Detecta anomalías en tráfico de red con aprendizaje no supervisado | ✅ Activo |
| 83 | **Phishing URL Classifier** | Clasifica URLs como phishing o legítimas | ✅ Activo |
| 84 | **Log Anomaly Analyzer** | Analiza logs y detecta comportamientos anómalos | ✅ Activo |
| 85 | **Threat Score Calculator** | Calcula puntuación de riesgo de IoCs usando ML | ✅ Activo |

---

## 🔧 Requisitos

- **Node.js**: v18.0.0 o superior
- **npm**: v9.0.0 o superior
- **Memoria RAM**: 512 MB mínimo (recomendado 1 GB)
- **Almacenamiento**: 100 MB para el proyecto + modelos

---

## 📥 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/Falconmx1/ThreatLens-ML.git
cd ThreatLens-ML

# Instalar dependencias
npm install

# Verificar instalación
node src/cli.js info

Dependencias Principales

{
  "@tensorflow/tfjs-node": "^4.15.0",  // Motor de ML
  "csv-parser": "^3.0.0",              // Parseo de CSV
  "node-fetch": "^2.7.0"               // Peticiones HTTP
}

Ejecutar un análisis

# Detectar malware en un binario
node src/cli.js run malware --file=./muestra.bin

# Clasificar URLs sospechosas
node src/cli.js run phishing --file=./urls.csv

# Analizar logs del sistema
node src/cli.js run log --file=./access.log

# Calcular riesgo de IoCs
node src/cli.js run threat --file=./iocs.txt

# Detectar anomalías en tráfico de red
node src/cli.js run network --file=./traffic.csv
Salida de ejemplo

{
  "isMalicious": true,
  "confidence": 0.87,
  "entropy": 0.92,
  "suspiciousPatterns": 3,
  "recommendation": "🚨 Cuarentena inmediata"
}

🛠️ Comandos del CLI

Comandos principales
Comando             Descripción                                     Ejemplo
run                 Ejecuta un módulo de análisis                   node src/cli.js run malware --file=./test.bin
list                Lista todos los módulos disponibles             node src/cli.js list
info                Muestra información del sistema                 node src/cli.js info
train               Entrena un modelo (experimental)                node src/cli.js train --module=phishing
help                Muestra la ayuda completa                       node src/cli.js help


Opciones comunes
--file=<ruta>: Ruta al archivo a analizar (requerido para run)

--module=<nombre>: Nombre del módulo a ejecutar

Ejemplos avanzados
# Análisis con salida formateada
node src/cli.js run malware --file=./muestra.bin | jq

# Guardar resultados en archivo
node src/cli.js run phishing --file=./urls.csv > resultados.json

# Ejecutar todos los tests
npm test
