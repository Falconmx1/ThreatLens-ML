/**
 * Model Loader - Carga y gestiona modelos de Machine Learning
 * Soporta modelos pre-entrenados y fallback a simulación
 */

const tf = require('@tensorflow/tfjs-node');
const fs = require('fs');
const path = require('path');

class ModelLoader {
  constructor() {
    this.models = new Map();
    this.modelPath = path.join(__dirname, '../../models');
    this.useSimulation = true; // Cambiar a false cuando tengas modelos reales
  }

  /**
   * Carga un modelo desde disco o crea uno por defecto
   * @param {string} modelName - Nombre del modelo (ej: 'malware', 'phishing')
   * @param {object} options - Opciones de configuración
   * @returns {Promise<tf.LayersModel>}
   */
  async loadModel(modelName, options = {}) {
    // Verificar si ya está cargado
    if (this.models.has(modelName)) {
      return this.models.get(modelName);
    }

    const modelPath = path.join(this.modelPath, `${modelName}/model.json`);
    
    try {
      // Intentar cargar modelo real
      if (fs.existsSync(modelPath)) {
        const model = await tf.loadLayersModel(`file://${modelPath}`);
        this.models.set(modelName, model);
        console.log(`✅ Modelo '${modelName}' cargado desde disco`);
        return model;
      }
    } catch (error) {
      console.warn(`⚠️ No se pudo cargar '${modelName}', usando simulación`);
    }

    // Fallback: crear modelo simple
    const model = this.createDefaultModel(modelName, options);
    this.models.set(modelName, model);
    return model;
  }

  /**
   * Crea un modelo por defecto según el tipo
   */
  createDefaultModel(modelName, options) {
    const inputDim = options.inputDim || 10;
    const outputDim = options.outputDim || 1;

    let model;

    switch (modelName) {
      case 'malware':
        model = tf.sequential({
          layers: [
            tf.layers.dense({ units: 64, activation: 'relu', inputShape: [inputDim] }),
            tf.layers.dropout({ rate: 0.3 }),
            tf.layers.dense({ units: 32, activation: 'relu' }),
            tf.layers.dense({ units: outputDim, activation: 'sigmoid' })
          ]
        });
        break;

      case 'phishing':
        model = tf.sequential({
          layers: [
            tf.layers.dense({ units: 32, activation: 'relu', inputShape: [inputDim] }),
            tf.layers.dense({ units: 16, activation: 'relu' }),
            tf.layers.dense({ units: outputDim, activation: 'sigmoid' })
          ]
        });
        break;

      case 'network':
        model = tf.sequential({
          layers: [
            tf.layers.dense({ units: 128, activation: 'relu', inputShape: [inputDim] }),
            tf.layers.dense({ units: 64, activation: 'relu' }),
            tf.layers.dense({ units: 32, activation: 'relu' }),
            tf.layers.dense({ units: outputDim, activation: 'sigmoid' })
          ]
        });
        break;

      default:
        // Modelo genérico
        model = tf.sequential({
          layers: [
            tf.layers.dense({ units: 64, activation: 'relu', inputShape: [inputDim] }),
            tf.layers.dense({ units: 32, activation: 'relu' }),
            tf.layers.dense({ units: outputDim, activation: 'sigmoid' })
          ]
        });
    }

    // Compilar el modelo
    model.compile({
      optimizer: 'adam',
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });

    console.log(`🧠 Modelo '${modelName}' creado (simulación)`);
    return model;
  }

  /**
   * Entrena un modelo con datos proporcionados
   * @param {string} modelName - Nombre del modelo
   * @param {tf.Tensor} xs - Datos de entrada
   * @param {tf.Tensor} ys - Etiquetas
   * @param {object} options - Opciones de entrenamiento
   * @returns {Promise<tf.History>}
   */
  async trainModel(modelName, xs, ys, options = {}) {
    const model = await this.loadModel(modelName);
    const epochs = options.epochs || 10;
    const batchSize = options.batchSize || 32;

    console.log(`📚 Entrenando '${modelName}' por ${epochs} épocas...`);
    
    const history = await model.fit(xs, ys, {
      epochs,
      batchSize,
      validationSplit: 0.2,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          if (epoch % 2 === 0) {
            console.log(`  Época ${epoch}: loss=${logs.loss.toFixed(4)}, acc=${logs.acc.toFixed(4)}`);
          }
        }
      }
    });

    return history;
  }

  /**
   * Guarda un modelo en disco
   * @param {string} modelName - Nombre del modelo
   * @returns {Promise<void>}
   */
  async saveModel(modelName) {
    const model = this.models.get(modelName);
    if (!model) {
      throw new Error(`Modelo '${modelName}' no encontrado`);
    }

    const savePath = path.join(this.modelPath, modelName);
    if (!fs.existsSync(savePath)) {
      fs.mkdirSync(savePath, { recursive: true });
    }

    await model.save(`file://${savePath}`);
    console.log(`💾 Modelo '${modelName}' guardado en ${savePath}`);
  }

  /**
   * Predice usando un modelo cargado
   * @param {string} modelName - Nombre del modelo
   * @param {tf.Tensor} input - Datos de entrada
   * @returns {Promise<tf.Tensor>}
   */
  async predict(modelName, input) {
    const model = await this.loadModel(modelName);
    return model.predict(input);
  }

  /**
   * Limpia los modelos de la memoria
   */
  dispose() {
    this.models.forEach((model) => {
      model.dispose();
    });
    this.models.clear();
    console.log('🧹 Modelos liberados de memoria');
  }
}

// Exportar instancia única (singleton)
module.exports = new ModelLoader();
