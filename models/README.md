# Modelos de Machine Learning

Esta carpeta contiene los modelos pre-entrenados para cada módulo.

## Estructura
models/
├── malware/
│ └── model.json
├── phishing/
│ └── model.json
├── network/
│ └── model.json
├── log/
│ └── model.json
└── threat/
└── model.json


## Formato
Los modelos están en formato TensorFlow.js (`model.json` + archivos `.bin`).

## Entrenamiento
Para entrenar un modelo:
```bash
node src/cli.js train --module=malware --data=./data/malware.csv

Notas
Los modelos se cargan automáticamente al iniciar

Si no existen, se usan modelos de simulación
