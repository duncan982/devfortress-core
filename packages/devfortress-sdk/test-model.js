const ort = require('onnxruntime-node');

(async () => {
  try {
    // 1. Load the model from the file system
    const session = await ort.InferenceSession.create(
      './models/threat-classifier.onnx'
    );

    // 2. Create a dummy input tensor (1 row, 14 features, filled with 0.5)
    // This matches the FloatTensorType([None, 14]) we defined in Python
    const input = new ort.Tensor(
      'float32',
      new Float32Array(14).fill(0.5),
      [1, 14]
    );

    // 3. Run the inference
    const results = await session.run({ [session.inputNames[0]]: input });

    // 4. Extract and print the output
    const outputData = Object.values(results)[1].data;
    console.log('✅ Inference Successful!');
    console.log('Severity Probabilities (LOW, MEDIUM, HIGH, CRITICAL):');
    console.log(outputData);
  } catch (error) {
    console.error('❌ Failed to run inference:', error);
  }
})();
