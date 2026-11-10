/**
 * Manual Jest mock for onnxruntime-node (TODO 192).
 *
 * onnxruntime-node's native binding is not safe to initialize more than
 * once per process, and is separately incompatible with jest-environment-node's
 * sandboxed vm context for constructing native TypedArray outputs (see
 * ml-classifier.test.ts for the full writeup of both issues). Auto-applied
 * to every test file except ml-classifier.test.ts, which calls
 * `jest.unmock('onnxruntime-node')` to exercise the real native module in
 * isolation, exactly once, in exactly one file.
 *
 * `InferenceSession.create()` rejecting is indistinguishable, from
 * MLClassifier's perspective, from "the model failed to load" — its
 * existing catch-all in loadSession() already handles that by falling back
 * to heuristic scoring. Every other test in the suite that happens to
 * construct a Team/Enterprise-tier internal/hybrid DevFortressCore (and so
 * picks up MLClassifier as the default Tier 2 scorer) gets that same safe,
 * non-crashing heuristic fallback instead of ever touching the native addon.
 */
module.exports = {
  InferenceSession: {
    create: () =>
      Promise.reject(new Error('onnxruntime-node mocked out under Jest')),
  },
  Tensor: class MockTensor {
    constructor(type, data, dims) {
      this.type = type;
      this.data = data;
      this.dims = dims;
    }
  },
};
