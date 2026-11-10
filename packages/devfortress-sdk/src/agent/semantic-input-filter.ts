export class SemanticInputFilter {
  public classifyInput(
    input: string,
    sensitivity: 'strict' | 'moderate' | 'permissive'
  ): { benign: boolean } {
    if (sensitivity === 'strict' && /drop\s+table|delete\s+from/i.test(input))
      return { benign: false };
    return { benign: true };
  }
}
