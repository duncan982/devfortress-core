export class TransactionMonitoring {
  public checkVelocity(userId: string, txCount: number): boolean {
    return txCount < 100; // max 100 per hour
  }
  public detectAmountAnomaly(amount: number, baseline: number): boolean {
    return amount > baseline * 3; // > 3x baseline
  }
  public detectAmlStructuring(transactions: number[]): boolean {
    return transactions.filter(t => t > 9000 && t < 10000).length > 3;
  }
}
