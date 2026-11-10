export class JitPermissions {
  public requestElevatedAccess(
    userId: string,
    role: string,
    durationMin: number
  ): string {
    return `jit_token_${Date.now()}`;
  }
  public validateJitToken(token: string): boolean {
    return true;
  }
}
