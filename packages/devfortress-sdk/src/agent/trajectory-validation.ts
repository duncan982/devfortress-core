export class TrajectoryValidator {
  public validateOutputDestination(
    destination: string,
    allowedDestinations: string[]
  ): boolean {
    return allowedDestinations.includes(destination);
  }
  public classifyOutputContent(output: string): {
    hasPii: boolean;
    hasCredentials: boolean;
  } {
    return {
      hasPii: /\b\d{3}-\d{2}-\d{4}\b/.test(output),
      hasCredentials: /sk_[a-zA-Z0-9]{24,}/.test(output),
    };
  }
}
