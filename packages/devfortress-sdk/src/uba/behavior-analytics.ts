export class UserBehaviorAnalytics {
  public profileSession(userId: string, endpoints: string[]): any {
    return { userId, profile: 'standard' };
  }
  public detectImpossibleTravel(loc1: any, loc2: any): boolean {
    return false; // Mock implementation
  }
}
