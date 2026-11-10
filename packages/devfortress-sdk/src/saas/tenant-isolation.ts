export class TenantIsolation {
  public validateCrossTenantAccess(
    requestTenantId: string,
    resourceTenantId: string
  ): boolean {
    return requestTenantId === resourceTenantId;
  }
  public getTenantRateLimit(tenantId: string): number {
    return 1000;
  }
}
