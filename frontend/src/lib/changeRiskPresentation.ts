import type { ChangeRiskLevel } from '@/types/domain';

type RiskBadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'default';

export function describeChangeRisk(
  level: ChangeRiskLevel | string | null | undefined,
): { variant: RiskBadgeVariant; label: string } | null {
  if (!level) return null;
  switch (level) {
    case 'CRITICAL': return { variant: 'critical', label: 'CRITICAL RISK' };
    case 'HIGH': return { variant: 'high', label: 'HIGH RISK' };
    case 'MEDIUM': return { variant: 'medium', label: 'MEDIUM RISK' };
    case 'LOW': return { variant: 'low', label: 'LOW RISK' };
    case 'NONE': return { variant: 'default', label: 'NO RISK LEVEL ASSIGNED' };
    default: return { variant: 'default', label: 'RISK UNKNOWN' };
  }
}
