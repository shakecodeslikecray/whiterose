/**
 * Shared TUI types
 * Extracted to avoid circular dependencies between App.tsx and screens/
 */

export interface FixResultInfo {
  falsePositive: boolean;
  falsePositiveReason?: string;
}

export type Screen = 'dashboard' | 'list' | 'detail' | 'fix';
