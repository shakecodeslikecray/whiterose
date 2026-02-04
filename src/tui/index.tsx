import React from 'react';
import { render } from 'ink';
import { Bug, WhiteroseConfig } from '../types.js';
import { App, FixResultInfo } from './App.js';
import { applyFix } from '../core/fixer.js';
import { removeBugFromAccumulated } from '../core/bug-merger.js';

interface FixOptions {
  dryRun: boolean;
  branch?: string;
}

export async function startFixTUI(
  bugs: Bug[],
  config: WhiteroseConfig,
  options: FixOptions,
  cwd?: string
): Promise<void> {
  return new Promise((resolve) => {
    const handleFix = async (bug: Bug): Promise<FixResultInfo> => {
      const result = await applyFix(bug, config, options);

      // Handle false positive - return info so UI can show it
      if (result.falsePositive) {
        // Remove from accumulated list since it's not a real bug
        if (cwd) {
          removeBugFromAccumulated(cwd, bug.id);
        }
        return {
          falsePositive: true,
          falsePositiveReason: result.falsePositiveReason,
        };
      }

      // Throw on failure so TUI shows error correctly
      if (!result.success) {
        throw new Error(result.error || 'Fix failed');
      }

      // Remove bug from accumulated list after successful fix (not dry-run)
      if (!options.dryRun && cwd) {
        removeBugFromAccumulated(cwd, bug.id);
      }

      return { falsePositive: false };
    };

    const handleExit = () => {
      resolve();
    };

    const { unmount, waitUntilExit } = render(
      <App
        bugs={bugs}
        config={config}
        fixOptions={options}
        onFix={handleFix}
        onExit={handleExit}
      />
    );

    waitUntilExit().then(() => {
      resolve();
    });
  });
}

// Also export a simpler non-interactive mode for CI/scripts
export { App } from './App.js';
export { Dashboard } from './screens/Dashboard.js';
export { BugList } from './screens/BugList.js';
export { BugDetail } from './screens/BugDetail.js';
export { FixConfirm } from './screens/FixConfirm.js';
