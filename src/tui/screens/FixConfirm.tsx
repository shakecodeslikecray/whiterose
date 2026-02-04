import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import { Bug } from '../../types.js';
import { FixResultInfo } from '../App.js';

interface FixConfirmProps {
  bug: Bug;
  dryRun: boolean;
  onConfirm: () => Promise<FixResultInfo>;
  onCancel: () => void;
  onFixComplete: () => void; // Called after user acknowledges success (or false positive)
}

export const FixConfirm: React.FC<FixConfirmProps> = ({ bug, dryRun, onConfirm, onCancel, onFixComplete }) => {
  const [status, setStatus] = useState<'confirm' | 'fixing' | 'done' | 'error' | 'false-positive'>('confirm');
  const [error, setError] = useState<string | null>(null);
  const [falsePositiveReason, setFalsePositiveReason] = useState<string | null>(null);
  const [progressMessage, setProgressMessage] = useState<string>('');

  useInput(async (input, key) => {
    // Handle success acknowledgment - user presses any key to continue
    if (status === 'done') {
      onFixComplete();
      return;
    }

    // Handle false positive acknowledgment - user presses any key to continue
    if (status === 'false-positive') {
      onFixComplete();
      return;
    }

    // Handle error acknowledgment
    if (status === 'error') {
      onCancel();
      return;
    }

    if (status !== 'confirm') return;

    if (input === 'y' || key.return) {
      setStatus('fixing');
      setProgressMessage('Starting agentic fix...');
      try {
        const result = await onConfirm();
        if (result.falsePositive) {
          setFalsePositiveReason(result.falsePositiveReason || 'The AI determined this bug is not real after analyzing the code.');
          setStatus('false-positive');
        } else {
          setStatus('done');
        }
      } catch (e: any) {
        setError(e.message || 'Unknown error');
        setStatus('error');
      }
    } else if (input === 'n' || key.escape) {
      onCancel();
    }
  });

  return (
    <Box flexDirection="column">
      {/* Bug summary */}
      <Box flexDirection="column" marginBottom={1}>
        <Box>
          <Text bold>Fix: </Text>
          <Text>{bug.title}</Text>
        </Box>
        <Box>
          <Text color="gray">File: </Text>
          <Text color="cyan">{bug.file}:{bug.line}</Text>
        </Box>
      </Box>

      {/* Bug details */}
      <Box
        flexDirection="column"
        borderStyle="single"
        borderColor="gray"
        padding={1}
        marginBottom={1}
      >
        <Text bold>Bug Details:</Text>
        <Box marginTop={1} flexDirection="column">
          <Text color="gray">{bug.description}</Text>
          {bug.evidence && bug.evidence.length > 0 && (
            <Box marginTop={1} flexDirection="column">
              <Text dimColor>Evidence:</Text>
              {bug.evidence.slice(0, 3).map((e, i) => (
                <Text key={i} color="gray">  • {e}</Text>
              ))}
            </Box>
          )}
        </Box>
      </Box>

      {/* Agentic fix explanation */}
      <Box marginBottom={1}>
        <Text color="cyan">
          ◆ The AI will explore the code, understand context, and apply a fix automatically.
        </Text>
      </Box>

      {/* Status */}
      {status === 'confirm' && (
        <Box flexDirection="column">
          {dryRun && (
            <Box marginBottom={1}>
              <Text color="yellow">DRY RUN MODE - Changes will NOT be applied</Text>
            </Box>
          )}
          <Box>
            <Text>Start agentic fix? </Text>
            <Text color="green">[y]es</Text>
            <Text> / </Text>
            <Text color="red">[n]o</Text>
          </Box>
        </Box>
      )}

      {status === 'fixing' && (
        <Box flexDirection="column">
          <Box>
            <Text color="cyan">
              <Spinner type="dots" />
            </Text>
            <Text> AI is analyzing and fixing the bug...</Text>
          </Box>
          {progressMessage && (
            <Box marginTop={1}>
              <Text color="gray">{progressMessage}</Text>
            </Box>
          )}
        </Box>
      )}

      {status === 'done' && (
        <Box flexDirection="column">
          <Box>
            <Text color="green" bold>✓ Bug fixed successfully!</Text>
          </Box>
          <Box marginTop={1}>
            <Text color="gray">Press any key to continue to next bug...</Text>
          </Box>
        </Box>
      )}

      {status === 'false-positive' && (
        <Box flexDirection="column">
          <Box>
            <Text color="yellow" bold>⚠ False Positive Detected</Text>
          </Box>
          <Box marginTop={1} flexDirection="column">
            <Text color="gray">The AI analyzed the code and determined this is NOT a real bug:</Text>
            {falsePositiveReason && (
              <Box marginTop={1} paddingLeft={2}>
                <Text color="cyan">{falsePositiveReason}</Text>
              </Box>
            )}
          </Box>
          <Box marginTop={1}>
            <Text color="gray">This bug has been removed from the list.</Text>
          </Box>
          <Box marginTop={1}>
            <Text color="gray">Press any key to continue...</Text>
          </Box>
        </Box>
      )}

      {status === 'error' && (
        <Box flexDirection="column">
          <Text color="red" bold>✗ Failed to fix bug</Text>
          {error && (
            <Box marginTop={1}>
              <Text color="gray">{error}</Text>
            </Box>
          )}
          <Box marginTop={1}>
            <Text color="gray">Press any key to go back</Text>
          </Box>
        </Box>
      )}
    </Box>
  );
};
