import React, { useState, useEffect } from 'react';
import { Box, Text, useInput } from 'ink';
import { Bug } from '../../types.js';

interface BugListProps {
  bugs: Bug[];
  selectedIndex: number;
  onSelect: (index: number) => void;
  onBack: () => void;
}

const VISIBLE_ITEMS = 10;

export const BugList: React.FC<BugListProps> = ({ bugs, selectedIndex, onSelect, onBack }) => {
  const [localIndex, setLocalIndex] = useState(selectedIndex);
  const [scrollOffset, setScrollOffset] = useState(0);

  useEffect(() => {
    setLocalIndex(selectedIndex);
  }, [selectedIndex]);

  // Ensure selected item is visible
  useEffect(() => {
    if (localIndex < scrollOffset) {
      setScrollOffset(localIndex);
    } else if (localIndex >= scrollOffset + VISIBLE_ITEMS) {
      setScrollOffset(localIndex - VISIBLE_ITEMS + 1);
    }
  }, [localIndex, scrollOffset]);

  useInput((input, key) => {
    if (key.upArrow || input === 'k') {
      setLocalIndex((i) => Math.max(0, i - 1));
    } else if (key.downArrow || input === 'j') {
      setLocalIndex((i) => Math.min(bugs.length - 1, i + 1));
    } else if (key.return) {
      onSelect(localIndex);
    } else if (input === 'b' || key.escape) {
      onBack();
    } else if (input === 'u' || input === '[') {
      // Page up
      setLocalIndex((i) => Math.max(0, i - VISIBLE_ITEMS));
    } else if (input === 'd' || input === ']') {
      // Page down
      setLocalIndex((i) => Math.min(bugs.length - 1, i + VISIBLE_ITEMS));
    }
  });

  if (bugs.length === 0) {
    return (
      <Box flexDirection="column">
        <Text color="gray">No bugs in this category.</Text>
        <Text color="gray">[b] Back to dashboard</Text>
      </Box>
    );
  }

  const visibleBugs = bugs.slice(scrollOffset, scrollOffset + VISIBLE_ITEMS);

  return (
    <Box flexDirection="column">
      {/* Header */}
      <Box marginBottom={1}>
        <Box width={10}>
          <Text bold color="gray">ID</Text>
        </Box>
        <Box width={7}>
          <Text bold color="gray">Kind</Text>
        </Box>
        <Box width={10}>
          <Text bold color="gray">Severity</Text>
        </Box>
        <Box width={10}>
          <Text bold color="gray">Conf</Text>
        </Box>
        <Box flexGrow={1}>
          <Text bold color="gray">Title</Text>
        </Box>
      </Box>

      {/* Bug list */}
      {visibleBugs.map((bug, index) => {
        const actualIndex = scrollOffset + index;
        const isSelected = actualIndex === localIndex;
        const kindLabel = bug.kind === 'smell' ? 'SMELL' : 'BUG';
        const kindColor = bug.kind === 'smell' ? 'yellow' : 'red';

        return (
          <Box key={`${bug.id}-${actualIndex}`} flexDirection="column">
            <Box>
              <Text color={isSelected ? 'cyan' : 'white'}>
                {isSelected ? '▶ ' : '  '}
              </Text>
              <Box width={8}>
                <Text color="gray">{bug.id}</Text>
              </Box>
              <Box width={7}>
                <Text color={kindColor}>{kindLabel.padEnd(5)}</Text>
              </Box>
              <Box width={10}>
                <Text color={getSeverityColor(bug.severity)}>
                  {bug.severity.toUpperCase().padEnd(8)}
                </Text>
              </Box>
              <Box width={10}>
                <Text color={getConfidenceColor(bug.confidence.overall)}>
                  {bug.confidence.overall.toUpperCase().padEnd(6)}
                </Text>
              </Box>
              <Box flexGrow={1} flexShrink={1}>
                <Text color={isSelected ? 'white' : 'gray'} wrap="truncate-end">
                  {bug.title}
                </Text>
              </Box>
            </Box>
            {/* Show file on second line for selected item */}
            {isSelected && (
              <Box marginLeft={2}>
                <Text color="cyan" dimColor>
                  └─ {bug.file}:{bug.line}
                </Text>
              </Box>
            )}
          </Box>
        );
      })}

      {/* Scroll indicator */}
      {bugs.length > VISIBLE_ITEMS && (
        <Box marginTop={1}>
          <Text color="gray">
            Showing {scrollOffset + 1}-{Math.min(scrollOffset + VISIBLE_ITEMS, bugs.length)} of {bugs.length}
            {scrollOffset > 0 && ' [↑ more above]'}
            {scrollOffset + VISIBLE_ITEMS < bugs.length && ' [↓ more below]'}
          </Text>
        </Box>
      )}

      {/* Instructions */}
      <Box marginTop={1}>
        <Text color="gray">
          [↑↓/jk] Navigate  [Enter] View  [u/d] Page up/down  [b] Back
        </Text>
      </Box>
    </Box>
  );
};

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'red';
    case 'high':
      return 'yellow';
    case 'medium':
      return 'blue';
    case 'low':
      return 'gray';
    default:
      return 'white';
  }
}

function getConfidenceColor(confidence: string): string {
  switch (confidence) {
    case 'high':
      return 'green';
    case 'medium':
      return 'yellow';
    case 'low':
      return 'red';
    default:
      return 'white';
  }
}
