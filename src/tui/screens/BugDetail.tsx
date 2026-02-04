import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import { Bug } from '../../types.js';

interface BugDetailProps {
  bug: Bug;
  index: number;
  total: number;
  onFix: () => void;
  onNext: () => void;
  onPrev: () => void;
  onBack: () => void;
}

type Tab = 'overview' | 'codepath' | 'evidence' | 'fix';

export const BugDetail: React.FC<BugDetailProps> = ({
  bug,
  index,
  total,
  onFix,
  onNext,
  onPrev,
  onBack,
}) => {
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  useInput((input, key) => {
    if (input === 'f') {
      onFix();
    } else if (input === 'n' || key.rightArrow) {
      onNext();
    } else if (input === 'p' || key.leftArrow) {
      onPrev();
    } else if (input === 'b' || key.escape) {
      onBack();
    } else if (input === '1') {
      setActiveTab('overview');
    } else if (input === '2') {
      setActiveTab('codepath');
    } else if (input === '3') {
      setActiveTab('evidence');
    } else if (input === '4') {
      setActiveTab('fix');
    } else if (key.tab) {
      const tabs: Tab[] = ['overview', 'codepath', 'evidence', 'fix'];
      const currentIndex = tabs.indexOf(activeTab);
      setActiveTab(tabs[(currentIndex + 1) % tabs.length]);
    }
  });

  return (
    <Box flexDirection="column">
      {/* Bug header */}
      <Box flexDirection="column" marginBottom={1}>
        <Box>
          <Text color="gray">{bug.id} </Text>
          <Text color={getSeverityColor(bug.severity)} bold>
            [{bug.severity.toUpperCase()}]
          </Text>
          <Text> </Text>
          <Text bold>{bug.title}</Text>
        </Box>
        <Box marginTop={1}>
          <Text color="gray">File: </Text>
          <Text color="cyan">{bug.file}</Text>
          <Text color="gray">:</Text>
          <Text color="yellow">{bug.line}</Text>
          {bug.endLine && (
            <>
              <Text color="gray">-</Text>
              <Text color="yellow">{bug.endLine}</Text>
            </>
          )}
        </Box>
        <Box>
          <Text color="gray">Category: </Text>
          <Text>{formatCategory(bug.category)}</Text>
          <Text color="gray"> | Confidence: </Text>
          <Text color={getConfidenceColor(bug.confidence.overall)}>
            {bug.confidence.overall.toUpperCase()}
          </Text>
          {bug.confidence.adversarialSurvived && (
            <Text color="green"> ✓ Validated</Text>
          )}
        </Box>
      </Box>

      {/* Tabs */}
      <Box marginBottom={1}>
        <TabButton label="1:Overview" active={activeTab === 'overview'} />
        <TabButton label="2:Code Path" active={activeTab === 'codepath'} />
        <TabButton label="3:Evidence" active={activeTab === 'evidence'} />
        <TabButton label="4:Action" active={activeTab === 'fix'} />
      </Box>

      {/* Tab content */}
      <Box
        flexDirection="column"
        borderStyle="single"
        borderColor="gray"
        padding={1}
        minHeight={10}
      >
        {activeTab === 'overview' && (
          <Box flexDirection="column">
            <Text bold>Description</Text>
            <Text wrap="wrap">{bug.description}</Text>
          </Box>
        )}

        {activeTab === 'codepath' && (
          <Box flexDirection="column">
            <Text bold>Code Path ({bug.codePath.length} steps)</Text>
            {bug.codePath.length === 0 ? (
              <Text color="gray">No code path available</Text>
            ) : (
              bug.codePath.map((step, i) => (
                <Box key={i} flexDirection="column" marginTop={i > 0 ? 1 : 0}>
                  <Box>
                    <Text color="cyan">{step.step}. </Text>
                    <Text color="yellow">{step.file}:{step.line}</Text>
                  </Box>
                  {step.code && (
                    <Box marginLeft={3}>
                      <Text color="gray">{step.code}</Text>
                    </Box>
                  )}
                  <Box marginLeft={3}>
                    <Text>{step.explanation}</Text>
                  </Box>
                </Box>
              ))
            )}
          </Box>
        )}

        {activeTab === 'evidence' && (
          <Box flexDirection="column">
            <Text bold>Evidence ({bug.evidence.length} items)</Text>
            {bug.evidence.length === 0 ? (
              <Text color="gray">No evidence provided</Text>
            ) : (
              bug.evidence.map((e, i) => (
                <Box key={i}>
                  <Text color="gray">• </Text>
                  <Text>{e}</Text>
                </Box>
              ))
            )}

            {/* Confidence breakdown */}
            <Box flexDirection="column" marginTop={2}>
              <Text bold>Confidence Breakdown</Text>
              <Box>
                <Text color="gray">Code Path Validity: </Text>
                <Text>{(bug.confidence.codePathValidity * 100).toFixed(0)}%</Text>
              </Box>
              <Box>
                <Text color="gray">Reachability: </Text>
                <Text>{(bug.confidence.reachability * 100).toFixed(0)}%</Text>
              </Box>
              <Box>
                <Text color="gray">Intent Violation: </Text>
                <Text>{bug.confidence.intentViolation ? 'Yes' : 'No'}</Text>
              </Box>
              <Box>
                <Text color="gray">Static Tool Signal: </Text>
                <Text>{bug.confidence.staticToolSignal ? 'Yes' : 'No'}</Text>
              </Box>
              <Box>
                <Text color="gray">Adversarial Validated: </Text>
                <Text color={bug.confidence.adversarialSurvived ? 'green' : 'gray'}>
                  {bug.confidence.adversarialSurvived ? 'Yes ✓' : 'No'}
                </Text>
              </Box>
            </Box>
          </Box>
        )}

        {activeTab === 'fix' && (
          <Box flexDirection="column">
            <Text bold>Agentic Fix</Text>
            <Box marginTop={1} flexDirection="column">
              <Text color="cyan">Press [f] to start an AI-powered fix.</Text>
              <Box marginTop={1}>
                <Text color="gray">The AI will:</Text>
              </Box>
              <Text color="gray">  1. Read the file and understand the context</Text>
              <Text color="gray">  2. Explore related files if needed</Text>
              <Text color="gray">  3. Apply a fix directly to the code</Text>
              <Text color="gray">  4. Show you the diff for review</Text>
            </Box>
          </Box>
        )}
      </Box>

      {/* Navigation */}
      <Box marginTop={1} justifyContent="space-between">
        <Text color="gray">
          Bug {index + 1} of {total}
        </Text>
        <Text color="gray">
          [←/p] Prev  [→/n] Next  [f] Fix  [Tab] Switch tab  [b] Back
        </Text>
      </Box>
    </Box>
  );
};

const TabButton: React.FC<{ label: string; active: boolean }> = ({ label, active }) => (
  <Box marginRight={2}>
    <Text color={active ? 'cyan' : 'gray'} bold={active} underline={active}>
      {label}
    </Text>
  </Box>
);

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

function formatCategory(category: string): string {
  return category
    .split('-')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}
