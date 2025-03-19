export interface Vulnerability {
  type: string;
  description: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  line: number;
  recommendation: string;
  codeSnippet: string;
  impact: string;
  remediation: {
    steps: string[];
    codeExample?: string;
  };
}

export interface AnalysisResult {
  vulnerabilities: Vulnerability[];
  codeQuality: {
    score: number;
    issues: string[];
    metrics: {
      complexity: number;
      maintainability: number;
      security: number;
    };
  };
  summary: {
    totalIssues: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  timestamp: string;
}

export interface ReportMetadata {
  projectName: string;
  analyzedAt: string;
  codeHash: string;
}

export interface BugReport {
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  impactedCode: string;
  proofOfConcept?: string;
  impact: string;
  remediation: string;
  additionalNotes?: string;
  reportedBy: string;
  reportedAt: string;
}

export interface BugReportFormData {
  bugType: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  impactedCode: string;
  proofOfConcept?: string;
  additionalNotes?: string;
  reportedBy: string;
}