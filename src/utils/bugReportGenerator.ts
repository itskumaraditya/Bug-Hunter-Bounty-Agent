import { BugReport, BugReportFormData } from '../types';
import { format } from 'date-fns';

const BUG_TEMPLATES = {
  'Integer Overflow': {
    title: 'Integer Overflow Vulnerability',
    description: 'Potential integer overflow in arithmetic operations could lead to unexpected behavior.',
    impact: 'Attackers could exploit numeric overflow to manipulate balances or bypass checks.',
    remediation: 'Implement safe math operations with proper bounds checking and overflow protection.'
  },
  'Access Control': {
    title: 'Insufficient Access Control',
    description: 'Critical functions lack proper access control mechanisms.',
    impact: 'Unauthorized users could execute privileged operations.',
    remediation: 'Implement role-based access control and proper authorization checks.'
  },
  'Resource Safety': {
    title: 'Resource Safety Violation',
    description: 'Improper handling of Move resources could lead to safety violations.',
    impact: 'Resources could be duplicated or lost, leading to contract state inconsistencies.',
    remediation: 'Implement proper resource management with existence checks and cleanup.'
  },
  'Reentrancy': {
    title: 'Potential Reentrancy Vulnerability',
    description: 'Contract state changes after external calls could enable reentrancy attacks.',
    impact: 'Attackers could recursively call functions to manipulate contract state.',
    remediation: 'Follow the checks-effects-interactions pattern and implement reentrancy guards.'
  },
  'Custom': {
    title: 'Security Vulnerability',
    description: '',
    impact: '',
    remediation: ''
  }
};

export function generateBugReport(formData: BugReportFormData): BugReport {
  const template = BUG_TEMPLATES[formData.bugType as keyof typeof BUG_TEMPLATES] || BUG_TEMPLATES.Custom;

  return {
    title: formData.bugType === 'Custom' ? 'Security Vulnerability' : template.title,
    severity: formData.severity,
    description: formData.description || template.description,
    impactedCode: formData.impactedCode,
    proofOfConcept: formData.proofOfConcept,
    impact: template.impact,
    remediation: template.remediation,
    additionalNotes: formData.additionalNotes,
    reportedBy: formData.reportedBy,
    reportedAt: format(new Date(), 'yyyy-MM-dd HH:mm:ss')
  };
}