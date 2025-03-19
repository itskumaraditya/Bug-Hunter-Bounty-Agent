import { jsPDF } from 'jspdf';
import { AnalysisResult, ReportMetadata } from '../types';
import { format } from 'date-fns';

export function generatePDFReport(result: AnalysisResult, metadata: ReportMetadata): string {
  const doc = new jsPDF();
  let yPos = 20;

  // Title
  doc.setFontSize(20);
  doc.text('Move Smart Contract Security Analysis Report', 20, yPos);
  yPos += 20;

  // Metadata
  doc.setFontSize(12);
  doc.text(`Project: ${metadata.projectName}`, 20, yPos);
  yPos += 10;
  doc.text(`Analysis Date: ${metadata.analyzedAt}`, 20, yPos);
  yPos += 20;

  // Summary
  doc.setFontSize(16);
  doc.text('Summary', 20, yPos);
  yPos += 10;
  doc.setFontSize(12);
  doc.text(`Total Issues: ${result.summary.totalIssues}`, 30, yPos);
  yPos += 7;
  doc.text(`Critical: ${result.summary.criticalCount}`, 30, yPos);
  yPos += 7;
  doc.text(`High: ${result.summary.highCount}`, 30, yPos);
  yPos += 7;
  doc.text(`Medium: ${result.summary.mediumCount}`, 30, yPos);
  yPos += 7;
  doc.text(`Low: ${result.summary.lowCount}`, 30, yPos);
  yPos += 20;

  // Code Quality
  doc.setFontSize(16);
  doc.text('Code Quality Metrics', 20, yPos);
  yPos += 10;
  doc.setFontSize(12);
  doc.text(`Overall Score: ${result.codeQuality.score}/100`, 30, yPos);
  yPos += 7;
  doc.text(`Complexity: ${result.codeQuality.metrics.complexity}/100`, 30, yPos);
  yPos += 7;
  doc.text(`Maintainability: ${result.codeQuality.metrics.maintainability}/100`, 30, yPos);
  yPos += 7;
  doc.text(`Security: ${result.codeQuality.metrics.security}/100`, 30, yPos);
  yPos += 20;

  // Vulnerabilities
  doc.setFontSize(16);
  doc.text('Detailed Findings', 20, yPos);
  yPos += 10;

  result.vulnerabilities.forEach((vuln, index) => {
    if (yPos > 250) {
      doc.addPage();
      yPos = 20;
    }

    doc.setFontSize(14);
    doc.text(`${index + 1}. ${vuln.type} (${vuln.severity})`, 20, yPos);
    yPos += 7;
    doc.setFontSize(12);
    doc.text(`Line ${vuln.line}: ${vuln.description}`, 30, yPos);
    yPos += 7;
    doc.text(`Impact: ${vuln.impact}`, 30, yPos);
    yPos += 7;
    doc.text('Remediation:', 30, yPos);
    yPos += 7;
    vuln.remediation.steps.forEach(step => {
      doc.text(`• ${step}`, 35, yPos);
      yPos += 7;
    });
    yPos += 10;
  });

  // Save the PDF
  return doc.output('datauristring');
}