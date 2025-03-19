import React, { useState } from 'react';
import { Shield, AlertTriangle, Code2, CheckCircle, Download, FileText, PieChart, Bug, Zap, Plus } from 'lucide-react';
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter';
import { analyzeMoveCode } from './utils/analyzer';
import { generatePDFReport } from './utils/report';
import { generateBugReport } from './utils/bugReportGenerator';
import { Vulnerability, AnalysisResult, BugReport, BugReportFormData } from './types';
import { format } from 'date-fns';

const SAMPLE_CODE = `
module example::basic_coin {
    struct Coin has key {
        value: u64,
    }

    public fun mint(account: &signer, value: u64) {
        move_to(account, Coin { value })
    }

    public fun transfer(from: &signer, to: address, amount: u64) {
        assert!(amount > 0, 101);
        // Implementation
    }
}
`;

function App() {
  const [code, setCode] = useState(SAMPLE_CODE.trim());
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [projectName, setProjectName] = useState('Move Smart Contract');
  const [showBugReportForm, setShowBugReportForm] = useState(false);
  const [bugReports, setBugReports] = useState<BugReport[]>([]);
  const [bugReportForm, setBugReportForm] = useState<BugReportFormData>({
    bugType: 'Custom',
    severity: 'Medium',
    description: '',
    impactedCode: '',
    reportedBy: ''
  });

  const handleAnalyze = () => {
    const result = analyzeMoveCode(code);
    setAnalysis(result);
  };

  const handleDownloadReport = () => {
    if (!analysis) return;

    const metadata = {
      projectName,
      analyzedAt: format(new Date(), 'PPpp'),
      codeHash: btoa(code).slice(0, 10)
    };

    const pdfDataUri = generatePDFReport(analysis, metadata);
    const link = document.createElement('a');
    link.href = pdfDataUri;
    link.download = `${projectName.toLowerCase().replace(/\s+/g, '-')}-security-report.pdf`;
    link.click();
  };

  const handleSubmitBugReport = (e: React.FormEvent) => {
    e.preventDefault();
    const report = generateBugReport(bugReportForm);
    setBugReports([...bugReports, report]);
    setShowBugReportForm(false);
    setBugReportForm({
      bugType: 'Custom',
      severity: 'Medium',
      description: '',
      impactedCode: '',
      reportedBy: ''
    });
  };

  const getSeverityColor = (severity: Vulnerability['severity']) => {
    switch (severity) {
      case 'Critical': return 'text-red-600';
      case 'High': return 'text-orange-500';
      case 'Medium': return 'text-yellow-500';
      case 'Low': return 'text-blue-500';
      default: return 'text-gray-500';
    }
  };

  const getSeverityBgColor = (severity: Vulnerability['severity']) => {
    switch (severity) {
      case 'Critical': return 'bg-red-100';
      case 'High': return 'bg-orange-100';
      case 'Medium': return 'bg-yellow-100';
      case 'Low': return 'bg-blue-100';
      default: return 'bg-gray-100';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-indigo-600" />
              <h1 className="ml-3 text-2xl font-bold text-gray-900">Move Code Security Analyzer</h1>
            </div>
            <div className="flex items-center space-x-4">
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="px-3 py-2 border rounded-md text-sm"
                placeholder="Project Name"
              />
              <button
                onClick={() => setShowBugReportForm(true)}
                className="flex items-center px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors"
              >
                <Plus className="h-4 w-4 mr-2" />
                Report Bug
              </button>
              {analysis && (
                <button
                  onClick={handleDownloadReport}
                  className="flex items-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors"
                >
                  <Download className="h-4 w-4 mr-2" />
                  Download Report
                </button>
              )}
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 sm:px-6 lg:px-8">
        {showBugReportForm && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
              <h2 className="text-xl font-bold mb-4">Report Security Bug</h2>
              <form onSubmit={handleSubmitBugReport} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Bug Type</label>
                  <select
                    value={bugReportForm.bugType}
                    onChange={(e) => setBugReportForm({...bugReportForm, bugType: e.target.value})}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
                  >
                    <option value="Custom">Custom</option>
                    <option value="Integer Overflow">Integer Overflow</option>
                    <option value="Access Control">Access Control</option>
                    <option value="Resource Safety">Resource Safety</option>
                    <option value="Reentrancy">Reentrancy</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Severity</label>
                  <select
                    value={bugReportForm.severity}
                    onChange={(e) => setBugReportForm({...bugReportForm, severity: e.target.value as any})}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Description</label>
                  <textarea
                    value={bugReportForm.description}
                    onChange={(e) => setBugReportForm({...bugReportForm, description: e.target.value})}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
                    rows={4}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Impacted Code</label>
                  <textarea
                    value={bugReportForm.impactedCode}
                    onChange={(e) => setBugReportForm({...bugReportForm, impactedCode: e.target.value})}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 font-mono"
                    rows={4}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Proof of Concept (Optional)</label>
                  <textarea
                    value={bugReportForm.proofOfConcept}
                    onChange={(e) => setBugReportForm({...bugReportForm, proofOfConcept: e.target.value})}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50 font-mono"
                    rows={4}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Additional Notes (Optional)</label>
                  <textarea
                    value={bugReportForm.additionalNotes}
                    onChange={(e) => setBugReportForm({...bugReportForm, additionalNotes: e.target.value})}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
                    rows={2}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Reported By</label>
                  <input
                    type="text"
                    value={bugReportForm.reportedBy}
                    onChange={(e) => setBugReportForm({...bugReportForm, reportedBy: e.target.value})}
                    className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50"
                  />
                </div>
                <div className="flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setShowBugReportForm(false)}
                    className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700"
                  >
                    Submit Report
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-6">
            <div className="bg-white rounded-lg shadow">
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold flex items-center">
                    <Code2 className="h-5 w-5 mr-2 text-gray-500" />
                    Move Code
                  </h2>
                  <button
                    onClick={handleAnalyze}
                    className="flex items-center px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
                  >
                    <Zap className="h-4 w-4 mr-2" />
                    Analyze Code
                  </button>
                </div>
                <textarea
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  className="w-full h-[400px] font-mono text-sm p-4 border rounded-md focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  placeholder="Paste your Move code here..."
                />
              </div>
            </div>

            {analysis && (
              <div className="bg-white rounded-lg shadow p-6">
                <h2 className="text-lg font-semibold flex items-center mb-4">
                  <PieChart className="h-5 w-5 mr-2 text-gray-500" />
                  Analysis Summary
                </h2>
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-4 bg-red-50 rounded-lg">
                    <div className="text-sm text-red-600">Critical</div>
                    <div className="text-2xl font-bold text-red-700">
                      {analysis.summary.criticalCount}
                    </div>
                  </div>
                  <div className="p-4 bg-orange-50 rounded-lg">
                    <div className="text-sm text-orange-600">High</div>
                    <div className="text-2xl font-bold text-orange-700">
                      {analysis.summary.highCount}
                    </div>
                  </div>
                  <div className="p-4 bg-yellow-50 rounded-lg">
                    <div className="text-sm text-yellow-600">Medium</div>
                    <div className="text-2xl font-bold text-yellow-700">
                      {analysis.summary.mediumCount}
                    </div>
                  </div>
                  <div className="p-4 bg-blue-50 rounded-lg">
                    <div className="text-sm text-blue-600">Low</div>
                    <div className="text-2xl font-bold text-blue-700">
                      {analysis.summary.lowCount}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {bugReports.length > 0 && (
              <div className="bg-white rounded-lg shadow p-6">
                <h2 className="text-lg font-semibold flex items-center mb-4">
                  <Bug className="h-5 w-5 mr-2 text-purple-500" />
                  Reported Bugs
                </h2>
                <div className="space-y-4">
                  {bugReports.map((report, index) => (
                    <div key={index} className="border rounded-md p-4">
                      <div className="flex items-center justify-between">
                        <h3 className="font-medium">{report.title}</h3>
                        <span className={`px-2 py-1 rounded-full text-xs ${getSeverityColor(report.severity)} ${getSeverityBgColor(report.severity)}`}>
                          {report.severity}
                        </span>
                      </div>
                      <p className="mt-2 text-gray-600">{report.description}</p>
                      <div className="mt-2 p-2 bg-gray-50 rounded text-sm font-mono">
                        {report.impactedCode}
                      </div>
                      {report.proofOfConcept && (
                        <div className="mt-3">
                          <h4 className="font-medium text-gray-700">Proof of Concept:</h4>
                          <div className="mt-1 p-2 bg-gray-50 rounded text-sm font-mono">
                            {report.proofOfConcept}
                          </div>
                        </div>
                      )}
                      <div className="mt-3">
                        <h4 className="font-medium text-gray-700">Impact:</h4>
                        <p className="mt-1 text-sm text-gray-600">{report.impact}</p>
                      </div>
                      <div className="mt-3">
                        <h4 className="font-medium text-gray-700">Remediation:</h4>
                        <p className="mt-1 text-sm text-gray-600">{report.remediation}</p>
                      </div>
                      <div className="mt-3 text-sm text-gray-500">
                        Reported by {report.reportedBy} on {report.reportedAt}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="space-y-6">
            {analysis && (
              <>
                <div className="bg-white rounded-lg shadow p-6">
                  <h2 className="text-lg font-semibold flex items-center mb-4">
                    <Bug className="h-5 w-5 mr-2 text-yellow-500" />
                    Vulnerabilities Found
                  </h2>
                  <div className="space-y-4">
                    {analysis.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="border rounded-md p-4">
                        <div className="flex items-center justify-between">
                          <h3 className={`font-medium ${getSeverityColor(vuln.severity)}`}>
                            {vuln.type}
                          </h3>
                          <span className={`px-2 py-1 rounded-full text-xs ${getSeverityColor(vuln.severity)} ${getSeverityBgColor(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <p className="mt-2 text-gray-600">{vuln.description}</p>
                        <p className="mt-1 text-sm text-gray-500">Line: {vuln.line}</p>
                        <div className="mt-2 p-2 bg-gray-50 rounded text-sm font-mono">
                          {vuln.codeSnippet}
                        </div>
                        <div className="mt-3">
                          <h4 className="font-medium text-gray-700">Impact:</h4>
                          <p className="mt-1 text-sm text-gray-600">{vuln.impact}</p>
                        </div>
                        <div className="mt-3">
                          <h4 className="font-medium text-gray-700">Remediation:</h4>
                          <ul className="mt-1 list-disc list-inside text-sm text-gray-600">
                            {vuln.remediation.steps.map((step, i) => (
                              <li key={i}>{step}</li>
                            ))}
                          </ul>
                          {vuln.remediation.codeExample && (
                            <div className="mt-2 p-2 bg-gray-50 rounded text-sm font-mono whitespace-pre">
                              {vuln.remediation.codeExample}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                    {analysis.vulnerabilities.length === 0 && (
                      <p className="text-green-600 flex items-center">
                        <CheckCircle className="h-5 w-5 mr-2" />
                        No vulnerabilities detected
                      </p>
                    )}
                  </div>
                </div>

                <div className="bg-white rounded-lg shadow p-6">
                  <h2 className="text-lg font-semibold flex items-center mb-4">
                    <FileText className="h-5 w-5 mr-2 text-gray-500" />
                    Code Quality Analysis
                  </h2>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="text-3xl font-bold text-indigo-600">
                        {analysis.codeQuality.score}/100
                      </div>
                      <div className="text-sm text-gray-500">
                        Overall Quality Score
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-4">
                      <div className="p-3 bg-gray-50 rounded-lg">
                        <div className="text-sm text-gray-500">Complexity</div>
                        <div className="text-lg font-semibold text-gray-700">
                          {analysis.codeQuality.metrics.complexity}/100
                        </div>
                      </div>
                      <div className="p-3 bg-gray-50 rounded-lg">
                        <div className="text-sm text-gray-500">Maintainability</div>
                        <div className="text-lg font-semibold text-gray-700">
                          {analysis.codeQuality.metrics.maintainability}/100
                        </div>
                      </div>
                      <div className="p-3 bg-gray-50 rounded-lg">
                        <div className="text-sm text-gray-500">Security</div>
                        <div className="text-lg font-semibold text-gray-700">
                          {analysis.codeQuality.metrics.security}/100
                        </div>
                      </div>
                    </div>
                    {analysis.codeQuality.issues.length > 0 && (
                      <div className="mt-4">
                        <h3 className="font-medium text-gray-700 mb-2">Quality Issues:</h3>
                        <ul className="list-disc pl-5 space-y-1">
                          {analysis.codeQuality.issues.map((issue, index) => (
                            <li key={index} className="text-gray-600">{issue}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;