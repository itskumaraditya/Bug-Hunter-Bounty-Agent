import { AnalysisResult, Vulnerability } from '../types';
import { format } from 'date-fns';

const VULNERABILITY_PATTERNS = [
  {
    pattern: /assert!\(/g,
    type: 'Assertion Check',
    severity: 'Medium',
    description: 'Assertions should be used carefully as they can be potential attack vectors',
    recommendation: 'Consider using proper error handling instead of assertions',
    impact: 'Malicious users could potentially exploit assertion conditions to cause contract failures',
    remediation: {
      steps: [
        'Replace assertions with proper error handling mechanisms',
        'Use custom errors with meaningful error codes',
        'Implement proper input validation'
      ],
      codeExample: `
// Instead of:
assert!(amount > 0, 101);

// Use:
if (amount == 0) {
    abort INVALID_AMOUNT
};`
    }
  },
  {
    pattern: /public\s+fun/g,
    type: 'Public Function Security',
    severity: 'High',
    description: 'Public functions need careful access control and input validation',
    recommendation: 'Implement proper access controls and validate all inputs',
    impact: 'Unauthorized users could potentially call these functions and manipulate contract state',
    remediation: {
      steps: [
        'Add access control modifiers',
        'Implement role-based permissions',
        'Add input validation'
      ],
      codeExample: `
// Add access control:
public(script) fun protected_function(account: &signer) {
    assert!(Roles::has_role(account, ADMIN_ROLE), ERROR_NOT_AUTHORIZED);
    // ... function logic
}`
    }
  },
  {
    pattern: /copy\s+/g,
    type: 'Resource Copy',
    severity: 'Medium',
    description: 'Copying resources can lead to unexpected behavior',
    recommendation: 'Consider using references instead of copying',
    impact: 'Unnecessary resource copying can lead to higher gas costs and potential state inconsistencies',
    remediation: {
      steps: [
        'Use references where possible',
        'Implement proper resource management',
        'Consider using move_to/move_from for resource handling'
      ]
    }
  },
  {
    pattern: /move_to\(/g,
    type: 'Resource Management',
    severity: 'High',
    description: 'Improper resource management can lead to resource leaks or duplications',
    recommendation: 'Ensure proper resource cleanup and management',
    impact: 'Resources could be locked in contracts or duplicated, leading to contract state issues',
    remediation: {
      steps: [
        'Implement proper resource cleanup',
        'Use move_from when removing resources',
        'Verify resource existence before operations'
      ]
    }
  },
  {
    pattern: /while\s*\(/g,
    type: 'Loop Safety',
    severity: 'Medium',
    description: 'Unbounded loops can lead to gas limit issues',
    recommendation: 'Implement proper loop bounds and gas considerations',
    impact: 'Transactions could fail due to gas limits or become too expensive',
    remediation: {
      steps: [
        'Add maximum iteration limits',
        'Consider gas costs in loop operations',
        'Use alternative non-loop implementations where possible'
      ]
    }
  },
  // New vulnerability patterns for common attack vectors
  {
    pattern: /borrow_global_mut/g,
    type: 'Mutable Global Access',
    severity: 'Critical',
    description: 'Mutable access to global storage without proper access control',
    recommendation: 'Implement strict access controls for mutable global resources',
    impact: 'Attackers could manipulate global state and potentially drain funds or manipulate contract data',
    remediation: {
      steps: [
        'Add role-based access control',
        'Implement multi-signature requirements for critical operations',
        'Add event emission for tracking state changes'
      ],
      codeExample: `
// Add access control:
public fun modify_global(account: &signer) {
    assert!(Roles::has_admin_role(account), ERROR_UNAUTHORIZED);
    let resource = borrow_global_mut<T>(addr);
    // ... protected operations
}`
    }
  },
  {
    pattern: /exists/g,
    type: 'Resource Existence Check',
    severity: 'High',
    description: 'Missing or improper resource existence verification',
    recommendation: 'Always verify resource existence before operations',
    impact: 'Contract could panic or behave unexpectedly if resources don\'t exist',
    remediation: {
      steps: [
        'Add existence checks before operations',
        'Handle non-existent resource cases gracefully',
        'Implement proper error handling'
      ],
      codeExample: `
if (!exists<CoinStore>(addr)) {
    abort ERROR_COIN_STORE_NOT_FOUND
};`
    }
  },
  {
    pattern: /as\s+u128|as\s+u64/g,
    type: 'Integer Overflow',
    severity: 'Critical',
    description: 'Potential integer overflow in numeric operations',
    recommendation: 'Use safe math operations and proper bounds checking',
    impact: 'Attackers could exploit numeric overflow to manipulate balances or bypass checks',
    remediation: {
      steps: [
        'Add overflow checks before operations',
        'Use safe math libraries',
        'Implement proper bounds validation'
      ],
      codeExample: `
// Add overflow check:
fun safe_add(a: u64, b: u64): u64 {
    assert!(a <= MAX_U64 - b, ERROR_OVERFLOW);
    a + b
}`
    }
  },
  {
    pattern: /signer::address_of/g,
    type: 'Signer Validation',
    severity: 'High',
    description: 'Potential signer address manipulation or improper validation',
    recommendation: 'Implement proper signer validation and authorization',
    impact: 'Attackers could impersonate other users or bypass authorization',
    remediation: {
      steps: [
        'Validate signer addresses',
        'Implement proper authorization checks',
        'Add event emission for tracking'
      ],
      codeExample: `
// Add proper validation:
public fun protected_operation(account: &signer) {
    let addr = signer::address_of(account);
    assert!(addr == @owner, ERROR_UNAUTHORIZED);
    // ... protected operation
}`
    }
  },
  {
    pattern: /vector::empty|vector::push_back/g,
    type: 'Vector Operation Safety',
    severity: 'Medium',
    description: 'Potential vector operation vulnerabilities',
    recommendation: 'Implement proper bounds checking and validation for vector operations',
    impact: 'Could lead to out-of-bounds access or resource exhaustion',
    remediation: {
      steps: [
        'Add length checks',
        'Implement maximum size limits',
        'Validate vector operations'
      ],
      codeExample: `
// Add bounds checking:
public fun safe_push(v: &mut vector<T>, item: T) {
    assert!(vector::length(v) < MAX_LENGTH, ERROR_VECTOR_FULL);
    vector::push_back(v, item);
}`
    }
  }
];

function calculateCodeMetrics(code: string) {
  const complexity = calculateComplexity(code);
  const maintainability = calculateMaintainability(code);
  const security = calculateSecurityScore(code);

  return {
    complexity,
    maintainability,
    security
  };
}

function calculateComplexity(code: string): number {
  let score = 100;
  
  // Deduct points for nested control structures
  const nestedControlStructures = (code.match(/\{[^}]*\{/g) || []).length;
  score -= nestedControlStructures * 5;

  // Deduct points for long functions
  const longFunctions = (code.match(/fun\s+\w+[^}]*}/g) || [])
    .filter(func => func.split('\n').length > 30).length;
  score -= longFunctions * 10;

  // Deduct for complex arithmetic operations
  const complexArithmetic = (code.match(/[+\-*/%]=|\+\+|--/g) || []).length;
  score -= complexArithmetic * 2;

  // Deduct for multiple resource types
  const resourceTypes = (code.match(/struct\s+\w+\s+has\s+key/g) || []).length;
  score -= Math.max(0, (resourceTypes - 2) * 5);

  return Math.max(0, score);
}

function calculateMaintainability(code: string): number {
  let score = 100;

  // Check for documentation
  if (!code.includes('///')) score -= 20;

  // Check for consistent naming
  const inconsistentNaming = (code.match(/[A-Z][a-z]+_[a-z]+/g) || []).length;
  score -= inconsistentNaming * 5;

  // Check for function length
  const longFunctions = (code.match(/fun\s+\w+[^}]*}/g) || [])
    .filter(func => func.split('\n').length > 50).length;
  score -= longFunctions * 10;

  // Check for proper error codes
  if (!code.includes('const ERROR_')) score -= 15;

  // Check for event emission
  if (!code.includes('emit_event')) score -= 10;

  return Math.max(0, score);
}

function calculateSecurityScore(code: string): number {
  let score = 100;

  // Check for unsafe patterns
  VULNERABILITY_PATTERNS.forEach(pattern => {
    const matches = (code.match(pattern.pattern) || []).length;
    switch (pattern.severity) {
      case 'Critical':
        score -= matches * 25;
        break;
      case 'High':
        score -= matches * 15;
        break;
      case 'Medium':
        score -= matches * 10;
        break;
      case 'Low':
        score -= matches * 5;
        break;
    }
  });

  // Check for access control
  if (!code.includes('has_role') && !code.includes('assert!(signer::address_of')) {
    score -= 20;
  }

  // Check for proper error handling
  if (!code.includes('abort') || !code.includes('ERROR_')) {
    score -= 15;
  }

  // Check for resource safety
  if (code.includes('key') && !code.includes('exists<')) {
    score -= 20;
  }

  return Math.max(0, score);
}

export function analyzeMoveCode(code: string): AnalysisResult {
  const vulnerabilities: Vulnerability[] = [];
  const lines = code.split('\n');
  
  // Analyze each line for vulnerabilities
  lines.forEach((line, index) => {
    VULNERABILITY_PATTERNS.forEach(pattern => {
      if (line.match(pattern.pattern)) {
        vulnerabilities.push({
          ...pattern,
          line: index + 1,
          codeSnippet: line.trim()
        });
      }
    });
  });

  // Calculate metrics
  const metrics = calculateCodeMetrics(code);

  // Calculate summary counts
  const summary = {
    totalIssues: vulnerabilities.length,
    criticalCount: vulnerabilities.filter(v => v.severity === 'Critical').length,
    highCount: vulnerabilities.filter(v => v.severity === 'High').length,
    mediumCount: vulnerabilities.filter(v => v.severity === 'Medium').length,
    lowCount: vulnerabilities.filter(v => v.severity === 'Low').length
  };

  // Get quality issues
  const qualityIssues = getQualityIssues(code);

  return {
    vulnerabilities,
    codeQuality: {
      score: metrics.security,
      issues: qualityIssues,
      metrics
    },
    summary,
    timestamp: format(new Date(), 'yyyy-MM-dd HH:mm:ss')
  };
}

function getQualityIssues(code: string): string[] {
  const issues: string[] = [];

  // Documentation checks
  if (!code.includes('///')) {
    issues.push('Missing documentation comments for functions and modules');
  }

  // Function length checks
  const functionMatches = code.match(/fun\s+\w+[^}]*}/g) || [];
  functionMatches.forEach(func => {
    const lines = func.split('\n').length;
    if (lines > 50) {
      issues.push('Function is too long (exceeds 50 lines) - consider breaking it down');
    }
  });

  // Error handling checks
  if (!code.includes('abort')) {
    issues.push('Consider implementing proper error handling with custom error codes');
  }

  // Resource handling checks
  if (code.includes('has key') && !code.includes('exists<')) {
    issues.push('Resource type defined but missing existence checks');
  }

  // Access control checks
  if (!code.includes('has_role') && code.includes('public')) {
    issues.push('Public functions found without role-based access control');
  }

  // Event emission checks
  if (!code.includes('emit_event')) {
    issues.push('Consider adding event emission for important state changes');
  }

  // Integer overflow checks
  if (code.includes('as u64') || code.includes('as u128')) {
    issues.push('Potential integer overflow risks detected - implement safe math operations');
  }

  // Vector operation checks
  if (code.includes('vector') && !code.includes('vector::length')) {
    issues.push('Vector operations found without proper length validation');
  }

  return issues;
}