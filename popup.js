// Main popup script for SecureClip extension
class SecureClipPopup {
  constructor() {
    this.apiUrl = 'http://localhost:5000/api';
    this.authToken = null;
    this.openaiKey = null;
    this.cryptoUtils = new CryptoUtils();
    this.validator = new ContentValidator();
    this.openaiService = null;
    this.scanHistory = [];
    this.stats = { blocked: 0, allowed: 0 };
    
    this.init();
  }

  async init() {
    // Load saved settings
    const settings = await chrome.storage.sync.get([
      'authToken', 'apiUrl', 'openaiKey', 'autoScan', 'aiScan'
    ]);
    
    if (settings.authToken) this.authToken = settings.authToken;
    if (settings.apiUrl) this.apiUrl = settings.apiUrl;
    if (settings.openaiKey) {
      this.openaiKey = settings.openaiKey;
      this.openaiService = new OpenAIService(this.openaiKey);
    }

    // Set UI values
    document.getElementById('apiUrl').value = this.apiUrl;
    document.getElementById('autoScan').checked = settings.autoScan !== false;
    document.getElementById('aiScan').checked = settings.aiScan !== false;

    // Check authentication status
    if (this.authToken) {
      await this.validateConnection();
    } else {
      this.showLoginForm();
    }

    this.setupEventListeners();
    await this.loadStats();
  }

  setupEventListeners() {
    // Connection
    document.getElementById('connectBtn').addEventListener('click', () => this.connect());
    document.getElementById('disconnectBtn').addEventListener('click', () => this.disconnect());
    
    // Dashboard
    document.getElementById('openDashboard').addEventListener('click', () => this.openDashboard());
    
    // Scanning
    document.getElementById('scanNow').addEventListener('click', () => this.scanClipboard());
    
    // Settings
    document.getElementById('autoScan').addEventListener('change', (e) => {
      chrome.storage.sync.set({ autoScan: e.target.checke‌d });
      this.notifyBackgroundScript('SETTINGS_CHANGED', { autoScan: e.target.checked });
    });
    
    document.getElementById('aiScan').addEventListener('change', (e) => {
      chrome.storage.sync.set({ aiScan: e.target.checked });
      this.notifyBackgroundScript('SETTINGS_CHANGED', { aiScan: e.target.checked });
    });
  }

  async connect() {
    const apiUrl = document.getElementById('apiUrl').value.trim();
    const authToken = document.getElementById('authToken').value.trim();
    const openaiKey = document.getElementById('openaiKey').value.trim();

    if (!apiUrl || !authToken) {
      this.showError('Please enter both API URL and Auth Token');
      return;
    }

    try {
      // Test connection
      const response = await fetch(`${apiUrl}/health`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });

      if (!response.ok) {
        throw new Error('Authentication failed');
      }

      // Save settings
      await chrome.storage.sync.set({
        apiUrl,
        authToken,
        openaiKey
      });

      this.apiUrl = apiUrl;
      this.authToken = authToken;
      this.openaiKey = openaiKey;
      
      if (openaiKey) {
        this.openaiService = new OpenAIService(openaiKey);
      }

      // Notify background script
      await this.notifyBackgroundScript('AUTH_UPDATED', {
        apiUrl,
        authToken,
        openaiKey
      });

      this.showDashboard();
      await this.loadRules();
      await this.loadStats();
      
      this.showSuccess('Connected successfully!');
    } catch (error) {
      this.showError(`Connection failed: ${error.message}`);
    }
  }

  async disconnect() {
    await chrome.storage.sync.clear();
    await this.notifyBackgroundScript('AUTH_CLEARED');
    
    this.authToken = null;
    this.openaiKey = null;
    this.openaiService = null;
    
    this.showLoginForm();
    this.showSuccess('Disconnected successfully');
  }

  async validateConnection() {
    try {
      const response = await fetch(`${this.apiUrl}/health`, {
        headers: { 'Authorization': `Bearer ${this.authToken}` }
      });

      if (response.ok) {
        this.showDashboard();
        await this.loadRules();
        return true;
      } else {
        this.showLoginForm();
        return false;
      }
    } catch (error) {
      console.error('Connection validation failed:', error);
      this.showLoginForm();
      return false;
    }
  }

  showLoginForm() {
    document.getElementById('loginForm').style.display = 'block';
    document.getElementById('dashboard').style.display = 'none';
    document.getElementById('status').className = 'status disconnected';
    document.getElementById('status').textContent = 'Not Connected';
  }

  showDashboard() {
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
    document.getElementById('status').className = 'status connected';
    document.getElementById('status').textContent = '🔒 Connected & Protected';
  }

  async loadStats() {
    try {
      const response = await fetch(`${this.apiUrl}/dashboard/stats`, {
        headers: { 'Authorization': `Bearer ${this.authToken}` }
      });

      if (response.ok) {
        const data = await response.json();
        this.stats = {
          blocked: data.blocked_today || 0,
          allowed: data.allowed_today || 0
        };
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }

    document.getElementById('blockedCount').textContent = this.stats.blocked;
    document.getElementById('allowedCount').textContent = this.stats.allowed;
  }

  async loadRules() {
    try {
      const response = await fetch(`${this.apiUrl}/domain-rules`, {
        headers: { 'Authorization': `Bearer ${this.authToken}` }
      });

      if (response.ok) {
        const data = await response.json();
        this.displayRules(data.rules || []);
      }
    } catch (error) {
      console.error('Failed to load rules:', error);
      document.getElementById('domainRules').innerHTML = 
        '<div class="rule-item"><span class="rule-domain">Failed to load rules</span></div>';
    }
  }

  displayRules(rules) {
    const container = document.getElementById('domainRules');
    
    if (rules.length === 0) {
      container.innerHTML = '<div class="rule-item"><span class="rule-domain">No rules configured</span></div>';
      return;
    }

    const displayRules = rules.slice(0, 3);
    const rulesHtml = displayRules.map(rule => `
      <div class="rule-item">
        <span class="rule-domain">${rule.domain}</span>
        <span class="rule-type ${rule.rule_type}">${rule.rule_type}</span>
      </div>
    `).join('');

    let extraRulesHtml = '';
    if (rules.length > 3) {
      extraRulesHtml = `
        <div class="rule-item">
          <span class="rule-domain">+${rules.length - 3} more rules</span>
        </div>
      `;
    }

    container.innerHTML = rulesHtml + extraRulesHtml;
  }

  async scanClipboard() {
    try {
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        this.showError('Clipboard is empty');
        return;
      }

      await this.performScan(text);
    } catch (error) {
      this.showError('Failed to read clipboard: ' + error.message);
    }
  }

  async performScan(content) {
    const scanBtn = document.getElementById('scanNow');
    const originalText = scanBtn.textContent;
    scanBtn.textContent = 'Scanning...';
    scanBtn.disabled = true;

    try {
      let result;
      const useAI = document.getElementById('aiScan').checked;

      if (useAI && this.openaiService) {
        // Use AI scanning
        try {
          const aiResult = await this.openaiService.scanForThreats(content);
          result = {
            timestamp: new Date().toLocaleString(),
            content: content.substring(0, 100) + (content.length > 100 ? '...' : ''),
            classification: aiResult.is_safe ? 'safe' : 'blocked',
            threats: aiResult.threats,
            action: aiResult.is_safe ? 'allowed' : 'blocked',
            aiAnalysis: aiResult.ai_analysis,
            method: 'AI'
          };
        } catch (aiError) {
          console.error('AI scanning failed, falling back to local:', aiError);
          result = await this.performLocalScan(content);
          result.method = 'Local (AI failed)';
        }
      } else {
        // Use local pattern matching
        result = await this.performLocalScan(content);
        result.method = 'Local';
      }

      // Add to history
      this.scanHistory.unshift(result);
      if (this.scanHistory.length > 10) this.scanHistory.pop();

      // Update stats
      if (result.classification === 'safe') {
        this.stats.allowed++;
      } else {
        this.stats.blocked++;
      }

      // Update UI
      this.updateScanHistory();
      this.updateStats();

      // Send to backend
      await this.reportScanResult(result, content);

      // Show notification
      if (result.classification !== 'safe') {
        this.showError(`Threat detected: ${result.threats[0] || 'Security concern'}`);
      } else {
        this.showSuccess('Content is safe');
      }

    } catch (error) {
      console.error('Scan error:', error);
      this.showError('Scan failed: ' + error.message);
    } finally {
      scanBtn.textContent = originalText;
      scanBtn.disabled = false;
    }
  }

  async performLocalScan(content) {
    // Simulate processing delay
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const validation = this.validator.validateContent(content);
    
    return {
      timestamp: new Date().toLocaleString(),
      content: content.substring(0, 100) + (content.length > 100 ? '...' : ''),
      classification: validation.is_safe ? 'safe' : (validation.risk_score > 7 ? 'blocked' : 'warning'),
      threats: validation.threats,
      action: validation.action,
      riskScore: validation.risk_score,
      contentType: validation.content_type
    };
  }

  async reportScanResult(result, content) {
    try {
      const contentHash = await this.cryptoUtils.generateHash(content);
      
      await fetch(`${this.apiUrl}/content/scan`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.authToken}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          content_hash: contentHash,
          classification: result.classification,
          threats: result.threats,
          ai_analysis: result.aiAnalysis,
          method: result.method,
          domain: window.location?.hostname || 'extension'
        })
      });
    } catch (error) {
      console.error('Failed to report scan result:', error);
    }
  }

  updateScanHistory() {
    const container = document.getElementById('scanHistory');
    
    if (this.scanHistory.length === 0) {
      container.innerHTML = '<div class="scan-item">No scans performed yet</div>';
      return;
    }

    const historyHtml = this.scanHistory.map(scan => `
      <div class="scan-item">
        <div class="scan-header">
          <span class="scan-status ${scan.classification}">${scan.action?.toUpperCase() || scan.classification.toUpperCase()}</span>
          <span class="scan-time">${scan.timestamp}</span>
        </div>
        <div class="scan-content">${scan.content}</div>
        ${scan.threats && scan.threats.length > 0 ? `
          <div class="scan-threats">
            ${scan.threats.slice(0, 2).map(threat => `<div>• ${threat}</div>`).join('')}
          </div>
        ` : ''}
      </div>
    `).join('');

    container.innerHTML = historyHtml;
  }

  updateStats() {
    document.getElementById('blockedCount').textContent = this.stats.blocked;
    document.getElementById('allowedCount').textContent = this.stats.allowed;
  }

  openDashboard() {
    chrome.tabs.create({
      url: 'http://localhost:3000','http://localhost:8080' // Your main dashboard URL
    });
  }

  async notifyBackgroundScript(type, data = {}) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type, ...data }, resolve);
    });
  }

  showSuccess(message) {
    this.showNotification(message, 'success');
  }

  showError(message) {
    this.showNotification(message, 'error');
  }

  showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      left: 50%;
      transform: translateX(-50%);
      padding: 8px 16px;
      border-radius: 4px;
      font-size: 12px;
      z-index: 1000;
      ${type === 'success' ? 'background: #10b981; color: white;' : 'background: #ef4444; color: white;'}
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 3000);
  }
}

// Initialize popup when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new SecureClipPopup();
});
