class AdvancedPrivacyScanner {
  constructor() {
    this.scanBtn = document.getElementById('scanBtn');
    this.loading = document.getElementById('loading');
    this.results = document.getElementById('results');
    this.tabs = document.getElementById('tabs');
    this.urlInfo = document.getElementById('url-info');
    this.currentTab = null;
    this.scanData = null;
    
    this.initEventListeners();
  }

  initEventListeners() {
    this.scanBtn.addEventListener('click', () => this.startComprehensiveScan());
    
    // Tab switching
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
    });
  }

  switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
      tab.classList.remove('active');
    });
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.remove('active');
    });
    document.getElementById(tabName).classList.add('active');
  }

  async startComprehensiveScan() {
    try {
      this.scanBtn.textContent = '🔄 AI Scanning in Progress...';
      this.scanBtn.classList.add('scanning');
      this.scanBtn.disabled = true;
      this.loading.style.display = 'block';
      this.results.style.display = 'none';
      this.tabs.classList.add('hidden');

      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tab;
      
      // Show current URL
      this.urlInfo.textContent = `Analyzing: ${tab.url}`;
      this.urlInfo.classList.remove('hidden');

      // Step 1: Basic website scan
      console.log('Starting basic website scan...');
      const basicScan = await this.performBasicScan(tab);
      
      // Step 2: Advanced privacy analysis
      console.log('Performing advanced privacy analysis...');
      const advancedScan = await this.performAdvancedScan(tab);
      
      // Step 3: Network traffic analysis
      console.log('Analyzing network traffic...');
      const networkAnalysis = await this.analyzeNetworkTraffic(tab);
      
      // Step 4: AI-powered threat detection
      console.log('Running AI threat detection...');
      const aiAnalysis = await this.performAIAnalysis({
        basic: basicScan,
        advanced: advancedScan,
        network: networkAnalysis,
        url: tab.url,
        tabId: tab.id
      });

      // Combine all data
      this.scanData = {
        basic: basicScan,
        advanced: advancedScan,
        network: networkAnalysis,
        ai: aiAnalysis,
        url: tab.url,
        timestamp: new Date().toISOString()
      };

      await this.displayResults();

    } catch (error) {
      console.error('Scan error:', error);
      this.showError(`Scan failed: ${error.message}\n\nDetails: ${error.stack}`);
    } finally {
      this.scanBtn.textContent = '🚀 Start AI Security Scan';
      this.scanBtn.classList.remove('scanning');
      this.scanBtn.disabled = false;
      this.loading.style.display = 'none';
    }
  }

  async performBasicScan(tab) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: this.basicWebsiteScan
      });
      
      if (!results || !results[0] || !results[0].result) {
        throw new Error('Failed to execute basic scan script');
      }
      
      return results[0].result;
    } catch (error) {
      console.error('Basic scan failed:', error);
      return this.getEmptyBasicScan();
    }
  }

  async performAdvancedScan(tab) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: this.advancedWebsiteScan
      });
      
      if (!results || !results[0] || !results[0].result) {
        throw new Error('Failed to execute advanced scan script');
      }
      
      return results[0].result;
    } catch (error) {
      console.error('Advanced scan failed:', error);
      return this.getEmptyAdvancedScan();
    }
  }

  async analyzeNetworkTraffic(tab) {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'getNetworkAnalysis',
        tabId: tab.id
      });
      
      return response || {
        tracking: [],
        ads: [],
        social: [],
        analytics: [],
        total: 0
      };
    } catch (error) {
      console.error('Network analysis failed:', error);
      return { tracking: [], ads: [], social: [], analytics: [], total: 0 };
    }
  }

  async performAIAnalysis(scanData) {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'performAIAnalysis',
        data: scanData
      });
      
      return response || this.getEmptyAIAnalysis();
    } catch (error) {
      console.error('AI analysis failed:', error);
      return this.getEmptyAIAnalysis();
    }
  }

  async displayResults() {
    if (!this.scanData) {
      throw new Error('No scan data available');
    }

    // Calculate overall security score
    const securityScore = this.calculateSecurityScore();
    
    // Update security score display
    document.querySelector('.score-number').textContent = securityScore;
    this.updateScoreColor(securityScore);
    
    // Populate all tabs
    this.populateOverview(securityScore);
    this.populateSecurity();
    this.populatePrivacy();
    this.populateThreats();
    this.populateAIAnalysis();
    
    // Show results
    this.results.style.display = 'block';
    this.tabs.classList.remove('hidden');
  }

  calculateSecurityScore() {
    if (!this.scanData) return 0;
    
    let score = 50; // Base score
    const { basic, advanced, network, url } = this.scanData;
    
    try {
      // HTTPS check
      if (url && url.startsWith('https://')) {
        score += 20;
      } else {
        score -= 30;
      }
      
      // Form security
      if (basic && basic.forms) {
        if (basic.forms.secure > 0 && basic.forms.insecure === 0) {
          score += 15;
        } else if (basic.forms.insecure > 0) {
          score -= 20;
        }
      }
      
      // Third-party scripts
      if (basic && basic.scripts && basic.scripts.thirdParty) {
        const thirdPartyCount = basic.scripts.thirdParty.length;
        if (thirdPartyCount < 5) {
          score += 10;
        } else if (thirdPartyCount > 15) {
          score -= 15;
        }
      }
      
      // Tracking cookies
      if (basic && basic.cookies) {
        if (basic.cookies.tracking < 3) {
          score += 10;
        } else {
          score -= 10;
        }
      }
      
      // Security headers
      if (basic && basic.security) {
        if (basic.security.csp) score += 15;
        if (basic.security.hsts) score += 10;
        if (basic.security.xFrame) score += 5;
      }
      
      // Advanced threats
      if (advanced) {
        score -= (advanced.trackingPixels || 0) * 5;
        score -= (advanced.fingerprintingAttempts || 0) * 8;
        score -= (advanced.cryptominers || []).length * 25;
      }
      
      // Network analysis
      if (network) {
        score -= (network.tracking || []).length * 3;
        score -= (network.ads || []).length * 2;
      }
      
    } catch (error) {
      console.error('Error calculating security score:', error);
    }
    
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  updateScoreColor(score) {
    const scoreElement = document.querySelector('.security-score');
    if (score >= 80) {
      scoreElement.style.background = 'linear-gradient(45deg, #4ecdc4, #44a08d)';
    } else if (score >= 60) {
      scoreElement.style.background = 'linear-gradient(45deg, #f7b733, #fc4a1a)';
    } else {
      scoreElement.style.background = 'linear-gradient(45deg, #ff4b4b, #c0392b)';
    }
  }

  populateOverview(score) {
    const content = document.getElementById('overview-content');
    const { basic, network, advanced } = this.scanData;
    
    const status = score >= 80 ? 'Secure' : score >= 60 ? 'Moderate Risk' : 'High Risk';
    const statusClass = score >= 80 ? 'safe' : score >= 60 ? 'info' : 'warning';
    
    const formsCount = basic?.forms?.total || 0;
    const scriptsCount = basic?.scripts?.thirdParty?.length || 0;
    const trackingCount = basic?.cookies?.tracking || 0;
    const analyticsCount = basic?.analytics?.tools?.length || 0;
    const networkRequests = network?.total || 0;
    
    content.innerHTML = `
      <div class="${statusClass}">
        <strong>Overall Status: ${status}</strong>
        <div style="font-size: 12px; margin-top: 5px;">
          Based on ${networkRequests} network requests analyzed
        </div>
      </div>
      
      <div class="metric">
        <span>Website Forms:</span>
        <span class="metric-value">${formsCount}</span>
      </div>
      
      <div class="metric">
        <span>Third-party Scripts:</span>
        <span class="metric-value">${scriptsCount}</span>
      </div>
      
      <div class="metric">
        <span>Tracking Cookies:</span>
        <span class="metric-value">${trackingCount}</span>
      </div>
      
      <div class="metric">
        <span>Analytics Tools:</span>
        <span class="metric-value">${analyticsCount}</span>
      </div>
      
      <div class="metric">
        <span>Tracking Pixels:</span>
        <span class="metric-value">${advanced?.trackingPixels || 0}</span>
      </div>
      
      <div class="metric">
        <span>Fingerprinting Attempts:</span>
        <span class="metric-value">${advanced?.fingerprintingAttempts || 0}</span>
      </div>
    `;
  }

  populateSecurity() {
    const content = document.getElementById('security-content');
    const { basic, url } = this.scanData;
    const isHttps = url && url.startsWith('https://');
    const security = basic?.security || {};
    
    content.innerHTML = `
      <div class="result-section">
        <div class="section-title">🔒 Connection Security</div>
        <div class="${isHttps ? 'safe' : 'warning'}">
          ${isHttps ? '✅ Website uses HTTPS encryption' : '⚠️ Website uses insecure HTTP connection'}
        </div>
        ${!isHttps ? '<div class="warning">🚨 Your data can be intercepted by attackers</div>' : ''}
      </div>

      <div class="result-section">
        <div class="section-title">📋 Form Security</div>
        <div class="section-content">
          <div class="metric">
            <span>Secure Forms:</span>
            <span class="metric-value">${basic?.forms?.secure || 0}</span>
          </div>
          <div class="metric">
            <span>Insecure Forms:</span>
            <span class="metric-value">${basic?.forms?.insecure || 0}</span>
          </div>
          ${(basic?.forms?.insecure || 0) > 0 ? 
            '<div class="warning">⚠️ Some forms send data insecurely</div>' : 
            '<div class="safe">✅ All forms are secure</div>'
          }
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">🛡️ Security Headers</div>
        <div class="section-content">
          <div class="metric">
            <span>Content Security Policy:</span>
            <span class="metric-value">${security.csp ? '✅ Enabled' : '❌ Missing'}</span>
          </div>
          <div class="metric">
            <span>Strict Transport Security:</span>
            <span class="metric-value">${security.hsts ? '✅ Enabled' : '❌ Missing'}</span>
          </div>
          <div class="metric">
            <span>X-Frame-Options:</span>
            <span class="metric-value">${security.xFrame ? '✅ Enabled' : '❌ Missing'}</span>
          </div>
          <div class="metric">
            <span>X-Content-Type-Options:</span>
            <span class="metric-value">${security.xContent ? '✅ Enabled' : '❌ Missing'}</span>
          </div>
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">🔍 Input Field Analysis</div>
        <div class="section-content">
          <div class="metric">
            <span>Password Fields:</span>
            <span class="metric-value">${basic?.inputs?.password || 0}</span>
          </div>
          <div class="metric">
            <span>Email Fields:</span>
            <span class="metric-value">${basic?.inputs?.email || 0}</span>
          </div>
          <div class="metric">
            <span>Personal Info Fields:</span>
            <span class="metric-value">${basic?.inputs?.personal || 0}</span>
          </div>
        </div>
      </div>
    `;
  }

  populatePrivacy() {
    const content = document.getElementById('privacy-content');
    const { basic, network, advanced } = this.scanData;
    
    content.innerHTML = `
      <div class="result-section">
        <div class="section-title">🍪 Cookies & Tracking</div>
        <div class="section-content">
          <div class="metric">
            <span>Total Cookies:</span>
            <span class="metric-value">${basic?.cookies?.total || 0}</span>
          </div>
          <div class="metric">
            <span>Tracking Cookies:</span>
            <span class="metric-value">${basic?.cookies?.tracking || 0}</span>
          </div>
          <div class="metric">
            <span>Third-party Cookies:</span>
            <span class="metric-value">${basic?.cookies?.thirdParty || 0}</span>
          </div>
          <div class="metric">
            <span>Tracking Pixels:</span>
            <span class="metric-value">${advanced?.trackingPixels || 0}</span>
          </div>
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">📊 Analytics & Monitoring</div>
        <div class="section-content">
          ${(basic?.analytics?.tools || []).length > 0 ? 
            (basic.analytics.tools.map(tool => `<div class="info">📈 ${tool} detected</div>`).join('')) :
            '<div class="safe">✅ No major analytics tools detected</div>'
          }
          <div class="metric">
            <span>Analytics Requests:</span>
            <span class="metric-value">${network?.analytics?.length || 0}</span>
          </div>
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">🌐 Third-party Connections</div>
        <div class="section-content">
          <div class="metric">
            <span>External Scripts:</span>
            <span class="metric-value">${basic?.scripts?.thirdParty?.length || 0}</span>
          </div>
          <div class="metric">
            <span>Ad Network Requests:</span>
            <span class="metric-value">${network?.ads?.length || 0}</span>
          </div>
          <div class="metric">
            <span>Social Media Widgets:</span>
            <span class="metric-value">${advanced?.socialWidgets || 0}</span>
          </div>
          ${(basic?.scripts?.thirdParty?.length || 0) > 10 ? 
            '<div class="warning">⚠️ High number of third-party scripts detected</div>' : 
            '<div class="safe">✅ Reasonable number of external connections</div>'
          }
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">🔍 Fingerprinting Detection</div>
        <div class="section-content">
          <div class="metric">
            <span>Canvas Fingerprinting:</span>
            <span class="metric-value">${advanced?.fingerprintingAttempts || 0} attempts</span>
          </div>
          <div class="metric">
            <span>WebGL Information:</span>
            <span class="metric-value">${advanced?.webgl ? 'Accessible' : 'Protected'}</span>
          </div>
          ${(advanced?.fingerprintingAttempts || 0) > 0 ? 
            '<div class="warning">⚠️ Website is attempting to fingerprint your device</div>' : 
            '<div class="safe">✅ No fingerprinting attempts detected</div>'
          }
        </div>
      </div>
    `;
  }

  populateThreats() {
    const content = document.getElementById('threats-content');
    const { ai } = this.scanData;
    const threats = ai?.threats || [];
    
    if (threats.length === 0) {
      content.innerHTML = `
        <div class="safe">
          ✅ <strong>No Major Threats Detected</strong>
          <p>Our AI analysis found no significant security or privacy threats on this website.</p>
        </div>
        <div class="info">
          <strong>General Recommendations:</strong>
          <ul style="margin: 10px 0; padding-left: 20px;">
            <li>Always verify the website URL before entering sensitive information</li>
            <li>Use strong, unique passwords for each website</li>
            <li>Enable two-factor authentication when available</li>
            <li>Keep your browser and extensions updated</li>
          </ul>
        </div>
      `;
      return;
    }

    const threatSections = threats.map(threat => {
      const severityClass = threat.severity === 'high' ? 'warning' : 
                           threat.severity === 'medium' ? 'info' : 'suggestion';
      const severityIcon = threat.severity === 'high' ? '🚨' : 
                          threat.severity === 'medium' ? '⚠️' : 'ℹ️';
      
      return `
        <div class="${severityClass}">
          ${severityIcon} <strong>${threat.type.replace(/_/g, ' ').toUpperCase()}</strong>
          <p>${threat.description}</p>
          ${threat.recommendation ? `<p><strong>Recommendation:</strong> ${threat.recommendation}</p>` : ''}
        </div>
      `;
    }).join('');

    content.innerHTML = threatSections;
  }

  populateAIAnalysis() {
    const content = document.getElementById('ai-content');
    const { ai, basic, network } = this.scanData;
    
    const privacyScore = ai?.privacyScore || 50;
    const riskLevel = ai?.riskLevel || 'unknown';
    const dataCollection = ai?.dataCollection || {};
    
    content.innerHTML = `
      <div class="result-section">
        <div class="section-title">🤖 AI Privacy Assessment</div>
        <div class="security-score" style="margin-bottom: 15px;">
          <div class="score-number">${privacyScore}</div>
          <div class="score-text">Privacy Score</div>
        </div>
        <div class="${riskLevel === 'low' ? 'safe' : riskLevel === 'medium' ? 'info' : 'warning'}">
          <strong>Risk Level: ${riskLevel.toUpperCase()}</strong>
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">📊 Data Collection Analysis</div>
        <div class="section-content">
          <div class="metric">
            <span>Personal Data Collection:</span>
            <span class="metric-value">${dataCollection.personal ? '⚠️ Detected' : '✅ None'}</span>
          </div>
          <div class="metric">
            <span>Financial Data Collection:</span>
            <span class="metric-value">${dataCollection.financial ? '⚠️ Detected' : '✅ None'}</span>
          </div>
          <div class="metric">
            <span>Behavioral Tracking:</span>
            <span class="metric-value">${dataCollection.behavioral ? '⚠️ Active' : '✅ None'}</span>
          </div>
          <div class="metric">
            <span>Location Tracking:</span>
            <span class="metric-value">${dataCollection.location ? '⚠️ Possible' : '✅ None'}</span>
          </div>
          <div class="metric">
            <span>Device Fingerprinting:</span>
            <span class="metric-value">${dataCollection.device ? '⚠️ Active' : '✅ None'}</span>
          </div>
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">💡 AI Recommendations</div>
        <div class="section-content">
          ${(ai?.recommendations || []).map(rec => `
            <div class="${rec.priority === 'high' ? 'warning' : rec.priority === 'medium' ? 'info' : 'suggestion'}">
              <strong>${rec.priority.toUpperCase()} PRIORITY:</strong> ${rec.action}
              <br><small>Reason: ${rec.reason}</small>
            </div>
          `).join('')}
        </div>
      </div>

      <div class="result-section">
        <div class="section-title">🔍 Technical Details</div>
        <div class="section-content">
          <div class="metric">
            <span>Total Network Requests:</span>
            <span class="metric-value">${network?.total || 0}</span>
          </div>
          <div class="metric">
            <span>Unique Third-party Domains:</span>
            <span class="metric-value">${[...new Set(basic?.scripts?.thirdParty || [])].length}</span>
          </div>
          <div class="metric">
            <span>Scan Timestamp:</span>
            <span class="metric-value">${new Date(this.scanData.timestamp).toLocaleString()}</span>
          </div>
        </div>
      </div>
    `;
  }

  showError(message) {
    this.results.innerHTML = `
      <div class="warning">
        <strong>❌ Scan Error</strong>
        <pre style="white-space: pre-wrap; margin-top: 10px; font-size: 12px;">${message}</pre>
        <div style="margin-top: 10px;">
          <button onclick="location.reload()" style="padding: 5px 10px; background: #ff4444; color: white; border: none; border-radius: 3px; cursor: pointer;">
            Retry Scan
          </button>
        </div>
      </div>
    `;
    this.results.style.display = 'block';
    this.tabs.classList.add('hidden');
  }

  getEmptyBasicScan() {
    return {
      forms: { total: 0, secure: 0, insecure: 0 },
      scripts: { total: 0, thirdParty: [], inline: 0 },
      cookies: { total: 0, tracking: 0, thirdParty: 0 },
      analytics: { tools: [] },
      security: { csp: false, xFrame: false, hsts: false, xContent: false },
      inputs: { password: 0, email: 0, personal: 0 }
    };
  }

  getEmptyAdvancedScan() {
    return {
      trackingPixels: 0,
      socialWidgets: 0,
      fingerprintingAttempts: 0,
      webgl: null,
      cryptominers: [],
      privacy_risk_score: 0
    };
  }

  getEmptyAIAnalysis() {
    return {
      privacyScore: 50,
      threats: [],
      recommendations: [{
        priority: 'low',
        action: 'Analysis incomplete - some features may not be available',
        reason: 'Scan error occurred'
      }],
      dataCollection: {
        personal: false,
        financial: false,
        behavioral: false,
        location: false,
        device: false
      },
      riskLevel: 'unknown'
    };
  }

  // This function runs in the webpage context for basic scanning
  basicWebsiteScan() {
    const results = {
      forms: { total: 0, secure: 0, insecure: 0 },
      scripts: { total: 0, thirdParty: [], inline: 0 },
      cookies: { total: 0, tracking: 0, thirdParty: 0 },
      analytics: { tools: [] },
      security: { csp: false, xFrame: false, hsts: false, xContent: false },
      inputs: { password: 0, email: 0, personal: 0 }
    };

    try {
      // Analyze forms
      const forms = document.querySelectorAll('form');
      results.forms.total = forms.length;
      
      forms.forEach(form => {
        const action = form.action || window.location.href;
        const isSecure = action.startsWith('https://') || action.startsWith('/') || !action;
        if (isSecure) {
          results.forms.secure++;
        } else {
          results.forms.insecure++;
        }
      });

      // Analyze scripts
      const scripts = document.scripts;
      results.scripts.total = scripts.length;
      
      Array.from(scripts).forEach(script => {
        if (script.src) {
          try {
            const scriptUrl = new URL(script.src, window.location.href);
            const currentDomain = window.location.hostname;
            if (scriptUrl.hostname !== currentDomain) {
              results.scripts.thirdParty.push(scriptUrl.hostname);
            }
          } catch (e) {
            // Invalid URL, treat as inline
            results.scripts.inline++;
          }
        } else {
          results.scripts.inline++;
        }
      });

      // Remove duplicate domains
      results.scripts.thirdParty = [...new Set(results.scripts.thirdParty)];

      // Analyze cookies
      const cookies = document.cookie.split(';').filter(c => c.trim());
      results.cookies.total = cookies.length;
      
      // Check for common tracking cookies
      const trackingPatterns = [
        '_ga', '_gid', '_gat', '_gtag', '_fbp', '_fbc', '_hjid', '_hjIncludedInSample',
        'utm_', '_clck', '_dc_', '__utma', '__utmb', '__utmc', '__utmz', '_pk_'
      ];
      
      cookies.forEach(cookie => {
        const name = cookie.split('=')[0].trim();
        if (trackingPatterns.some(pattern => name.includes(pattern))) {
          results.cookies.tracking++;
        }
      });

      // Estimate third-party cookies
      results.cookies.thirdParty = Math.min(results.cookies.total, Math.floor(results.scripts.thirdParty.length * 0.7));

      // Detect analytics tools
      const analyticsDetection = {
        'Google Analytics': () => {
          return window.gtag || window.ga || window.dataLayer || 
                 document.querySelector('script[src*="google-analytics"]') ||
                 document.querySelector('script[src*="googletagmanager"]');
        },
        'Facebook Pixel': () => {
          return window.fbq || document.querySelector('script[src*="facebook.net"]') ||
                 document.querySelector('script[src*="facebook.com/tr"]');
        },
        'Hotjar': () => {
          return window.hj || document.querySelector('script[src*="hotjar"]');
        },
        'Google Tag Manager': () => {
          return window.dataLayer || document.querySelector('script[src*="googletagmanager"]');
        },
        'Adobe Analytics': () => {
          return window.s_code || window.s_gi || document.querySelector('script[src*="omtrdc.net"]');
        },
        'Yandex Metrica': () => {
          return window.ym || document.querySelector('script[src*="mc.yandex"]');
        },
        'Mixpanel': () => {
          return window.mixpanel || document.querySelector('script[src*="mixpanel"]');
        },
        'Segment': () => {
          return window.analytics || document.querySelector('script[src*="segment"]');
        }
      };

      Object.entries(analyticsDetection).forEach(([name, detect]) => {
        try {
          if (detect()) {
            results.analytics.tools.push(name);
          }
        } catch (e) {
          // Ignore detection errors
        }
      });

      // Check security headers through meta tags
      const metaTags = document.querySelectorAll('meta[http-equiv]');
      metaTags.forEach(meta => {
        const httpEquiv = meta.getAttribute('http-equiv').toLowerCase();
        if (httpEquiv === 'content-security-policy') {
          results.security.csp = true;
        }
      });

      // Additional security checks
      results.security.hsts = document.location.protocol === 'https:';

      // Analyze input fields
      const inputs = document.querySelectorAll('input, textarea');
      inputs.forEach(input => {
        const type = (input.type || '').toLowerCase();
        const name = (input.name || '').toLowerCase();
        const placeholder = (input.placeholder || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        
        if (type === 'password') {
          results.inputs.password++;
        }
        
        if (type === 'email' || 
            name.includes('email') || 
            placeholder.includes('email') || 
            id.includes('email')) {
          results.inputs.email++;
        }
        
        if (name.includes('phone') || name.includes('address') || name.includes('name') ||
            placeholder.includes('phone') || placeholder.includes('address') || 
            placeholder.includes('name') || id.includes('phone') || id.includes('address')) {
          results.inputs.personal++;
        }
      });

    } catch (error) {
      console.error('Basic scan error:', error);
      // Return partial results even if there's an error
    }

    return results;
  }

  // Advanced scanning function
  advancedWebsiteScan() {
    const results = {
      trackingPixels: 0,
      socialWidgets: 0,
      fingerprintingAttempts: 0,
      webgl: null,
      cryptominers: [],
      storage: { localStorage: 0, sessionStorage: 0, indexedDB: 0 },
      adNetworks: [],
      suspiciousActivity: []
    };

    try {
      // Detect tracking pixels
      const images = document.querySelectorAll('img');
      images.forEach(img => {
        if ((img.width <= 1 && img.height <= 1) || 
            (img.style.width === '1px' && img.style.height === '1px') ||
            img.style.display === 'none' || img.style.visibility === 'hidden') {
          results.trackingPixels++;
        }
      });

      // Detect social media widgets
      const socialSelectors = [
        'iframe[src*="facebook.com"]', 'iframe[src*="twitter.com"]',
        'iframe[src*="instagram.com"]', 'iframe[src*="linkedin.com"]',
        'iframe[src*="youtube.com"]', 'iframe[src*="tiktok.com"]',
        '.fb-like', '.twitter-share-button', '.linkedin-share-button',
        '[class*="social"]', '[id*="social"]', '[class*="share"]'
      ];

      socialSelectors.forEach(selector => {
        try {
          const elements = document.querySelectorAll(selector);
          results.socialWidgets += elements.length;
        } catch (e) {
          // Ignore selector errors
        }
      });

      // Canvas fingerprinting detection
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      if (ctx) {
        // Check if canvas is being used for fingerprinting
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        let fingerprintAttempts = 0;
        
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
          fingerprintAttempts++;
          return originalToDataURL.apply(this, args);
        };
        
        // Trigger potential fingerprinting
        ctx.fillText('Fingerprint test', 2, 2);
        canvas.toDataURL();
        
        results.fingerprintingAttempts = fingerprintAttempts;
        
        // Restore original method
        HTMLCanvasElement.prototype.toDataURL = originalToDataURL;
      }

      // WebGL information
      try {
        const webglCanvas = document.createElement('canvas');
        const gl = webglCanvas.getContext('webgl') || webglCanvas.getContext('experimental-webgl');
        if (gl) {
          results.webgl = {
            renderer: gl.getParameter(gl.RENDERER),
            vendor: gl.getParameter(gl.VENDOR),
            version: gl.getParameter(gl.VERSION),
            extensions: gl.getSupportedExtensions()?.length || 0
          };
        }
      } catch (e) {
        results.webgl = null;
      }

      // Storage analysis
      try {
        results.storage.localStorage = localStorage.length;
      } catch (e) {
        results.storage.localStorage = 0;
      }
      
      try {
        results.storage.sessionStorage = sessionStorage.length;
      } catch (e) {
        results.storage.sessionStorage = 0;
      }

      // IndexedDB detection
      try {
        if ('indexedDB' in window) {
          results.storage.indexedDB = 1; // Just mark as present
        }
      } catch (e) {
        results.storage.indexedDB = 0;
      }

      // Detect ad networks
      const adNetworks = [
        'googlesyndication.com', 'doubleclick.net', 'googleadservices.com',
        'amazon-adsystem.com', 'facebook.com', 'outbrain.com', 'taboola.com',
        'criteo.com', 'adsystem.amazon.com', 'media.net'
      ];

      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        const src = script.src;
        adNetworks.forEach(network => {
          if (src.includes(network) && !results.adNetworks.includes(network)) {
            results.adNetworks.push(network);
          }
        });
      });

      // Detect potential cryptominers
      const minerPatterns = [
        'coinhive', 'jsecoin', 'coinerra', 'minergate', 'crypto-loot',
        'webminerpool', 'coin-have', 'minero', 'coinhive.com'
      ];

      const allScripts = document.querySelectorAll('script');
      allScripts.forEach(script => {
        const content = (script.textContent || script.src || '').toLowerCase();
        minerPatterns.forEach(pattern => {
          if (content.includes(pattern)) {
            results.cryptominers.push({
              type: 'potential_cryptominer',
              pattern: pattern,
              source: script.src || 'inline_script'
            });
          }
        });
      });

      // Check for suspicious activity
      if (results.scripts?.thirdParty?.length > 20) {
        results.suspiciousActivity.push('excessive_third_party_scripts');
      }
      
      if (results.trackingPixels > 5) {
        results.suspiciousActivity.push('excessive_tracking_pixels');
      }
      
      if (results.fingerprintingAttempts > 3) {
        results.suspiciousActivity.push('active_fingerprinting');
      }

    } catch (error) {
      console.error('Advanced scan error:', error);
    }

    return results;
  }
}

// Initialize scanner when popup opens
document.addEventListener('DOMContentLoaded', () => {
  new AdvancedPrivacyScanner();
});