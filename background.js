// Enhanced AI-powered privacy analysis background script
class EnhancedAIPrivacyAnalyzer {
  constructor() {
    this.scanResults = new Map();
    this.networkRequests = new Map();
    this.securityHeaders = new Map();
    this.privacyDatabase = this.initEnhancedPrivacyDatabase();
    this.aiAnalysisCache = new Map();
    
    this.initEventListeners();
  }

  initEventListeners() {
    // Monitor network requests for comprehensive analysis
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => this.analyzeOutgoingRequest(details),
      { urls: ["<all_urls>"] },
      ["requestHeaders"]
    );

    // Monitor response headers for security analysis
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => this.analyzeIncomingResponse(details),
      { urls: ["<all_urls>"] },
      ["responseHeaders"]
    );

    // Handle messages from popup and content scripts
    chrome.runtime.onMessage.addListener(
      (request, sender, sendResponse) => this.handleMessage(request, sender, sendResponse)
    );

    // Clean up data when tabs are closed or updated
    chrome.tabs.onUpdated.addListener(
      (tabId, changeInfo, tab) => this.onTabUpdated(tabId, changeInfo, tab)
    );

    chrome.tabs.onRemoved.addListener(
      (tabId) => this.cleanupTabData(tabId)
    );
  }

  initEnhancedPrivacyDatabase() {
    return {
      trackingDomains: [
        // Analytics
        'google-analytics.com', 'googletagmanager.com', 'ga.jspm.io',
        'hotjar.com', 'crazyegg.com', 'mouseflow.com', 'fullstory.com',
        'logrocket.com', 'amplitude.com', 'mixpanel.com', 'segment.com',
        
        // Social media tracking
        'facebook.com', 'facebook.net', 'fbcdn.net', 'instagram.com',
        'twitter.com', 'linkedin.com', 'pinterest.com', 'tiktok.com',
        
        // Ad networks
        'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
        'amazon-adsystem.com', 'media.amazon.com', 'adsystem.amazon.com',
        'outbrain.com', 'taboola.com', 'criteo.com', 'media.net',
        
        // Data brokers
        'scorecardresearch.com', 'comscore.com', 'quantserve.com',
        'bluekai.com', 'rlcdn.com', 'krxd.net', 'exelator.com',
        
        // CDNs often used for tracking
        'cdnjs.cloudflare.com', 'ajax.googleapis.com', 'code.jquery.com'
      ],
      
      maliciousDomains: [
        'coinhive.com', 'coin-hive.com', 'authedmine.com', 'crypto-loot.com',
        'webminerpool.com', 'jsecoin.com', 'minergate.com', 'deepminer.net'
      ],
      
      privacyRisks: {
        high: [
          'canvas_fingerprinting', 'webgl_fingerprinting', 'audio_fingerprinting',
          'font_fingerprinting', 'battery_api_access', 'device_orientation'
        ],
        medium: [
          'local_storage_tracking', 'cookie_syncing', 'pixel_tracking',
          'social_media_widgets', 'third_party_embeds'
        ],
        low: [
          'basic_analytics', 'necessary_cookies', 'cdn_resources'
        ]
      },
      
      securityThreats: {
        critical: [
          'mixed_content', 'insecure_forms', 'missing_csp', 'xss_vulnerability'
        ],
        high: [
          'missing_hsts', 'clickjacking_risk', 'outdated_libraries'
        ],
        medium: [
          'weak_cipher_suites', 'missing_security_headers', 'http_only_cookies'
        ]
      }
    };
  }

  analyzeOutgoingRequest(details) {
    const tabId = details.tabId;
    if (tabId === -1) return;

    if (!this.networkRequests.has(tabId)) {
      this.networkRequests.set(tabId, {
        tracking: [],
        ads: [],
        social: [],
        analytics: [],
        malicious: [],
        cdn: [],
        total: 0,
        domains: new Set(),
        startTime: Date.now()
      });
    }

    const requests = this.networkRequests.get(tabId);
    requests.total++;

    try {
      const url = new URL(details.url);
      const domain = url.hostname;
      requests.domains.add(domain);

      // Analyze headers for additional insights
      const headers = details.requestHeaders || [];
      const userAgent = headers.find(h => h.name.toLowerCase() === 'user-agent');
      const referer = headers.find(h => h.name.toLowerCase() === 'referer');

      const requestInfo = {
        domain: domain,
        url: details.url,
        method: details.method,
        timestamp: Date.now(),
        headers: headers.length,
        hasUserAgent: !!userAgent,
        hasReferer: !!referer,
        resourceType: details.type
      };

      // Categorize requests
      if (this.isTrackingDomain(domain)) {
        requests.tracking.push(requestInfo);
      }

      if (this.isAdNetwork(domain)) {
        requests.ads.push(requestInfo);
      }

      if (this.isSocialNetwork(domain)) {
        requests.social.push(requestInfo);
      }

      if (this.isMaliciousDomain(domain)) {
        requests.malicious.push(requestInfo);
      }

      if (this.isCDN(domain)) {
        requests.cdn.push(requestInfo);
      }

      // Detect analytics tools
      const analyticsTool = this.detectAnalyticsTool(domain, details.url);
      if (analyticsTool) {
        requests.analytics.push({
          tool: analyticsTool,
          domain: domain,
          url: details.url,
          timestamp: Date.now()
        });
      }

    } catch (error) {
      console.error('Error analyzing request:', error);
    }
  }

  analyzeIncomingResponse(details) {
    const tabId = details.tabId;
    if (tabId === -1 || details.type !== 'main_frame') return;

    const headers = details.responseHeaders || [];
    const securityAnalysis = this.analyzeSecurityHeaders(headers);
    
    if (!this.securityHeaders.has(tabId)) {
      this.securityHeaders.set(tabId, {});
    }
    
    this.securityHeaders.get(tabId).main_frame = securityAnalysis;
  }

  analyzeSecurityHeaders(headers) {
    const security = {
      csp: false,
      cspDetails: null,
      hsts: false,
      hstsDetails: null,
      xFrame: false,
      xContent: false,
      referrerPolicy: false,
      permissions: false,
      expectCT: false,
      serverInfo: null,
      poweredBy: null,
      securityScore: 0
    };

    headers.forEach(header => {
      const name = header.name.toLowerCase();
      const value = header.value;

      switch (name) {
        case 'content-security-policy':
          security.csp = true;
          security.cspDetails = this.analyzeCSP(value);
          security.securityScore += 25;
          break;
        case 'strict-transport-security':
          security.hsts = true;
          security.hstsDetails = this.analyzeHSTS(value);
          security.securityScore += 20;
          break;
        case 'x-frame-options':
          security.xFrame = true;
          security.securityScore += 15;
          break;
        case 'x-content-type-options':
          security.xContent = true;
          security.securityScore += 10;
          break;
        case 'referrer-policy':
          security.referrerPolicy = true;
          security.securityScore += 10;
          break;
        case 'permissions-policy':
        case 'feature-policy':
          security.permissions = true;
          security.securityScore += 10;
          break;
        case 'expect-ct':
          security.expectCT = true;
          security.securityScore += 5;
          break;
        case 'server':
          security.serverInfo = value;
          break;
        case 'x-powered-by':
          security.poweredBy = value;
          security.securityScore -= 5; // Information disclosure
          break;
      }
    });

    return security;
  }

  analyzeCSP(cspValue) {
    return {
      hasUnsafeInline: cspValue.includes("'unsafe-inline'"),
      hasUnsafeEval: cspValue.includes("'unsafe-eval'"),
      allowsDataUris: cspValue.includes('data:'),
      hasNonce: cspValue.includes('nonce-'),
      strictness: this.calculateCSPStrictness(cspValue)
    };
  }

  analyzeHSTS(hstsValue) {
    const maxAge = hstsValue.match(/max-age=(\d+)/);
    return {
      maxAge: maxAge ? parseInt(maxAge[1]) : 0,
      includeSubDomains: hstsValue.includes('includeSubDomains'),
      preload: hstsValue.includes('preload')
    };
  }

  calculateCSPStrictness(csp) {
    let strictness = 5; // Base strictness
    
    if (csp.includes("'unsafe-inline'")) strictness -= 2;
    if (csp.includes("'unsafe-eval'")) strictness -= 2;
    if (csp.includes("'self'")) strictness += 1;
    if (csp.includes('nonce-')) strictness += 2;
    if (csp.includes("'strict-dynamic'")) strictness += 1;
    
    return Math.max(0, Math.min(10, strictness));
  }

  async handleMessage(request, sender, sendResponse) {
    try {
      switch (request.action) {
        case 'getNetworkAnalysis':
          const tabId = sender.tab?.id || request.tabId;
          const networkData = this.networkRequests.get(tabId) || {
            tracking: [], ads: [], social: [], analytics: [], malicious: [], 
            cdn: [], total: 0, domains: new Set()
          };
          // Convert Set to array for JSON serialization
          networkData.domains = Array.from(networkData.domains);
          sendResponse(networkData);
          break;

        case 'performAIAnalysis':
          const aiAnalysis = await this.performEnhancedAIAnalysis(request.data);
          sendResponse(aiAnalysis);
          break;

        case 'getSecurityHeaders':
          const tabId2 = sender.tab?.id || request.tabId;
          const securityData = this.securityHeaders.get(tabId2) || {};
          sendResponse(securityData);
          break;

        default:
          sendResponse({ error: 'Unknown action' });
      }
    } catch (error) {
      console.error('Message handling error:', error);
      sendResponse({ error: error.message });
    }
  }

  async performEnhancedAIAnalysis(scanData) {
    try {
      const cacheKey = this.generateCacheKey(scanData);
      
      // Check cache first
      if (this.aiAnalysisCache.has(cacheKey)) {
        return this.aiAnalysisCache.get(cacheKey);
      }

      const analysis = {
        privacyScore: this.calculateAdvancedPrivacyScore(scanData),
        securityScore: this.calculateAdvancedSecurityScore(scanData),
        threats: this.identifyComprehensiveThreats(scanData),
        recommendations: this.generateIntelligentRecommendations(scanData),
        dataCollection: this.analyzeDataCollectionPatterns(scanData),
        riskLevel: 'unknown',
        fingerprinting: this.analyzeFingerprintingRisk(scanData),
        thirdPartyAnalysis: this.analyzeThirdPartyRisks(scanData),
        behaviorAnalysis: this.analyzeSiteBehavior(scanData)
      };

      analysis.riskLevel = this.determineOverallRiskLevel(analysis);
      
      // Cache the result
      this.aiAnalysisCache.set(cacheKey, analysis);
      
      return analysis;

    } catch (error) {
      console.error('AI Analysis error:', error);
      return this.getDefaultAIAnalysis();
    }
  }

  calculateAdvancedPrivacyScore(data) {
    let score = 100;
    const { basic, advanced, network } = data;

    try {
      // Network tracking impact
      if (network) {
        score -= (network.tracking?.length || 0) * 4;
        score -= (network.ads?.length || 0) * 3;
        score -= (network.malicious?.length || 0) * 20;
        score -= Math.max(0, (network.domains?.length || 0) - 10) * 2;
      }

      // Advanced tracking techniques
      if (advanced) {
        score -= (advanced.trackingPixels || 0) * 5;
        score -= (advanced.fingerprintingAttempts || 0) * 10;
        score -= (advanced.cryptominers?.length || 0) * 25;
        score -= Math.max(0, (advanced.storage?.localStorage || 0) - 5) * 2;
      }

      // Basic privacy violations
      if (basic) {
        score -= (basic.cookies?.tracking || 0) * 3;
        score -= Math.max(0, (basic.scripts?.thirdParty?.length || 0) - 5) * 2;
      }

      // HTTPS bonus
      if (data.url?.startsWith('https://')) {
        score += 5;
      } else {
        score -= 20;
      }

    } catch (error) {
      console.error('Privacy score calculation error:', error);
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  calculateAdvancedSecurityScore(data) {
    let score = 50;
    const { basic, network, url } = data;

    try {
      // HTTPS check
      if (url?.startsWith('https://')) {
        score += 30;
      } else {
        score -= 40;
      }

      // Security headers
      if (basic?.security) {
        if (basic.security.csp) score += 20;
        if (basic.security.hsts) score += 15;
        if (basic.security.xFrame) score += 10;
        if (basic.security.xContent) score += 5;
      }

      // Form security
      if (basic?.forms) {
        if (basic.forms.insecure > 0) score -= 25;
        if (basic.forms.secure > 0 && basic.forms.insecure === 0) score += 10;
      }

      // Malicious content
      if (network?.malicious?.length > 0) {
        score -= network.malicious.length * 30;
      }

      // Third-party risks
      const thirdPartyCount = basic?.scripts?.thirdParty?.length || 0;
      if (thirdPartyCount > 20) score -= 15;
      else if (thirdPartyCount < 5) score += 5;

    } catch (error) {
      console.error('Security score calculation error:', error);
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  identifyComprehensiveThreats(data) {
    const threats = [];
    const { basic, advanced, network, url } = data;

    try {
      // Security threats
      if (!url?.startsWith('https://')) {
        threats.push({
          type: 'insecure_connection',
          severity: 'critical',
          description: 'Website uses unencrypted HTTP connection, data can be intercepted',
          recommendation: 'Only enter sensitive information on HTTPS websites',
          category: 'security'
        });
      }

      if (basic?.forms?.insecure > 0) {
        threats.push({
          type: 'insecure_forms',
          severity: 'high',
          description: `${basic.forms.insecure} form(s) submit data insecurely`,
          recommendation: 'Avoid entering personal information in these forms',
          category: 'security'
        });
      }

      // Privacy threats
      if ((advanced?.fingerprintingAttempts || 0) > 0) {
        threats.push({
          type: 'active_fingerprinting',
          severity: 'high',
          description: 'Website is actively trying to fingerprint your device',
          recommendation: 'Use privacy-focused browser or incognito mode',
          category: 'privacy'
        });
      }

      if ((basic?.cookies?.tracking || 0) > 10) {
        threats.push({
          type: 'excessive_tracking',
          severity: 'medium',
          description: 'High number of tracking cookies detected',
          recommendation: 'Clear cookies regularly or use tracking protection',
          category: 'privacy'
        });
      }

      // Malicious content
      if (network?.malicious?.length > 0) {
        threats.push({
          type: 'malicious_content',
          severity: 'critical',
          description: 'Connections to known malicious domains detected',
          recommendation: 'Leave this website immediately and run antivirus scan',
          category: 'security'
        });
      }

      // Cryptomining
      if (advanced?.cryptominers?.length > 0) {
        threats.push({
          type: 'cryptomining',
          severity: 'high',
          description: 'Potential cryptocurrency mining scripts detected',
          recommendation: 'Close this website to prevent unauthorized CPU usage',
          category: 'performance'
        });
      }

      // Third-party risks
      const thirdPartyCount = basic?.scripts?.thirdParty?.length || 0;
      if (thirdPartyCount > 25) {
        threats.push({
          type: 'excessive_third_parties',
          severity: 'medium',
          description: `${thirdPartyCount} third-party scripts loading, potential privacy risk`,
          recommendation: 'Use ad blocker or script blocker for better privacy',
          category: 'privacy'
        });
      }

    } catch (error) {
      console.error('Threat identification error:', error);
    }

    return threats;
  }

  generateIntelligentRecommendations(data) {
    const recommendations = [];
    const { basic, advanced, network, url } = data;

    try {
      const privacyScore = this.calculateAdvancedPrivacyScore(data);
      const securityScore = this.calculateAdvancedSecurityScore(data);

      // Critical security recommendations
      if (!url?.startsWith('https://')) {
        recommendations.push({
          priority: 'critical',
          action: 'Do not enter any sensitive information on this website',
          reason: 'Unencrypted connection allows data interception',
          category: 'security'
        });
      }

      if (network?.malicious?.length > 0) {
        recommendations.push({
          priority: 'critical',
          action: 'Leave this website immediately and scan your device for malware',
          reason: 'Connections to known malicious domains detected',
          category: 'security'
        });
      }

      // High priority recommendations
      if ((advanced?.fingerprintingAttempts || 0) > 0) {
        recommendations.push({
          priority: 'high',
          action: 'Use incognito/private browsing mode',
          reason: 'Active device fingerprinting detected',
          category: 'privacy'
        });
      }

      if ((basic?.cookies?.tracking || 0) > 8) {
        recommendations.push({
          priority: 'high',
          action: 'Enable tracking protection in your browser',
          reason: 'Excessive tracking cookies found',
          category: 'privacy'
        });
      }

      // Medium priority recommendations
      if ((basic?.scripts?.thirdParty?.length || 0) > 15) {
        recommendations.push({
          priority: 'medium',
          action: 'Install an ad blocker or script blocker',
          reason: 'Many third-party scripts may compromise privacy',
          category: 'privacy'
        });
      }

      if (securityScore < 60) {
        recommendations.push({
          priority: 'medium',
          action: 'Avoid entering personal or financial information',
          reason: 'Poor website security practices detected',
          category: 'security'
        });
      }

      // General recommendations based on scores
      if (privacyScore < 50) {
        recommendations.push({
          priority: 'medium',
          action: 'Use VPN and clear cookies after visiting',
          reason: 'Poor privacy practices on this website',
          category: 'privacy'
        });
      }

      // Always include general security advice
      recommendations.push({
        priority: 'low',
        action: 'Verify website URL matches the expected domain',
        reason: 'General security practice to avoid phishing',
        category: 'security'
      });

      recommendations.push({
        priority: 'low',
        action: 'Keep your browser and extensions updated',
        reason: 'Updated software provides better security protection',
        category: 'security'
      });

    } catch (error) {
      console.error('Recommendation generation error:', error);
    }

    return recommendations;
  }

  analyzeDataCollectionPatterns(data) {
    const collection = {
      personal: false,
      financial: false,
      behavioral: false,
      location: false,
      device: false,
      biometric: false,
      details: {}
    };

    try {
      const { basic, advanced, network } = data;

      // Personal data indicators
      if (basic?.inputs) {
        if (basic.inputs.email > 0 || basic.inputs.personal > 0) {
          collection.personal = true;
          collection.details.personal = `${basic.inputs.email} email fields, ${basic.inputs.personal} personal info fields`;
        }

        if (basic.inputs.password > 0) {
          collection.financial = true;
          collection.details.financial = `${basic.inputs.password} password fields detected`;
        }
      }

      // Behavioral tracking
      if ((basic?.analytics?.tools?.length || 0) > 0 || (basic?.cookies?.tracking || 0) > 0) {
        collection.behavioral = true;
        collection.details.behavioral = `${basic?.analytics?.tools?.length || 0} analytics tools, ${basic?.cookies?.tracking || 0} tracking cookies`;
      }

      // Device fingerprinting
      if ((advanced?.fingerprintingAttempts || 0) > 0 || advanced?.webgl) {
        collection.device = true;
        collection.details.device = `Fingerprinting attempts: ${advanced?.fingerprintingAttempts || 0}`;
      }

      // Location tracking (heuristic)
      const locationIndicators = ['maps', 'location', 'geolocation', 'gps'];
      const hasLocationScripts = basic?.scripts?.thirdParty?.some(script => 
        locationIndicators.some(indicator => script.includes(indicator))
      );
      
      if (hasLocationScripts) {
        collection.location = true;
        collection.details.location = 'Location-related scripts detected';
      }

      // Biometric data (advanced heuristic)
      if (advanced?.webgl && (advanced?.fingerprintingAttempts || 0) > 3) {
        collection.biometric = true;
        collection.details.biometric = 'Advanced fingerprinting may include biometric markers';
      }

    } catch (error) {
      console.error('Data collection analysis error:', error);
    }

    return collection;
  }

  analyzeFingerprintingRisk(data) {
    const fingerprinting = {
      risk: 'low',
      techniques: [],
      score: 0
    };

    try {
      const { advanced } = data;

      if (advanced?.fingerprintingAttempts > 0) {
        fingerprinting.techniques.push('Canvas Fingerprinting');
        fingerprinting.score += advanced.fingerprintingAttempts * 10;
      }

      if (advanced?.webgl) {
        fingerprinting.techniques.push('WebGL Fingerprinting');
        fingerprinting.score += 15;
      }

      if ((advanced?.storage?.localStorage || 0) > 10) {
        fingerprinting.techniques.push('Storage-based Tracking');
        fingerprinting.score += 10;
      }

      // Determine risk level
      if (fingerprinting.score > 50) fingerprinting.risk = 'high';
      else if (fingerprinting.score > 20) fingerprinting.risk = 'medium';

    } catch (error) {
      console.error('Fingerprinting analysis error:', error);
    }

    return fingerprinting;
  }

  analyzeThirdPartyRisks(data) {
    const thirdParty = {
      totalDomains: 0,
      riskCategories: {
        tracking: 0,
        advertising: 0,
        social: 0,
        analytics: 0,
        unknown: 0
      },
      riskScore: 0
    };

    try {
      const { basic, network } = data;

      thirdParty.totalDomains = basic?.scripts?.thirdParty?.length || 0;
      
      if (network) {
        thirdParty.riskCategories.tracking = network.tracking?.length || 0;
        thirdParty.riskCategories.advertising = network.ads?.length || 0;
        thirdParty.riskCategories.social = network.social?.length || 0;
        thirdParty.riskCategories.analytics = network.analytics?.length || 0;
      }

      thirdParty.riskCategories.unknown = Math.max(0, 
        thirdParty.totalDomains - 
        Object.values(thirdParty.riskCategories).reduce((a, b) => a + b, 0)
      );

      // Calculate risk score
      thirdParty.riskScore = 
        thirdParty.riskCategories.tracking * 5 +
        thirdParty.riskCategories.advertising * 3 +
        thirdParty.riskCategories.social * 2 +
        thirdParty.riskCategories.analytics * 2 +
        thirdParty.riskCategories.unknown * 1;

    } catch (error) {
      console.error('Third-party analysis error:', error);
    }

    return thirdParty;
  }

  analyzeSiteBehavior(data) {
    const behavior = {
      loadingPattern: 'normal',
      resourceIntensive: false,
      suspiciousActivity: [],
      performanceImpact: 'low'
    };

    try {
      const { basic, network, advanced } = data;

      // Analyze loading patterns
      const totalRequests = network?.total || 0;
      const thirdPartyCount = basic?.scripts?.thirdParty?.length || 0;
      
      if (totalRequests > 100) {
        behavior.loadingPattern = 'heavy';
        behavior.resourceIntensive = true;
      } else if (totalRequests > 50) {
        behavior.loadingPattern = 'moderate';
      }

      // Detect suspicious activities
      if ((advanced?.cryptominers?.length || 0) > 0) {
        behavior.suspiciousActivity.push('cryptocurrency_mining');
      }

      if ((advanced?.fingerprintingAttempts || 0) > 5) {
        behavior.suspiciousActivity.push('aggressive_fingerprinting');
      }

      if (thirdPartyCount > 30) {
        behavior.suspiciousActivity.push('excessive_third_party_loading');
      }

      // Performance impact assessment
      if (behavior.resourceIntensive || behavior.suspiciousActivity.length > 0) {
        behavior.performanceImpact = thirdPartyCount > 20 ? 'high' : 'medium';
      }

    } catch (error) {
      console.error('Behavior analysis error:', error);
    }

    return behavior;
  }

  determineOverallRiskLevel(analysis) {
    try {
      const { privacyScore, securityScore, threats } = analysis;
      
      const criticalThreats = threats.filter(t => t.severity === 'critical').length;
      const highThreats = threats.filter(t => t.severity === 'high').length;
      
      if (criticalThreats > 0 || securityScore < 30) return 'critical';
      if (highThreats > 0 || securityScore < 50 || privacyScore < 40) return 'high';
      if (securityScore < 70 || privacyScore < 60) return 'medium';
      
      return 'low';
    } catch (error) {
      return 'unknown';
    }
  }

  // Helper methods
  isTrackingDomain(domain) {
    return this.privacyDatabase.trackingDomains.some(tracker => 
      domain.includes(tracker) || tracker.includes(domain)
    );
  }

  isAdNetwork(domain) {
    const adNetworks = [
      'googlesyndication.com', 'doubleclick.net', 'googleadservices.com',
      'amazon-adsystem.com', 'outbrain.com', 'taboola.com', 'criteo.com',
      'media.net', 'adsystem.amazon.com', 'facebook.com'
    ];
    return adNetworks.some(network => domain.includes(network));
  }

  isSocialNetwork(domain) {
    const socialNetworks = [
      'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
      'pinterest.com', 'tiktok.com', 'youtube.com', 'snapchat.com'
    ];
    return socialNetworks.some(social => domain.includes(social));
  }

  isMaliciousDomain(domain) {
    return this.privacyDatabase.maliciousDomains.some(malicious => 
      domain.includes(malicious)
    );
  }

  isCDN(domain) {
    const cdns = [
      'cloudflare.com', 'amazonaws.com', 'cloudfront.net', 'jsdelivr.net',
      'unpkg.com', 'cdnjs.cloudflare.com', 'googleapis.com'
    ];
    return cdns.some(cdn => domain.includes(cdn));
  }

  detectAnalyticsTool(domain, url) {
    const tools = {
      'Google Analytics': ['google-analytics.com', 'googletagmanager.com'],
      'Facebook Pixel': ['facebook.com', 'facebook.net'],
      'Hotjar': ['hotjar.com'],
      'Mixpanel': ['mixpanel.com'],
      'Segment': ['segment.com', 'segment.io'],
      'Adobe Analytics': ['omtrdc.net', 'demdex.net'],
      'Yandex Metrica': ['mc.yandex.ru'],
      'Crazy Egg': ['crazyegg.com'],
      'Full Story': ['fullstory.com']
    };

    for (const [tool, domains] of Object.entries(tools)) {
      if (domains.some(d => domain.includes(d))) {
        return tool;
      }
    }
    return null;
  }

  generateCacheKey(scanData) {
    try {
      const key = JSON.stringify({
        url: scanData.url,
        formsCount: scanData.basic?.forms?.total || 0,
        scriptsCount: scanData.basic?.scripts?.total || 0,
        cookiesCount: scanData.basic?.cookies?.total || 0
      });
      return btoa(key).substring(0, 32);
    } catch (error) {
      return Math.random().toString(36).substring(7);
    }
  }

  getDefaultAIAnalysis() {
    return {
      privacyScore: 50,
      securityScore: 50,
      threats: [{
        type: 'analysis_incomplete',
        severity: 'medium',
        description: 'AI analysis could not be completed due to technical limitations',
        recommendation: 'Manual review recommended for sensitive activities',
        category: 'system'
      }],
      recommendations: [{
        priority: 'medium',
        action: 'Exercise caution when entering sensitive information',
        reason: 'Complete security analysis unavailable',
        category: 'general'
      }],
      dataCollection: {
        personal: false,
        financial: false,
        behavioral: false,
        location: false,
        device: false,
        biometric: false,
        details: {}
      },
      riskLevel: 'unknown',
      fingerprinting: { risk: 'unknown', techniques: [], score: 0 },
      thirdPartyAnalysis: { totalDomains: 0, riskCategories: {}, riskScore: 0 },
      behaviorAnalysis: { loadingPattern: 'unknown', suspiciousActivity: [] }
    };
  }

  onTabUpdated(tabId, changeInfo, tab) {
    if (changeInfo.status === 'loading') {
      this.cleanupTabData(tabId);
    }
  }

  cleanupTabData(tabId) {
    this.networkRequests.delete(tabId);
    this.securityHeaders.delete(tabId);
    this.scanResults.delete(tabId);
  }
}

// Initialize the enhanced AI analyzer
const enhancedAIAnalyzer = new EnhancedAIPrivacyAnalyzer();