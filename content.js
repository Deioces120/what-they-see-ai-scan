// Enhanced content script for comprehensive website analysis
class ComprehensiveWebsiteAnalyzer {
  constructor() {
    this.trackingPixels = [];
    this.networkRequests = [];
    this.fingerprintingAttempts = [];
    this.socialMediaWidgets = [];
    this.suspiciousActivities = [];
    this.performanceMetrics = {};
    this.securityVulnerabilities = [];
    
    this.init();
  }

  init() {
    try {
      this.setupPerformanceMonitoring();
      this.detectTrackingPixels();
      this.detectSocialWidgets();
      this.monitorFingerprintingAttempts();
      this.analyzeLocalStorage();
      this.detectAdNetworks();
      this.analyzeWebGL();
      this.detectCryptominers();
      this.analyzeSecurityVulnerabilities();
      this.monitorNetworkActivity();
      this.analyzeDOMManipulation();
    } catch (error) {
      console.error('Content script initialization error:', error);
    }
  }

  setupPerformanceMonitoring() {
    try {
      // Monitor page load performance
      if (window.performance && window.performance.timing) {
        const timing = window.performance.timing;
        this.performanceMetrics = {
          domLoading: timing.domLoading - timing.navigationStart,
          domInteractive: timing.domInteractive - timing.navigationStart,
          domComplete: timing.domComplete - timing.navigationStart,
          loadEventEnd: timing.loadEventEnd - timing.navigationStart
        };
      }

      // Monitor resource loading
      if (window.performance && window.performance.getEntriesByType) {
        const resources = window.performance.getEntriesByType('resource');
        this.performanceMetrics.totalResources = resources.length;
        this.performanceMetrics.slowResources = resources.filter(r => r.duration > 1000).length;
      }
    } catch (error) {
      console.error('Performance monitoring error:', error);
    }
  }

  detectTrackingPixels() {
    try {
      // Detect 1x1 tracking pixels
      const images = document.querySelectorAll('img');
      images.forEach(img => {
        if (this.isTrackingPixel(img)) {
          this.trackingPixels.push({
            src: img.src,
            type: 'image_pixel',
            hidden: img.style.display === 'none' || img.style.visibility === 'hidden',
            dimensions: `${img.width}x${img.height}`
          });
        }
      });

      // Detect CSS background tracking
      this.detectCSSTrackingPixels();

      // Detect iframe tracking
      this.detectIframeTracking();

    } catch (error) {
      console.error('Tracking pixel detection error:', error);
    }
  }

  isTrackingPixel(img) {
    return (img.width <= 1 && img.height <= 1) ||
           (img.style.width === '1px' && img.style.height === '1px') ||
           (img.style.display === 'none' && img.src && img.src.length > 50) ||
           (img.style.visibility === 'hidden' && img.src);
  }

  detectCSSTrackingPixels() {
    try {
      const elements = document.querySelectorAll('*');
      elements.forEach(el => {
        const style = window.getComputedStyle(el);
        const bgImage = style.backgroundImage;
        
        if (bgImage && bgImage !== 'none') {
          const matches = bgImage.match(/url\(["']?([^"')]+)["']?\)/g);
          if (matches) {
            matches.forEach(match => {
              const url = match.match(/url\(["']?([^"')]+)["']?\)/)[1];
              if (this.isTrackingUrl(url)) {
                this.trackingPixels.push({
                  src: url,
                  type: 'css_background',
                  element: el.tagName.toLowerCase()
                });
              }
            });
          }
        }
      });
    } catch (error) {
      console.error('CSS tracking detection error:', error);
    }
  }

  detectIframeTracking() {
    try {
      const iframes = document.querySelectorAll('iframe');
      iframes.forEach(iframe => {
        if (iframe.width <= 1 && iframe.height <= 1 && iframe.src) {
          this.trackingPixels.push({
            src: iframe.src,
            type: 'iframe_pixel',
            dimensions: `${iframe.width}x${iframe.height}`
          });
        }
      });
    } catch (error) {
      console.error('Iframe tracking detection error:', error);
    }
  }

  detectSocialWidgets() {
    try {
      const socialPatterns = {
        facebook: ['facebook.com', 'fb.com', 'fbcdn.net'],
        twitter: ['twitter.com', 't.co', 'twimg.com'],
        instagram: ['instagram.com', 'cdninstagram.com'],
        linkedin: ['linkedin.com', 'licdn.com'],
        youtube: ['youtube.com', 'youtu.be', 'ytimg.com'],
        tiktok: ['tiktok.com', 'tiktokcdn.com'],
        pinterest: ['pinterest.com', 'pinimg.com']
      };

      // Check iframes
      const iframes = document.querySelectorAll('iframe[src]');
      iframes.forEach(iframe => {
        const src = iframe.src.toLowerCase();
        Object.entries(socialPatterns).forEach(([platform, domains]) => {
          if (domains.some(domain => src.includes(domain))) {
            this.socialMediaWidgets.push({
              platform: platform,
              type: 'iframe',
              src: iframe.src,
              element: iframe
            });
          }
        });
      });

      // Check script sources
      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        const src = script.src.toLowerCase();
        Object.entries(socialPatterns).forEach(([platform, domains]) => {
          if (domains.some(domain => src.includes(domain))) {
            this.socialMediaWidgets.push({
              platform: platform,
              type: 'script',
              src: script.src
            });
          }
        });
      });

      // Check common social media classes/IDs
      const socialSelectors = [
        '.fb-like', '.fb-share-button', '.facebook-share',
        '.twitter-share-button', '.tweet-button',
        '.linkedin-share-button', '.in-share-button',
        '.pinterest-share-button', '.pin-button',
        '[class*="social"]', '[id*="social"]',
        '[class*="share"]', '[id*="share"]'
      ];

      socialSelectors.forEach(selector => {
        try {
          const elements = document.querySelectorAll(selector);
          elements.forEach(el => {
            this.socialMediaWidgets.push({
              platform: this.detectPlatformFromElement(el),
              type: 'widget',
              element: el.tagName.toLowerCase(),
              classes: el.className
            });
          });
        } catch (e) {
          // Ignore selector errors
        }
      });

    } catch (error) {
      console.error('Social widget detection error:', error);
    }
  }

  monitorFingerprintingAttempts() {
    try {
      this.monitorCanvasFingerprinting();
      this.monitorWebGLFingerprinting();
      this.monitorAudioFingerprinting();
      this.monitorFontDetection();
      this.monitorBatteryAPI();
      this.monitorDeviceOrientation();
    } catch (error) {
      console.error('Fingerprinting monitoring error:', error);
    }
  }

  monitorCanvasFingerprinting() {
    try {
      const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      
      HTMLCanvasElement.prototype.toDataURL = function(...args) {
        this.analyzer?.fingerprintingAttempts.push({
          type: 'canvas_toDataURL',
          timestamp: Date.now(),
          stack: new Error().stack?.split('\n').slice(0, 3).join('\n')
        });
        return originalToDataURL.apply(this, args);
      };

      CanvasRenderingContext2D.prototype.getImageData = function(...args) {
        this.analyzer?.fingerprintingAttempts.push({
          type: 'canvas_getImageData',
          timestamp: Date.now(),
          parameters: args.length
        });
        return originalGetImageData.apply(this, args);
      };
    } catch (error) {
      console.error('Canvas fingerprinting monitoring error:', error);
    }
  }

  monitorWebGLFingerprinting() {
    try {
      const contexts = ['webgl', 'experimental-webgl', 'webgl2'];
      
      contexts.forEach(contextType => {
        const originalGetContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function(type, ...args) {
          if (type === contextType) {
            this.analyzer?.fingerprintingAttempts.push({
              type: 'webgl_context_creation',
              contextType: type,
              timestamp: Date.now()
            });
          }
          return originalGetContext.apply(this, [type, ...args]);
        };
      });

      // Monitor WebGL parameter access
      if (window.WebGLRenderingContext) {
        const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
          const sensitiveParams = [
            this.RENDERER, this.VENDOR, this.VERSION, this.SHADING_LANGUAGE_VERSION,
            this.UNMASKED_VENDOR_WEBGL, this.UNMASKED_RENDERER_WEBGL
          ];
          
          if (sensitiveParams.includes(parameter)) {
            this.analyzer?.fingerprintingAttempts.push({
              type: 'webgl_parameter_access',
              parameter: parameter,
              timestamp: Date.now()
            });
          }
          
          return originalGetParameter.call(this, parameter);
        };
      }
    } catch (error) {
      console.error('WebGL fingerprinting monitoring error:', error);
    }
  }

  monitorAudioFingerprinting() {
    try {
      if (window.AudioContext || window.webkitAudioContext) {
        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        const originalCreateOscillator = AudioContextClass.prototype.createOscillator;
        const originalCreateAnalyser = AudioContextClass.prototype.createAnalyser;
        
        AudioContextClass.prototype.createOscillator = function(...args) {
          this.analyzer?.fingerprintingAttempts.push({
            type: 'audio_oscillator_creation',
            timestamp: Date.now()
          });
          return originalCreateOscillator.apply(this, args);
        };

        AudioContextClass.prototype.createAnalyser = function(...args) {
          this.analyzer?.fingerprintingAttempts.push({
            type: 'audio_analyser_creation',
            timestamp: Date.now()
          });
          return originalCreateAnalyser.apply(this, args);
        };
      }
    } catch (error) {
      console.error('Audio fingerprinting monitoring error:', error);
    }
  }

  monitorFontDetection() {
    try {
      // Monitor dynamic style creation (common in font detection)
      const observer = new MutationObserver(mutations => {
        mutations.forEach(mutation => {
          if (mutation.type === 'childList') {
            mutation.addedNodes.forEach(node => {
              if (node.nodeType === 1 && node.tagName === 'STYLE') {
                const content = node.textContent || '';
                if (content.includes('font-family') || content.includes('@font-face')) {
                  this.fingerprintingAttempts.push({
                    type: 'font_detection_style',
                    timestamp: Date.now(),
                    contentLength: content.length
                  });
                }
              }
            });
          }
        });
      });

      observer.observe(document.head || document.documentElement, {
        childList: true,
        subtree: true
      });
    } catch (error) {
      console.error('Font detection monitoring error:', error);
    }
  }

  monitorBatteryAPI() {
    try {
      if (navigator.getBattery) {
        const originalGetBattery = navigator.getBattery;
        navigator.getBattery = function(...args) {
          this.analyzer?.fingerprintingAttempts.push({
            type: 'battery_api_access',
            timestamp: Date.now()
          });
          return originalGetBattery.apply(this, args);
        };
      }
    } catch (error) {
      console.error('Battery API monitoring error:', error);
    }
  }

  monitorDeviceOrientation() {
    try {
      if (window.DeviceOrientationEvent) {
        let orientationListenerCount = 0;
        const originalAddEventListener = window.addEventListener;
        
        window.addEventListener = function(type, listener, ...args) {
          if (type === 'deviceorientation' || type === 'devicemotion') {
            orientationListenerCount++;
            this.analyzer?.fingerprintingAttempts.push({
              type: 'device_orientation_listener',
              eventType: type,
              timestamp: Date.now(),
              totalListeners: orientationListenerCount
            });
          }
          return originalAddEventListener.apply(this, [type, listener, ...args]);
        };
      }
    } catch (error) {
      console.error('Device orientation monitoring error:', error);
    }
  }

  analyzeLocalStorage() {
    try {
      const storageAnalysis = {
        localStorage: { items: 0, trackingKeys: [], totalSize: 0 },
        sessionStorage: { items: 0, trackingKeys: [], totalSize: 0 },
        indexedDB: { available: false, databases: 0 },
        cookies: { count: 0, httpOnly: 0, secure: 0, sameSite: 0 }
      };

      // Analyze localStorage
      try {
        const localStorageData = { ...localStorage };
        storageAnalysis.localStorage.items = Object.keys(localStorageData).length;
        storageAnalysis.localStorage.trackingKeys = this.findTrackingKeys(localStorageData);
        storageAnalysis.localStorage.totalSize = JSON.stringify(localStorageData).length;
      } catch (e) {
        // localStorage not accessible
      }

      // Analyze sessionStorage
      try {
        const sessionStorageData = { ...sessionStorage };
        storageAnalysis.sessionStorage.items = Object.keys(sessionStorageData).length;