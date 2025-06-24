// OpenAI API integration for content analysis
class OpenAIService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://api.openai.com/v1';
  }

  setApiKey(apiKey) {
    this.apiKey = apiKey;
  }

  async analyzeContent(content) {
    if (!this.apiKey) {
      throw new Error('OpenAI API key not configured');
    }

    try {
      const response = await fetch(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [
            {
              role: 'system',
              content: `You are a security analyst. Analyze the provided content for potential security threats, sensitive information, or policy violations. 

              Respond with a JSON object containing:
              - is_safe: boolean (true if content is safe)
              - risk_score: number (0-10, where 10 is highest risk)
              - threats: array of detected threat descriptions
              - recommendations: array of recommended actions
              - summary: brief summary of the analysis
              - content_type: detected content type (text, code, url, credentials, etc.)

              Look for:
              - Personal information (SSN, credit cards, addresses)
              - Credentials (passwords, API keys, tokens)
              - Malicious URLs or code
              - Suspicious patterns
              - Corporate sensitive data`
            },
            {
              role: 'user',
              content: `Analyze this content: "${content.substring(0, 2000)}"`
            }
          ],
          temperature: 0.1,
          max_tokens: 1000,
        }),
      });

      if (!response.ok) {
        throw new Error(`OpenAI API error: ${response.statusText}`);
      }

      const data = await response.json();
      const analysisText = data.choices[0].message.content;
      
      try {
        return JSON.parse(analysisText);
      } catch (parseError) {
        // Fallback if JSON parsing fails
        return {
          is_safe: true,
          risk_score: 0,
          threats: ['Unable to parse AI analysis'],
          recommendations: ['Manual review recommended'],
          summary: analysisText.substring(0, 200),
          content_type: 'unknown'
        };
      }
    } catch (error) {
      console.error('OpenAI analysis error:', error);
      throw error;
    }
  }

  async scanForThreats(content) {
    const analysis = await this.analyzeContent(content);
    
    return {
      is_safe: analysis.is_safe,
      threats: analysis.threats || [],
      ai_analysis: {
        summary: analysis.summary,
        riskScore: analysis.risk_score,
        recommendations: analysis.recommendations || []
      }
    };
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = OpenAIService;
} else {
  window.OpenAIService = OpenAIService;
}