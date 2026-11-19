import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 60000, // 60s timeout for comprehensive NLP and AI analysis
});

// Interceptor to attach JWT token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('epa_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Interceptor for 401 handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      if (localStorage.getItem('epa_token')) {
        localStorage.removeItem('epa_token');
        // Dispatch custom session-expired event so UI can react gracefully
        window.dispatchEvent(new Event('epa_auth_expired'));
      }
    }
    return Promise.reject(error);
  }
);

export const authService = {
  login: async (email, password) => {
    const res = await api.post('/api/auth/login', { email, password });
    return res.data;
  },
  register: async (name, email, password) => {
    const res = await api.post('/api/auth/register', { name, email, password });
    return res.data;
  },
  getMe: async () => {
    const res = await api.get('/api/auth/me');
    return res.data;
  },
  updateMe: async (name) => {
    const res = await api.put('/api/auth/me', { name });
    return res.data;
  },
  changePassword: async (currentPassword, newPassword) => {
    const res = await api.post('/api/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
    return res.data;
  },
};

export const analyzerService = {
  analyzeEml: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/api/analyze/eml', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return res.data;
  },
  analyzeRaw: async (rawEmail) => {
    const res = await api.post('/api/analyze/raw', { raw_email: rawEmail });
    return res.data;
  },
  getSamples: async () => {
    const res = await api.get('/api/analyze/samples');
    return res.data;
  },
};

export const reportsService = {
  list: async (params = {}) => {
    const res = await api.get('/api/reports', { params });
    return res.data;
  },
  getById: async (reportId) => {
    const res = await api.get(`/api/reports/${reportId}`);
    return res.data;
  },
  delete: async (reportId) => {
    const res = await api.delete(`/api/reports/${reportId}`);
    return res.data;
  },
  exportJsonUrl: (reportId) => `${API_BASE_URL}/api/reports/${reportId}/json`,
};

export const gmailService = {
  getStatus: async () => {
    const res = await api.get('/api/gmail/status');
    return res.data;
  },
  getAuthUrl: async () => {
    const res = await api.get('/api/gmail/auth-url');
    return res.data;
  },
  callback: async (code, state) => {
    const res = await api.get('/api/gmail/callback', { params: { code, state } });
    return res.data;
  },
  getMessages: async (limit = 10) => {
    const res = await api.get('/api/gmail/messages', { params: { limit } });
    return res.data;
  },
  analyzeSelected: async (messageIds) => {
    const res = await api.post('/api/gmail/analyze', { message_ids: messageIds });
    return res.data;
  },
  disconnect: async () => {
    const res = await api.delete('/api/gmail/disconnect');
    return res.data;
  },
};

export const dashboardService = {
  getStats: async () => {
    const res = await api.get('/api/dashboard/stats');
    return res.data;
  },
};

export const settingsService = {
  get: async () => {
    const res = await api.get('/api/settings');
    return res.data;
  },
  update: async (data) => {
    const res = await api.put('/api/settings', data);
    return res.data;
  },
  getThreatIntel: async () => {
    const res = await api.get('/api/threat-intel');
    return res.data;
  },
  inspectUrl: async (url) => {
    const res = await api.post('/api/threat-intel/inspect-url', { url });
    return res.data;
  },
};

export const threatIntelService = {
  getThreats: async (params = {}) => {
    const res = await api.get('/api/threats', { params });
    return res.data;
  },
  getThreatById: async (incidentId) => {
    const res = await api.get(`/api/threats/${incidentId}`);
    return res.data;
  },
  getRecentThreats: async (limit = 10) => {
    const res = await api.get('/api/threats/recent', { params: { limit } });
    return res.data;
  },
  getStatistics: async () => {
    const res = await api.get('/api/threats/statistics');
    return res.data;
  },
  getSources: async () => {
    const res = await api.get('/api/threats/sources');
    return res.data;
  },
  getSyncStatus: async () => {
    const res = await api.get('/api/threats/sync-status');
    return res.data;
  },
  triggerSync: async () => {
    const res = await api.post('/api/threats/sync');
    return res.data;
  },
  getVulnerabilities: async (params = {}) => {
    const res = await api.get('/api/vulnerabilities', { params });
    return res.data;
  },
  getPhishingIntel: async (params = {}) => {
    const res = await api.get('/api/phishing-intelligence', { params });
    return res.data;
  },
};

export const systemService = {
  getHealth: async () => {
    const res = await api.get('/api/health');
    return res.data;
  },
};

export default api;
