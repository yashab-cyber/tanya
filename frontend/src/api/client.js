import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add token to requests if available
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    console.error('Request error:', error)
    return Promise.reject(error)
  }
)

// Response interceptor for better error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', {
      message: error.message,
      response: error.response?.data,
      status: error.response?.status,
      config: {
        url: error.config?.url,
        method: error.config?.method,
      }
    })
    
    if (error.response) {
      // Server responded with error status
      const message = error.response.data?.detail || error.response.data?.message || 'Server error'
      error.message = message
    } else if (error.request) {
      // Request made but no response received
      error.message = 'Cannot connect to server. Please check if the backend is running.'
    }
    
    return Promise.reject(error)
  }
)

// Scans API
export const scansAPI = {
  createScan: (data) => api.post('/api/v1/scans/', data),
  listScans: (params) => api.get('/api/v1/scans/', { params }),
  getScan: (id) => api.get(`/api/v1/scans/${id}`),
  getScanResults: (id) => api.get(`/api/v1/scans/${id}/results`),
  deleteScan: (id) => api.delete(`/api/v1/scans/${id}`),
}

// Tests API
export const testsAPI = {
  getTestResults: (scanId, params) => api.get(`/api/v1/tests/scan/${scanId}`, { params }),
  getVulnerabilities: (scanId) => api.get(`/api/v1/tests/scan/${scanId}/vulnerabilities`),
  getTestSummary: (scanId) => api.get(`/api/v1/tests/scan/${scanId}/summary`),
}

// Reports API
export const reportsAPI = {
  createReport: (data) => api.post('/api/v1/reports/', data),
  getReports: (scanId) => api.get(`/api/v1/reports/scan/${scanId}`),
}

// Auth API
export const authAPI = {
  register: (data) => api.post('/api/v1/auth/register', data),
  login: (data) => api.post('/api/v1/auth/token', data, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  }),
  getCurrentUser: () => api.get('/api/v1/auth/me'),
}

export default api
