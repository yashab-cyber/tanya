import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { scansAPI } from '../api/client'
import { Globe, Key, User, Loader } from 'lucide-react'

export default function NewScan() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [formData, setFormData] = useState({
    target_url: '',
    username: '',
    password: '',
  })

  const createScanMutation = useMutation({
    mutationFn: (data) => scansAPI.createScan(data),
    onSuccess: (response) => {
      queryClient.invalidateQueries(['scans'])
      navigate(`/scan/${response.data.id}`)
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    
    const payload = {
      target_url: formData.target_url,
    }

    if (formData.username && formData.password) {
      payload.username = formData.username
      payload.password = formData.password
    }

    createScanMutation.mutate(payload)
  }

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    })
  }

  return (
    <div className="max-w-2xl mx-auto">
      <div className="card">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Start New Security Scan</h2>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Target URL */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              <div className="flex items-center space-x-2">
                <Globe className="w-4 h-4" />
                <span>Target URL *</span>
              </div>
            </label>
            <input
              type="url"
              name="target_url"
              value={formData.target_url}
              onChange={handleChange}
              required
              placeholder="https://example.com"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
            />
            <p className="mt-1 text-sm text-gray-500">
              The URL of the application you want to scan
            </p>
          </div>

          {/* Authentication (Optional) */}
          <div className="border-t pt-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Authentication (Optional)
            </h3>
            <p className="text-sm text-gray-600 mb-4">
              Provide credentials if the application requires authentication
            </p>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  <div className="flex items-center space-x-2">
                    <User className="w-4 h-4" />
                    <span>Username</span>
                  </div>
                </label>
                <input
                  type="text"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="admin@example.com"
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  <div className="flex items-center space-x-2">
                    <Key className="w-4 h-4" />
                    <span>Password</span>
                  </div>
                </label>
                <input
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="••••••••"
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
            </div>
          </div>

          {/* Scan Features */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-semibold text-blue-900 mb-2">
              What will be scanned?
            </h4>
            <ul className="text-sm text-blue-800 space-y-1">
              <li>✓ Auto-crawl all pages and URLs</li>
              <li>✓ Discover and map all API endpoints</li>
              <li>✓ Extract and analyze JavaScript files</li>
              <li>✓ Identify all parameters and forms</li>
              <li>✓ Test for SQL Injection, XSS, CSRF vulnerabilities</li>
              <li>✓ Authentication and authorization testing</li>
              <li>✓ AI-powered vulnerability analysis</li>
            </ul>
          </div>

          {/* Error Message */}
          {createScanMutation.isError && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
              Error creating scan: {createScanMutation.error.message}
            </div>
          )}

          {/* Buttons */}
          <div className="flex space-x-4">
            <button
              type="submit"
              disabled={createScanMutation.isPending}
              className="btn btn-primary flex-1 flex items-center justify-center space-x-2"
            >
              {createScanMutation.isPending ? (
                <>
                  <Loader className="w-5 h-5 animate-spin" />
                  <span>Starting Scan...</span>
                </>
              ) : (
                <span>Start Scan</span>
              )}
            </button>

            <button
              type="button"
              onClick={() => navigate('/')}
              className="btn btn-secondary"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
