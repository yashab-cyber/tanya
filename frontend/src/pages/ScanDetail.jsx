import { useQuery } from '@tanstack/react-query'
import { useParams, useNavigate } from 'react-router-dom'
import { scansAPI, testsAPI } from '../api/client'
import {
  Globe,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  ArrowLeft,
  Download,
  FileText,
} from 'lucide-react'

export default function ScanDetail() {
  const { id } = useParams()
  const navigate = useNavigate()

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scansAPI.getScan(id).then((res) => res.data),
    refetchInterval: (data) => (data?.status === 'running' ? 3000 : false),
  })

  const { data: results, isLoading: resultsLoading } = useQuery({
    queryKey: ['scan-results', id],
    queryFn: () => scansAPI.getScanResults(id).then((res) => res.data),
    enabled: scan?.status === 'completed',
  })

  const { data: summary } = useQuery({
    queryKey: ['test-summary', id],
    queryFn: () => testsAPI.getTestSummary(id).then((res) => res.data),
    enabled: scan?.status === 'completed',
  })

  const { data: vulnerabilities } = useQuery({
    queryKey: ['vulnerabilities', id],
    queryFn: () => testsAPI.getVulnerabilities(id).then((res) => res.data),
    enabled: scan?.status === 'completed',
  })

  if (scanLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  const getSeverityBadge = (severity) => {
    const classes = `badge badge-${severity?.toLowerCase() || 'info'}`
    return <span className={classes}>{severity || 'INFO'}</span>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/')}
          className="flex items-center space-x-2 text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft className="w-5 h-5" />
          <span>Back to Dashboard</span>
        </button>
      </div>

      {/* Scan Info */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center space-x-3">
              <Globe className="w-6 h-6 text-primary" />
              <h2 className="text-2xl font-bold text-gray-900">{scan?.target_url}</h2>
            </div>
            <p className="text-sm text-gray-600 mt-1">Scan ID: #{scan?.id}</p>
          </div>
          <div className="flex items-center space-x-2">
            {scan?.status === 'running' && (
              <Clock className="w-5 h-5 text-blue-500 animate-spin" />
            )}
            {scan?.status === 'completed' && (
              <CheckCircle className="w-5 h-5 text-green-500" />
            )}
            {scan?.status === 'failed' && <XCircle className="w-5 h-5 text-red-500" />}
            <span className={`badge status-${scan?.status}`}>
              {scan?.status?.toUpperCase()}
            </span>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6">
          <div className="bg-blue-50 rounded-lg p-4">
            <p className="text-sm text-blue-600 font-medium">URLs Discovered</p>
            <p className="text-2xl font-bold text-blue-900">{scan?.total_urls || 0}</p>
          </div>
          <div className="bg-purple-50 rounded-lg p-4">
            <p className="text-sm text-purple-600 font-medium">APIs Found</p>
            <p className="text-2xl font-bold text-purple-900">{scan?.total_apis || 0}</p>
          </div>
          <div className="bg-green-50 rounded-lg p-4">
            <p className="text-sm text-green-600 font-medium">JS Files</p>
            <p className="text-2xl font-bold text-green-900">
              {scan?.total_js_files || 0}
            </p>
          </div>
          <div className="bg-orange-50 rounded-lg p-4">
            <p className="text-sm text-orange-600 font-medium">Parameters</p>
            <p className="text-2xl font-bold text-orange-900">
              {scan?.total_parameters || 0}
            </p>
          </div>
        </div>
      </div>

      {/* Vulnerabilities Summary */}
      {scan?.status === 'completed' && summary && (
        <div className="card">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-bold text-gray-900">
              Vulnerability Summary
            </h3>
            <button className="btn btn-primary flex items-center space-x-2">
              <Download className="w-4 h-4" />
              <span>Download Report</span>
            </button>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <p className="text-sm text-red-600 font-medium">Critical</p>
              <p className="text-3xl font-bold text-red-900">{summary.critical || 0}</p>
            </div>
            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
              <p className="text-sm text-orange-600 font-medium">High</p>
              <p className="text-3xl font-bold text-orange-900">{summary.high || 0}</p>
            </div>
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <p className="text-sm text-yellow-600 font-medium">Medium</p>
              <p className="text-3xl font-bold text-yellow-900">{summary.medium || 0}</p>
            </div>
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <p className="text-sm text-blue-600 font-medium">Low</p>
              <p className="text-3xl font-bold text-blue-900">{summary.low || 0}</p>
            </div>
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
              <p className="text-sm text-gray-600 font-medium">Info</p>
              <p className="text-3xl font-bold text-gray-900">{summary.info || 0}</p>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerabilities List */}
      {vulnerabilities && vulnerabilities.length > 0 && (
        <div className="card">
          <h3 className="text-xl font-bold text-gray-900 mb-6">
            Vulnerabilities Found
          </h3>

          <div className="space-y-4">
            {vulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <AlertTriangle className="w-5 h-5 text-orange-500" />
                      <h4 className="font-semibold text-gray-900">
                        {vuln.test_type.replace(/_/g, ' ').toUpperCase()}
                      </h4>
                      {getSeverityBadge(vuln.severity)}
                    </div>
                    <p className="text-sm text-gray-600 mb-2">
                      <strong>Target:</strong> {vuln.target_url}
                    </p>
                    {vuln.payload && (
                      <div className="bg-gray-50 rounded p-2 mt-2">
                        <p className="text-xs text-gray-600 mb-1">Payload:</p>
                        <code className="text-xs text-gray-900">{vuln.payload}</code>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan Running Message */}
      {scan?.status === 'running' && (
        <div className="card bg-blue-50 border border-blue-200">
          <div className="flex items-center space-x-3">
            <Clock className="w-6 h-6 text-blue-600 animate-spin" />
            <div>
              <h3 className="font-semibold text-blue-900">Scan in Progress</h3>
              <p className="text-sm text-blue-700">
                The AI agents are analyzing your application. This may take several
                minutes...
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Scan Failed Message */}
      {scan?.status === 'failed' && (
        <div className="card bg-red-50 border border-red-200">
          <div className="flex items-center space-x-3">
            <XCircle className="w-6 h-6 text-red-600" />
            <div>
              <h3 className="font-semibold text-red-900">Scan Failed</h3>
              <p className="text-sm text-red-700">
                {scan.error_message || 'An error occurred during the scan.'}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
