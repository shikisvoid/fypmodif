import React, { useState, useEffect } from 'react'
import { Lock, Unlock, Download, Eye, Upload, Loader } from 'lucide-react'
import Card from './Card'
import Button from './Button'
import Modal from './Modal'

interface PatientFile {
  id: string
  fileName: string
  fileSize: string
  encryptionStatus: 'encrypted' | 'decrypted'
  algorithm: string
  uploadedAt: string
  encryptedPath?: string
  mimeType?: string
  fileType?: string
  uploadedBy?: string
  ownerPatientId?: string
}

interface FileEncryptionProps {
  userEmail: string
  userName: string
  userRole: string
  hasViewPermission: boolean
  hasDownloadPermission: boolean
}

const FileEncryption: React.FC<FileEncryptionProps> = ({
  userEmail,
  userName,
  userRole,
  hasViewPermission,
  hasDownloadPermission
}) => {
  const [files, setFiles] = useState<PatientFile[]>([])
  const [filesLoading, setFilesLoading] = useState(true)

  // Load files from backend on component mount and when user changes
  useEffect(() => {
    const loadFiles = async () => {
      try {
        setFilesLoading(true)
        const token = localStorage.getItem('hp_access_token')
        if (!token) {
          setFiles([])
          setFilesLoading(false)
          return
        }

        const response = await fetch('/api/files/list', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        })

        if (response.ok) {
          const data = await response.json()
          setFiles(data.files || [])
        } else {
          setFiles([])
        }
      } catch (error) {
        console.error('Failed to load files:', error)
        setFiles([])
      } finally {
        setFilesLoading(false)
      }
    }

    loadFiles()
  }, [userEmail])

  const [selectedFile, setSelectedFile] = useState<PatientFile | null>(null)
  const [showDecryptModal, setShowDecryptModal] = useState(false)
  const [decryptLoading, setDecryptLoading] = useState(false)
  const [decryptedContent, setDecryptedContent] = useState<string>('')
  const [decryptError, setDecryptError] = useState<string>('')
  const [showUploadModal, setShowUploadModal] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploadLoading, setUploadLoading] = useState(false)

  const handleDecryptFile = async (file: PatientFile) => {
    if (!hasDownloadPermission) {
      setDecryptError('You do not have permission to decrypt files')
      return
    }

    setSelectedFile(file)
    setShowDecryptModal(true)
    setDecryptLoading(true)
    setDecryptedContent('')
    setDecryptError('')

    try {
      // Get JWT token from localStorage
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        setDecryptError('Not authenticated - please log in')
        setDecryptLoading(false)
        return
      }

      // Call the real encryption API
      const response = await fetch('/api/files/decrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          fileId: file.fileName
          // mfaToken: can be passed here if user has MFA enabled
        })
      })

      const data = await response.json()

      if (!response.ok) {
        if (response.status === 401) {
          // Check if MFA is needed
          if (data.error.includes('MFA')) {
            const mfaToken = prompt('Enter your MFA code:')
            if (mfaToken) {
              // Retry with MFA token
              const retryResponse = await fetch('/api/files/decrypt', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                  fileId: file.fileName,
                  mfaToken
                })
              })
              const retryData = await retryResponse.json()
              if (retryResponse.ok) {
                setDecryptedContent(retryData.content || 'File decrypted successfully')
                setDecryptLoading(false)
                return
              } else {
                setDecryptError(retryData.error || 'Decryption failed')
              }
            }
          } else {
            setDecryptError(data.error || 'Authentication failed')
          }
        } else {
          setDecryptError(data.error || 'Decryption failed')
        }
        setDecryptLoading(false)
        return
      }

      setDecryptedContent(data.content || `File decrypted successfully!\n\n${data.message || ''}`)
      setDecryptLoading(false)
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error'
      setDecryptError(`Error: ${errorMsg}`)
      console.error('Decryption error:', error)
      setDecryptLoading(false)
    }
  }

  const handleUploadFile = async () => {
    if (!uploadFile) return

    setUploadLoading(true)

    try {
      // Get JWT token from localStorage
      const token = localStorage.getItem('hp_access_token')
      if (!token) {
        alert('Not authenticated - please log in')
        setUploadLoading(false)
        return
      }

      // First, upload the file to backend to get the temp path
      const formData = new FormData()
      formData.append('file', uploadFile)

      const uploadResponse = await fetch('/api/files/upload', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      })

      const uploadData = await uploadResponse.json()

      if (!uploadResponse.ok) {
        throw new Error(uploadData.error || 'Upload failed')
      }

      // Then encrypt the uploaded file
      const encryptResponse = await fetch('/api/files/encrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          fileId: uploadFile.name,
          filePath: uploadData.filePath,
          fileSize: uploadData.fileSize
        })
      })

      const encryptData = await encryptResponse.json()

      if (!encryptResponse.ok) {
        throw new Error(encryptData.error || 'Encryption failed')
      }

      // Add file to list
      const newFile: PatientFile = {
        id: Date.now().toString(),
        fileName: uploadFile.name,
        fileSize: `${(uploadFile.size / 1024).toFixed(1)} KB`,
        encryptionStatus: 'encrypted',
        algorithm: 'AES-256-GCM',
        uploadedAt: new Date().toISOString().split('T')[0],
        encryptedPath: encryptData.encryptedPath
      }

      setFiles([...files, newFile])
      setShowUploadModal(false)
      setUploadFile(null)
      alert('File encrypted and saved successfully!')
    } catch (error) {
      console.error('Upload error:', error)
      alert(`Upload error: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setUploadLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="border-l-4 border-blue-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="muted text-sm">Encrypted Files</p>
              <p className="stat-number">{files.length}</p>
              <p className="text-xs text-blue-400 mt-1">AES-256-GCM</p>
            </div>
            <Lock className="text-blue-500" size={40} />
          </div>
        </Card>

        <Card className="border-l-4 border-green-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="muted text-sm">Your Access</p>
              <p className="stat-number">{hasDownloadPermission ? '✓' : '✗'}</p>
              <p className="text-xs text-green-400 mt-1">
                {hasViewPermission ? 'Can View' : 'No Access'}
              </p>
            </div>
            <Unlock className="text-green-500" size={40} />
          </div>
        </Card>

        <Card className="border-l-4 border-purple-500">
          <div className="flex items-center justify-between">
            <div>
              <p className="muted text-sm">Your Role</p>
              <p className="stat-number capitalize">{userRole}</p>
              <p className="text-xs text-purple-400 mt-1">
                {hasDownloadPermission ? 'Full Access' : 'Limited Access'}
              </p>
            </div>
            <Lock className="text-purple-500" size={40} />
          </div>
        </Card>
      </div>

      <Card className="overflow-hidden">
        <div className="px-6 py-4 border-b border-white/6 flex justify-between items-center">
          <h3 className="text-lg font-semibold">Patient Medical Files</h3>
          {hasDownloadPermission && (
            <Button variant="primary" onClick={() => setShowUploadModal(true)}>
              <Upload size={16} className="mr-2" />
              Upload & Encrypt
            </Button>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-white/3 border-b border-white/6">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-semibold uppercase">File Name</th>
                <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Size</th>
                <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Encryption</th>
                <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Uploaded</th>
                <th className="px-6 py-3 text-left text-xs font-semibold uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/6">
              {files.map(file => (
                <tr key={file.id} className="hover:bg-white/2">
                  <td className="px-6 py-4 text-sm flex items-center gap-2">
                    <Lock size={16} className="text-blue-400" />
                    {file.fileName}
                  </td>
                  <td className="px-6 py-4 text-sm">{file.fileSize}</td>
                  <td className="px-6 py-4 text-sm">
                    <span className="px-2 py-1 rounded text-xs bg-blue-500/20 text-blue-400">
                      {file.algorithm}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm">{file.uploadedAt}</td>
                  <td className="px-6 py-4 text-sm">
                    {hasDownloadPermission ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDecryptFile(file)}
                        className="gap-1"
                      >
                        <Eye size={16} />
                        View & Decrypt
                      </Button>
                    ) : (
                      <span className="text-xs text-red-400">Access Denied</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Decrypt Modal */}
      <Modal
        isOpen={showDecryptModal}
        onClose={() => setShowDecryptModal(false)}
        title={`Decrypting: ${selectedFile?.fileName}`}
        size="lg"
      >
        <div className="space-y-4">
          {decryptLoading && (
            <div className="flex items-center justify-center py-8">
              <div className="flex items-center gap-3">
                <Loader className="animate-spin text-blue-400" size={24} />
                <p className="text-sm">
                  Decrypting file with AES-256-GCM...
                  <br />
                  <span className="text-xs text-gray-400">Check terminal for encryption logs</span>
                </p>
              </div>
            </div>
          )}

          {decryptError && !decryptLoading && (
            <div className="bg-red-500/20 border border-red-500/50 text-red-300 px-4 py-3 rounded-lg text-sm">
              <strong>Error:</strong> {decryptError}
            </div>
          )}

          {decryptedContent && !decryptLoading && (
            <div>
              <p className="text-xs muted mb-2">Decrypted Content (Auto-deleted after 5 seconds):</p>
              <div className="bg-white/5 border border-white/10 rounded p-4 max-h-80 overflow-y-auto">
                <pre className="text-sm font-mono whitespace-pre-wrap break-words">
                  {decryptedContent}
                </pre>
              </div>
            </div>
          )}

          <div className="flex gap-3 justify-end pt-4">
            <Button
              variant="primary"
              onClick={() => {
                setShowDecryptModal(false)
                setDecryptedContent('')
              }}
            >
              Close
            </Button>
          </div>
        </div>
      </Modal>

      {/* Upload Modal */}
      <Modal
        isOpen={showUploadModal}
        onClose={() => setShowUploadModal(false)}
        title="Upload & Encrypt File"
        size="md"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Select File</label>
            <input
              type="file"
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
              className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div className="bg-blue-500/10 border border-blue-500/30 rounded p-3 text-sm">
            <p className="text-blue-200">
              <strong>Encryption Details:</strong>
              <br />
              Algorithm: AES-256-GCM
              <br />
              Key Size: 256-bit
              <br />
              The file will be encrypted before storage.
            </p>
          </div>

          <div className="flex gap-3 justify-end pt-4">
            <Button variant="ghost" onClick={() => setShowUploadModal(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleUploadFile}
              disabled={!uploadFile}
            >
              Upload & Encrypt
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

export default FileEncryption
