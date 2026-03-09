import React from 'react'
import { Sun, Moon, Menu, X } from 'lucide-react'

type Props = {
  title: string
  currentUser: any
  onToggleSidebar?: () => void
  sidebarOpen?: boolean
}

export default function Topbar({ title, currentUser, onToggleSidebar, sidebarOpen = true }: Props) {
  const [isLight, setIsLight] = React.useState(false)

  const toggleTheme = () => {
    const root = document.documentElement
    const newIsLight = !isLight
    setIsLight(newIsLight)
    if (newIsLight) {
      root.classList.add('light')
    } else {
      root.classList.remove('light')
    }
    try { localStorage.setItem('hp_theme', newIsLight ? 'light' : 'dark') } catch (e) {}
  }

  React.useEffect(() => {
    try {
      const saved = localStorage.getItem('hp_theme') || 'dark'
      const isLightTheme = saved === 'light'
      setIsLight(isLightTheme)
      if (isLightTheme) document.documentElement.classList.add('light')
    } catch (e) {}
  }, [])

  return (
    <div className="topbar p-4 flex items-center justify-between border-b border-white/6">
      <div className="flex items-center gap-4">
        {onToggleSidebar && (
          <button 
            onClick={onToggleSidebar}
            aria-label="Toggle sidebar"
            className="md:hidden p-2 bg-white/6 hover:bg-white/10 rounded-lg transition flex items-center justify-center"
            title="Toggle menu"
          >
            {sidebarOpen ? (
              <X size={20} className="text-white/90" />
            ) : (
              <Menu size={20} className="text-white/90" />
            )}
          </button>
        )}
        <div>
          <h2 className="text-lg font-bold">{title}</h2>
          <div className="text-xs muted">Welcome, {currentUser?.name || 'User'}</div>
        </div>
      </div>
      <div className="flex items-center gap-6">
        <div className="text-sm muted text-right">
          <div className="font-semibold text-white/90">{currentUser?.email}</div>
          <div className="text-xs">{currentUser?.role}</div>
        </div>
        <button 
          onClick={toggleTheme} 
          aria-label="Toggle theme" 
          className="p-2 bg-white/6 hover:bg-white/10 rounded-lg transition flex items-center justify-center"
          title={`Switch to ${isLight ? 'dark' : 'light'} mode`}
        >
          {isLight ? (
            <Moon size={18} className="text-yellow-400" />
          ) : (
            <Sun size={18} className="text-yellow-300" />
          )}
        </button>
      </div>
    </div>
  )
}
