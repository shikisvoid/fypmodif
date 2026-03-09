import React from 'react'

type Props = {
  children?: React.ReactNode
  className?: string
  title?: string
  subtitle?: string
}

export default function Card({ children, className = '', title, subtitle }: Props) {
  return (
    <div className={`card-gradient p-6 rounded-lg shadow hover:shadow-lg transition border border-white/5 ${className}`}>
      {title && (
        <div className="mb-4">
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          {subtitle && <p className="text-xs muted mt-1">{subtitle}</p>}
        </div>
      )}
      {children}
    </div>
  )
}
