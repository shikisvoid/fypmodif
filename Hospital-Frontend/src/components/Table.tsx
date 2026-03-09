import React from 'react'

type Props = {
  children?: React.ReactNode
  className?: string
}

export default function Table({ children, className = '' }: Props) {
  return (
    <div className={`overflow-x-auto table-wrap ${className}`}>
      <table className="w-full">
        {children}
      </table>
    </div>
  )
}
